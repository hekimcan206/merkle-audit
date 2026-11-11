# syntax=docker/dockerfile:1

# ---- build -------------------------------------------------------------------------------------------
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src

# Restore in its own layer: it only re-runs when package versions or project files change. The NuGet cache mount is
# locked: compose builds this image for three services at once, and parallel restores into one cache collide.
# Publish restores again (a no-op when the cache is warm): a restore layer reused from the CI layer cache can point
# at packages the cache mount of a fresh runner does not have.
COPY global.json Directory.Build.props Directory.Packages.props ./
COPY src/MerkleAudit.Core/MerkleAudit.Core.csproj src/MerkleAudit.Core/
COPY src/MerkleAudit.Server/MerkleAudit.Server.csproj src/MerkleAudit.Server/
RUN --mount=type=cache,id=nuget,target=/root/.nuget/packages,sharing=locked \
    dotnet restore src/MerkleAudit.Server/MerkleAudit.Server.csproj

COPY .editorconfig ./
COPY src/MerkleAudit.Core/ src/MerkleAudit.Core/
COPY src/MerkleAudit.Server/ src/MerkleAudit.Server/
RUN --mount=type=cache,id=nuget,target=/root/.nuget/packages,sharing=locked \
    dotnet publish src/MerkleAudit.Server/MerkleAudit.Server.csproj \
        --configuration Release --output /app/publish -p:UseAppHost=false \
    && mkdir -p /out/keys /out/trusted

# ---- runtime -----------------------------------------------------------------------------------------
# Chiseled Ubuntu: no shell, no package manager, and a non-root "app" user (UID 1654) baked in.
FROM mcr.microsoft.com/dotnet/aspnet:10.0-noble-chiseled AS runtime
LABEL org.opencontainers.image.title="merkle-audit-server" \
      org.opencontainers.image.source="https://github.com/hekimcan206/merkle-audit" \
      org.opencontainers.image.licenses="MIT"
WORKDIR /app
COPY --from=build --link /app/publish .
# Key directories owned by the app user, so fresh named volumes mounted here inherit that ownership.
COPY --from=build --chown=1654:1654 /out/keys /keys
COPY --from=build --chown=1654:1654 /out/trusted /trusted
USER $APP_UID
EXPOSE 8080
ENTRYPOINT ["dotnet", "MerkleAudit.Server.dll"]
