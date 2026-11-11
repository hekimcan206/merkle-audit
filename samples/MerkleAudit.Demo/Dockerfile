# syntax=docker/dockerfile:1
# The tamper demo and the merkle-verify CLI in one image (the CLI is at /app/verify/merkle-verify.dll).

FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY global.json Directory.Build.props Directory.Packages.props ./
COPY src/MerkleAudit.Core/MerkleAudit.Core.csproj src/MerkleAudit.Core/
COPY src/MerkleAudit.Verifier/MerkleAudit.Verifier.csproj src/MerkleAudit.Verifier/
COPY src/MerkleAudit.Verifier.Cli/MerkleAudit.Verifier.Cli.csproj src/MerkleAudit.Verifier.Cli/
COPY samples/MerkleAudit.Demo/MerkleAudit.Demo.csproj samples/MerkleAudit.Demo/
RUN --mount=type=cache,id=nuget,target=/root/.nuget/packages,sharing=locked \
    dotnet restore samples/MerkleAudit.Demo/MerkleAudit.Demo.csproj \
    && dotnet restore src/MerkleAudit.Verifier.Cli/MerkleAudit.Verifier.Cli.csproj

COPY .editorconfig ./
COPY src/MerkleAudit.Core/ src/MerkleAudit.Core/
COPY src/MerkleAudit.Verifier/ src/MerkleAudit.Verifier/
COPY src/MerkleAudit.Verifier.Cli/ src/MerkleAudit.Verifier.Cli/
COPY samples/MerkleAudit.Demo/ samples/MerkleAudit.Demo/
RUN --mount=type=cache,id=nuget,target=/root/.nuget/packages,sharing=locked \
    dotnet publish samples/MerkleAudit.Demo/MerkleAudit.Demo.csproj --configuration Release --output /app/demo -p:UseAppHost=false \
    && dotnet publish src/MerkleAudit.Verifier.Cli/MerkleAudit.Verifier.Cli.csproj --configuration Release --output /app/verify -p:UseAppHost=false

FROM mcr.microsoft.com/dotnet/runtime:10.0-noble-chiseled AS runtime
LABEL org.opencontainers.image.title="merkle-audit-demo" \
      org.opencontainers.image.source="https://github.com/hekimcan206/merkle-audit" \
      org.opencontainers.image.licenses="MIT"
WORKDIR /app
COPY --from=build --link /app/demo ./demo
COPY --from=build --link /app/verify ./verify
USER $APP_UID
ENTRYPOINT ["dotnet", "/app/demo/MerkleAudit.Demo.dll"]
