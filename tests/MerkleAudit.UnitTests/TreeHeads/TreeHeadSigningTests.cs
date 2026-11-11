using MerkleAudit.Core.Tree;
using MerkleAudit.Core.TreeHeads;
using MerkleAudit.Verifier;

namespace MerkleAudit.UnitTests.TreeHeads;

public sealed class TreeHeadSigningTests
{
    private static readonly byte[] Root = Convert.FromHexString("5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328");

    private static SignedHead ToVerifier(SignedTreeHead sth) =>
        new(sth.Head.TreeSize, sth.Head.TimestampMs, sth.Head.RootHash, sth.KeyId, sth.Signature);

    [Fact]
    public void Signature_input_is_the_rfc6962_tree_head_structure()
    {
        var input = new TreeHead(8, 0x0102030405060708, Root).ToSignatureInput();

        input.Should().HaveCount(50);
        input[0].Should().Be(0, "version v1");
        input[1].Should().Be(1, "signature type tree_hash");
        input[2..10].Should().Equal(0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08);
        input[10..18].Should().Equal(0, 0, 0, 0, 0, 0, 0, 8);
        input[18..].Should().Equal(Root);
        new SignedHead(8, 0x0102030405060708, Root, "k", []).SignatureInput().Should().Equal(input, "server and verifier serialise identically");
    }

    [Fact]
    public void Key_id_is_the_sha256_of_the_public_key_and_survives_pem_round_trip()
    {
        using var signer = TreeHeadSigner.Generate();
        using var reloaded = TreeHeadSigner.FromPem(signer.ExportPrivateKeyPem());
        using var trust = new TrustStore();

        reloaded.KeyId.Should().Be(signer.KeyId).And.HaveLength(64);
        trust.AddPem(signer.PublicKeyPem).KeyId.Should().Be(signer.KeyId);
    }

    [Fact]
    public void Signed_head_verifies_and_any_change_breaks_it()
    {
        using var signer = TreeHeadSigner.Generate();
        using var trust = new TrustStore();
        trust.AddPem(signer.PublicKeyPem);
        var head = ToVerifier(signer.Sign(new TreeHead(8, 1_762_000_000_000, Root)));

        trust.Check(head).Should().BeNull();
        trust.Check(head with { TreeSize = 9 }).Should().Be("signature does not verify");
        trust.Check(head with { TimestampMs = head.TimestampMs + 1 }).Should().Be("signature does not verify");
        var otherRoot = (byte[])Root.Clone();
        otherRoot[0] ^= 1;
        trust.Check(head with { RootHash = otherRoot }).Should().Be("signature does not verify");
    }

    [Fact]
    public void Heads_from_an_unknown_key_are_rejected_even_with_a_valid_signature()
    {
        using var trusted = TreeHeadSigner.Generate();
        using var attacker = TreeHeadSigner.Generate();
        using var trust = new TrustStore();
        trust.AddPem(trusted.PublicKeyPem);

        var forged = ToVerifier(attacker.Sign(new TreeHead(8, 1, Root)));
        trust.Check(forged).Should().StartWith("signed by untrusted key");

        // Claiming the trusted key's id does not help: the signature is checked with the trusted key.
        trust.Check(forged with { KeyId = trusted.KeyId }).Should().Be("signature does not verify");
    }

    [Fact]
    public void Rotation_keeps_history_valid_and_bounds_the_retired_key()
    {
        using var oldKey = TreeHeadSigner.Generate();
        using var newKey = TreeHeadSigner.Generate();
        const long rotatedAt = 1_762_000_000_000;
        using var trust = new TrustStore();
        trust.AddPem(oldKey.PublicKeyPem, notAfterMs: rotatedAt);
        trust.AddPem(newKey.PublicKeyPem);

        trust.Check(ToVerifier(oldKey.Sign(new TreeHead(5, rotatedAt - 1, Root)))).Should().BeNull("history signed before rotation stays valid");
        trust.Check(ToVerifier(newKey.Sign(new TreeHead(8, rotatedAt + 1, Root)))).Should().BeNull();
        trust.Check(ToVerifier(oldKey.Sign(new TreeHead(9, rotatedAt + 1, Root))))
            .Should().Be("signed by a retired key after its retirement", "a leaked retired key cannot extend the log");
    }

    [Fact]
    public void Only_p256_keys_are_accepted()
    {
        using var p384 = System.Security.Cryptography.ECDsa.Create(System.Security.Cryptography.ECCurve.NamedCurves.nistP384);
        var act = () => new TreeHeadSigner(p384);
        act.Should().Throw<ArgumentException>();

        using var trust = new TrustStore();
        var addWrongCurve = () => trust.AddPem(p384.ExportSubjectPublicKeyInfoPem());
        addWrongCurve.Should().Throw<System.Security.Cryptography.CryptographicException>();
    }

    [Fact]
    public void Appender_rejects_a_frontier_for_the_wrong_size()
    {
        var tree = new InMemoryMerkleTree();
        tree.AppendData([1]);
        var act = () => TreeAppender.Append(3, [], [Root]);
        act.Should().Throw<ArgumentException>();
    }
}
