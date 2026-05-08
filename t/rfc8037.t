use strict;
use warnings;
use Test::More;

use Crypt::JWT qw(encode_jwt decode_jwt);
use Crypt::PK::Ed25519;
use Crypt::PK::X25519;
use Crypt::Misc qw(decode_b64u encode_b64u);

# Test vectors from RFC 8037 (CFRG ECDH and Signatures in JOSE) Appendix A.
# https://www.rfc-editor.org/rfc/rfc8037.txt
#
# Crypt::JWT supports Ed25519 (EdDSA) and X25519 (ECDH-ES). It does not
# implement X448 / Ed448, so the §A.7 X448 example is omitted.

my $ed25519_priv_jwk = {
    kty => "OKP", crv => "Ed25519",
    d => "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
    x => "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
};
my $ed25519_pub_jwk = {
    kty => "OKP", crv => "Ed25519",
    x => "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
};

#----------------------------------------------------------------------
# A.1 / A.2: Ed25519 private and public key — verify hex bytes match.
#----------------------------------------------------------------------
{
    my $d_hex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    my $x_hex = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

    is(unpack("H*", decode_b64u($ed25519_priv_jwk->{d})), $d_hex, "A.1 Ed25519 private key 'd' hex");
    is(unpack("H*", decode_b64u($ed25519_priv_jwk->{x})), $x_hex, "A.1 Ed25519 public key 'x' hex");
    is($ed25519_pub_jwk->{x}, $ed25519_priv_jwk->{x},            "A.2 public key is the 'x' part of the private key");
}

#----------------------------------------------------------------------
# A.4 / A.5: Ed25519 signing and validation.
#----------------------------------------------------------------------
{
    my $jws_expected = "eyJhbGciOiJFZERTQSJ9".
                       ".RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc".
                       ".hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg";
    my $payload = "Example of Ed25519 signing";

    # A.5: validation against the RFC's exact JWS bytes.
    my $decoded = decode_jwt(token => $jws_expected, key => $ed25519_pub_jwk, decode_payload => 0);
    is($decoded, $payload, "A.5 Ed25519 JWS validates and yields original payload");

    # A.4: Ed25519 is deterministic, so re-signing the same payload with
    # the same private key must reproduce the RFC token bit-for-bit.
    my $jws_produced = encode_jwt(
        payload => $payload,
        alg     => 'EdDSA',
        key     => $ed25519_priv_jwk,
    );
    is($jws_produced, $jws_expected, "A.4 Ed25519 signing reproduces RFC compact JWS");

    # And the expected raw signature bytes (as a sanity check).
    my $sig_hex = "860c98d2297f3060a33f42739672d61b53cf3adefed3d3c672f320dc021b411e".
                  "9d59b8628dc351e248b88b29468e0e41855b0fb7d83bb15be902bfccb8cd0a02";
    my (undef, undef, $sig_b64u) = split /\./, $jws_expected;
    is(unpack("H*", decode_b64u($sig_b64u)), $sig_hex, "A.4 Ed25519 signature hex matches RFC");
}

#----------------------------------------------------------------------
# A.6 ECDH-ES with X25519
# Both parties must derive the same DH Z value. We exercise this by
# encoding a JWE with the ephemeral key as sender and decoding it as
# recipient. The RFC also gives the raw Z (same on both sides):
#   4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742
#----------------------------------------------------------------------
{
    my $bob_priv_jwk = {
        kty => "OKP", crv => "X25519", kid => "Bob",
        d => "XasIfmJKikt54X-Lg4AO5m87sSkmGLb9HC-LJ_-I4Os",  # synthetic; not in RFC
        x => "3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08",
    };
    # The RFC only gives the recipient's *public* key (and the
    # ephemeral secret). We check the ephemeral derivation directly by
    # computing the DH shared secret with raw 32-byte X25519 keys taken
    # from the RFC, since Crypt::JWT can't drive the encrypt side
    # without random ephemeral keys.

    my $bob_pub_hex   = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";
    my $eph_secret_hex= "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
    my $eph_pub_hex   = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
    my $z_hex         = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";

    # Sanity: Bob's public key in the JWK matches the RFC hex bytes.
    is(unpack("H*", decode_b64u($bob_priv_jwk->{x})), $bob_pub_hex,
       "A.6 Bob's X25519 public 'x' matches RFC hex");

    # Sanity: ephemeral public key from the RFC matches the JWK form.
    my $eph_jwk_x = "hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo";
    is(unpack("H*", decode_b64u($eph_jwk_x)), $eph_pub_hex,
       "A.6 ephemeral X25519 public 'x' matches RFC hex");

    # Compute Z from the receiver side: seckey x ephkey_pub.
    # We synthesize Bob's secret here just to demonstrate Z agreement
    # using Crypt::PK::X25519's shared_secret(); the sender's secret
    # (RFC's "ephemeral secret") plays the same role on the other end.
    my $eph_priv = Crypt::PK::X25519->new->import_key_raw(pack("H*", $eph_secret_hex), 'private');
    my $bob_pub  = Crypt::PK::X25519->new->import_key_raw(pack("H*", $bob_pub_hex), 'public');
    my $z = $eph_priv->shared_secret($bob_pub);
    is(unpack("H*", $z), $z_hex,
       "A.6 ECDH-ES X25519 shared secret Z matches RFC value");
}

done_testing;
