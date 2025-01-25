# NAME

Crypt::JWT - JSON Web Token (JWT, JWS, JWE) as defined by RFC7519, RFC7515, RFC7516

# SYNOPSIS

    # encoding
    use Crypt::JWT qw(encode_jwt);
    my $jws_token = encode_jwt(payload=>$data, alg=>'HS256', key=>'secret');
    my $jwe_token = encode_jwt(payload=>$data, alg=>'PBES2-HS256+A128KW', enc=>'A128GCM', key=>'secret');

    # decoding
    use Crypt::JWT qw(decode_jwt);
    my $data1 = decode_jwt(token=>$jws_token, key=>'secret');
    my $data2 = decode_jwt(token=>$jwe_token, key=>'secret');

# DESCRIPTION

Implements **JSON Web Token (JWT)** - [https://tools.ietf.org/html/rfc7519](https://tools.ietf.org/html/rfc7519).
The implementation covers not only **JSON Web Signature (JWS)** - [https://tools.ietf.org/html/rfc7515](https://tools.ietf.org/html/rfc7515),
but also **JSON Web Encryption (JWE)** - [https://tools.ietf.org/html/rfc7516](https://tools.ietf.org/html/rfc7516).

The module implements **all (100%) algorithms** defined in [https://tools.ietf.org/html/rfc7518](https://tools.ietf.org/html/rfc7518) - **JSON Web Algorithms (JWA)**.

This module supports **Compact JWS/JWE** and **Flattened JWS/JWE JSON** serialization, general JSON serialization is not supported yet.

# EXPORT

Nothing is exported by default.

You can export selected functions:

    use Crypt::JWT qw(decode_jwt encode_jwt);

Or all of them at once:

    use Crypt::JWT ':all';

# FUNCTIONS

## decode\_jwt

    my $data = decode_jwt(%named_args);

Named arguments:

- token

    Mandatory argument, a string with either JWS or JWE JSON Web Token.

        ### JWS token example (3 segments)
        $t = "eyJhbGciOiJIUzI1NiJ9.dGVzdA.ujBihtLSr66CEWqN74SpLUkv28lra_CeHnxLmLNp4Jo";
        my $data = decode_jwt(token=>$t, key=>$k);

        ### JWE token example (5 segments)
        $t = "eyJlbmMiOiJBMTI4R0NNIiwiYWxnIjoiQTEyOEtXIn0.UusxEbzhGkORxTRq0xkFKhvzPrXb9smw.VGfOuq0Fxt6TsdqLZUpnxw.JajIQQ.pkKZ7MHS0XjyGmRsqgom6w";
        my $data = decode_jwt(token=>$t, key=>$k);

- key

    A key used for token decryption (JWE) or token signature validation (JWS).
    The value depends on the `alg` token header value.

        JWS alg header      key value
        ------------------  ----------------------------------
        none                no key required
        HS256               string (raw octects) of any length (or perl HASH ref with JWK, kty=>'oct')
        HS384               dtto
        HS512               dtto
        RS256               public RSA key, perl HASH ref with JWK key structure,
                            a reference to SCALAR string with PEM or DER or JSON/JWK data,
                            object: Crypt::PK::RSA, Crypt::OpenSSL::RSA, Crypt::X509 or Crypt::OpenSSL::X509
        RS384               public RSA key, see RS256
        RS512               public RSA key, see RS256
        PS256               public RSA key, see RS256
        PS384               public RSA key, see RS256
        PS512               public RSA key, see RS256
        ES256               public ECC key, perl HASH ref with JWK key structure,
                            a reference to SCALAR string with PEM or DER or JSON/JWK data,
                            an instance of Crypt::PK::ECC
        ES256K              public ECC key, see ES256
        ES384               public ECC key, see ES256
        ES512               public ECC key, see ES256
        EdDSA               public Ed25519 key

        JWE alg header      key value
        ------------------  ----------------------------------
        dir                 string (raw octects) or perl HASH ref with JWK, kty=>'oct', length depends on 'enc' algorithm
        A128KW              string (raw octects) 16 bytes (or perl HASH ref with JWK, kty=>'oct')
        A192KW              string (raw octects) 24 bytes (or perl HASH ref with JWK, kty=>'oct')
        A256KW              string (raw octects) 32 bytes (or perl HASH ref with JWK, kty=>'oct')
        A128GCMKW           string (raw octects) 16 bytes (or perl HASH ref with JWK, kty=>'oct')
        A192GCMKW           string (raw octects) 24 bytes (or perl HASH ref with JWK, kty=>'oct')
        A256GCMKW           string (raw octects) 32 bytes (or perl HASH ref with JWK, kty=>'oct')
        PBES2-HS256+A128KW  string (raw octects) of any length (or perl HASH ref with JWK, kty=>'oct')
        PBES2-HS384+A192KW  string (raw octects) of any length (or perl HASH ref with JWK, kty=>'oct')
        PBES2-HS512+A256KW  string (raw octects) of any length (or perl HASH ref with JWK, kty=>'oct')
        RSA-OAEP            private RSA key, perl HASH ref with JWK key structure,
                            a reference to SCALAR string with PEM or DER or JSON/JWK data,
                            an instance of Crypt::PK::RSA or Crypt::OpenSSL::RSA
        RSA-OAEP-256        private RSA key, see RSA-OAEP
        RSA1_5              private RSA key, see RSA-OAEP
        ECDH-ES             private ECC or X25519 key, perl HASH ref with JWK key structure,
                            a reference to SCALAR string with PEM or DER or JSON/JWK data,
                            an instance of Crypt::PK::ECC
        ECDH-ES+A128KW      private ECC or X25519 key, see ECDH-ES
        ECDH-ES+A192KW      private ECC or X25519 key, see ECDH-ES
        ECDH-ES+A256KW      private ECC or X25519 key, see ECDH-ES

    Example using the key from `jwk` token header:

        my $data = decode_jwt(token=>$t, key_from_jwk_header=>1);
        my ($header, $data) = decode_jwt(token=>$t, decode_header=>1, key_from_jwk_header=>1);

    Examples with raw octet keys:

        #string
        my $data = decode_jwt(token=>$t, key=>'secretkey');
        #binary key
        my $data = decode_jwt(token=>$t, key=>pack("H*", "788A6E38F36B7596EF6A669E94"));
        #perl HASH ref with JWK structure (key type 'oct')
        my $data = decode_jwt(token=>$t, key=>{kty=>'oct', k=>"GawgguFyGrWKav7AX4VKUg"});

    Examples with RSA keys:

        my $pem_key_string = <<'EOF';
        -----BEGIN PRIVATE KEY-----
        MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCoVm/Sl5r+Ofky
        jioRSZK26GW6WyjyfWKddsSi13/NOtCn0rRErSF/u3QrgGMpWFqKohqbi1VVC+SZ
        ...
        8c1vm2YFafgdkSk9Qd1oU2Fv1aOQy4VovOFzJ3CcR+2r7cbRfcpLGnintHtp9yek
        02p+d5g4OChfFNDhDtnIqjvY
        -----END PRIVATE KEY-----
        EOF

        my $jwk_key_json_string = '{"kty":"RSA","n":"0vx7agoebG...L6tSoc_BJECP","e":"AQAB"}';

        #a reference to SCALAR string with PEM or DER or JSON/JWK data,
        my $data = decode_jwt(token=>$t, key=>\$pem_key_string);
        my $data = decode_jwt(token=>$t, key=>\$der_key_string);
        my $data = decode_jwt(token=>$t, key=>\$jwk_key_json_string);

        #instance of Crypt::PK::RSA
        my $data = decode_jwt(token=>$t, key=>Crypt::PK::RSA->new('keyfile.pem'));
        my $data = decode_jwt(token=>$t, key=>Crypt::PK::RSA->new(\$pem_key_string));

        #instance of Crypt::OpenSSL::RSA
        my $data = decode_jwt(token=>$t, key=>Crypt::OpenSSL::RSA->new_private_key($pem_key_string));

        #instance of Crypt::X509 (public key only)
        my $data = decode_jwt(token=>$t, key=>Crypt::X509->new(cert=>$cert));

        #instance of Crypt::OpenSSL::X509 (public key only)
        my $data = decode_jwt(token=>$t, key=>Crypt::OpenSSL::X509->new_from_file('cert.pem'));
        my $data = decode_jwt(token=>$t, key=>Crypt::OpenSSL::X509->new_from_string($cert));

        #perl HASH ref with JWK structure (key type 'RSA')
        my $rsa_priv = {
          kty => "RSA",
          n   => "0vx7agoebGcQSuuPiLJXZpt...eZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
          e   => "AQAB",
          d   => "X4cTteJY_gn4FYPsXB8rdXi...FLN5EEaG6RoVH-HLKD9Mdx5ooGURknhnrRwUkC7h5fJLMWbFAKLWY2v7B6NqSzUvx0_YSf",
          p   => "83i-7IvMGXoMXCskv73TKr8...Z27zvoj6pbUQyLPBQxtPnwD20-60eTmD2ujMt5PoMrm8RmNhVWtjjMmMjOpSicFHjXOuVI",
          q   => "3dfOR9cuYq-0S-mkFLzgItg...q3hWeMuG0ouqnb3obLyuqjVZQ1dIrdgTnCdYzBcOW5r37AFXjift_NGiovonzhKpoVVS78",
          dp  => "G4sPXkc6Ya9y8oJW9_ILj4...zi_H7TkS8x5SdX3oE0oiYwxIiemTAu0UOa5pgFGyJ4c8t2VF40XRugKTP8akhFo5tA77Qe",
          dq  => "s9lAH9fggBsoFR8Oac2R_E...T2kGOhvIllTE1efA6huUvMfBcpn8lqW6vzzYY5SSF7pMd_agI3G8IbpBUb0JiraRNUfLhc",
          qi  => "GyM_p6JrXySiz1toFgKbWV...4ypu9bMWx3QJBfm0FoYzUIZEVEcOqwmRN81oDAaaBk0KWGDjJHDdDmFW3AN7I-pux_mHZG",
        };
        my $data = decode_jwt(token=>$t, key=>$rsa_priv});

    Examples with ECC keys:

        my $pem_key_string = <<'EOF';
        -----BEGIN EC PRIVATE KEY-----
        MHcCAQEEIBG1c3z52T8XwMsahGVdOZWgKCQJfv+l7djuJjgetdbDoAoGCCqGSM49
        AwEHoUQDQgAEoBUyo8CQAFPeYPvv78ylh5MwFZjTCLQeb042TjiMJxG+9DLFmRSM
        lBQ9T/RsLLc+PmpB1+7yPAR+oR5gZn3kJQ==
        -----END EC PRIVATE KEY-----
        EOF

        my $jwk_key_json_string = '{"kty":"EC","crv":"P-256","x":"MKB..7D4","y":"4Et..FyM"}';

        #a reference to SCALAR string with PEM or DER or JSON/JWK data,
        my $data = decode_jwt(token=>$t, key=>\$pem_key_string);
        my $data = decode_jwt(token=>$t, key=>\$der_key_string);
        my $data = decode_jwt(token=>$t, key=>\$jwk_key_json_string);

        #instance of Crypt::PK::ECC
        my $data = decode_jwt(token=>$t, key=>Crypt::PK::ECC->new('keyfile.pem'));
        my $data = decode_jwt(token=>$t, key=>Crypt::PK::ECC->new(\$pem_key_string));

        #perl HASH ref with JWK structure (key type 'EC')
        my $ecc_priv = {
          kty => "EC",
          crv => "P-256",
          x   => "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
          y   => "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
          d   => "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE",
        };
        my $data = decode_jwt(token=>$t, key=>$ecc_priv});

- keypass

    When 'key' parameter is an encrypted private RSA or ECC key this optional parameter may contain a password for private key decryption.

- kid\_keys

    This parametes can be either a JWK Set JSON string (see RFC7517) or a perl HASH ref with JWK Set structure like this:

        my $keylist = {
          keys => [
            { kid=>"key1", kty=>"oct", k=>"GawgguFyGrWKav7AX4VKUg" },
            { kid=>"key2", kty=>"oct", k=>"ulxLGy4XqhbpkR5ObGh1gX" },
          ]
        };
        my $payload = decode_jwt(token=>$t, kid_keys=>$keylist);

    You can use ["export\_key\_jwk" in Crypt::PK::RSA](https://metacpan.org/pod/Crypt%3A%3APK%3A%3ARSA#export_key_jwk) to generate a JWK for RSA:

        my $pubkey = Crypt::PK::RSA->new('rs256-4096-public.pem');
        my $jwk_hash = $pubkey->export_key_jwk('public', 1);
        $jwk_hash->{kid} = 'key1';
        my $keylist = {
          keys => [
            $jwk_hash,
          ]
        };

    The structure described above is used e.g. by [https://www.googleapis.com/oauth2/v2/certs](https://www.googleapis.com/oauth2/v2/certs)

        use Mojo::UserAgent;
        my $ua = Mojo::UserAgent->new;
        my $google_keys => $ua->get('https://www.googleapis.com/oauth2/v2/certs')->result->json;
        my $payload = decode_jwt(token => $t, kid_keys => $google_keys);

    **SINCE 0.019** we also support alternative structure used e.g. by [https://www.googleapis.com/oauth2/v1/certs](https://www.googleapis.com/oauth2/v1/certs):

        use LWP::Simple;
        my $google_certs = get('https://www.googleapis.com/oauth2/v1/certs');
        my $payload = decode_jwt(token => $t, kid_keys => $google_certs);

    When the token header contains `kid` item the corresponding key is looked up in `kid_keys` list and used for token
    decoding (you do not need to pass the explicit key via `key` parameter). Add a kid header using ["extra\_headers"](#extra_headers).

    **INCOMPATIBLE CHANGE in 0.023:** When `kid_keys` is specified it croaks if token header does not contain `kid` value or
    if `kid` was not found in `kid_keys`.

- key\_from\_jwk\_header

    **SINCE 0.023**

    `1` - use `jwk` header value for validating JWS signature if neither `key` nor `kid_keys` specified, **BEWARE: DANGEROUS, UNSECURE!!!**

    `0` (default) - ignore `jwk` header value when validating JWS signature

    Keep in mind that enabling `key_from_jwk_header` requires `jwk` header to exist and be an valid RSA/ECDSA public key (otherwise it croaks).

- allow\_none

    `1` - accept JWS tokens with `none` 'alg' header value (which means that token has no signature), **BEWARE: DANGEROUS, UNSECURE!!!**

    `0` (default) - do not allow JWS with `none` 'alg' header value

- ignore\_signature

    `1` - do not check signature on JWS tokens, **BEWARE: DANGEROUS, UNSECURE!!!**

    `0` (default) - check signature on JWS tokens

- accepted\_alg

    `undef` (default) means accept all 'alg' algorithms except 'none' (for accepting 'none' use `allow_none`)

    `string` name of accepted 'alg' algorithm (only one)

    `ARRAY ref` a list of accepted 'alg' algorithms

    `Regexp` that has to match 'alg' algorithm name

        my $payload = decode_jwt(token=>$t, key=>$k, accepted_alg=>'HS256');
        #or
        my $payload = decode_jwt(token=>$t, key=>$k, accepted_alg=>['HS256','HS384']);
        #or
        my $payload = decode_jwt(token=>$t, key=>$k, accepted_alg=>qr/^HS(256|384|512)$/);

- accepted\_enc

    `undef` (default) means accept all 'enc' algorithms

    `string` name of accepted 'enc' algorithm (only one)

    `ARRAY ref` a list of accepted 'enc' algorithms

    `Regexp` that has to match 'enc' algorithm name

        my $payload = decode_jwt(token=>$t, key=>$k, accepted_enc=>'A192GCM');
        #or
        my $payload = decode_jwt(token=>$t, key=>$k, accepted_enc=>['A192GCM','A256GCM']);
        #or
        my $payload = decode_jwt(token=>$t, key=>$k, accepted_enc=>qr/^A(128|192|256)GCM$/);

- decode\_payload

    `0` - do not decode payload, return it as a raw string (octects).

    `1` - decode payload from JSON string, return it as perl hash ref (or array ref) - decode\_json failure means fatal error (croak).

    `undef` (default) - if possible decode payload from JSON string, if decode\_json fails return payload as a raw string (octets).

- decode\_header

    `0` (default) - do not return decoded header as a return value of decode\_jwt()

    `1` - return decoded header as a return value of decode\_jwt()

        my $payload = decode_jwt(token=>$t, key=>$k);
        #or
        my ($header, $payload) = decode_jwt(token=>$t, key=>$k, decode_header=>1);

- verify\_iss

    **INCOMPATIBLE CHANGE in 0.024:** If `verify_iss` is specified and
    claim `iss` (Issuer) is completely missing it is a failure since 0.024

    `CODE ref` - subroutine (with 'iss' claim value passed as argument) should return `true` otherwise verification fails

    `Regexp ref` - 'iss' claim value has to match given regexp otherwise verification fails

    `Scalar` - 'iss' claim value has to be equal to given string (since 0.029)

    `undef` (default) - do not verify 'iss' claim

- verify\_aud

    **INCOMPATIBLE CHANGE in 0.024:** If `verify_aud` is specified and
    claim `aud` (Audience) is completely missing it is a failure since 0.024

    `CODE ref` - subroutine (with 'aud' claim value passed as argument) should return `true` otherwise verification fails

    `Regexp ref` - 'aud' claim value has to match given regexp otherwise verification fails

    `Scalar` - 'aud' claim value has to be equal to given string (since 0.029)

    `undef` (default) - do not verify 'aud' claim

    **SINCE 0.036** we handle 'aud' claim when it contains an array of strings. In this case, the check should succeed if at least one
    value from the array matches. All checks (CODE, Regexp, Scalar) are performed individually against each member of the array of strings.

- verify\_sub

    **INCOMPATIBLE CHANGE in 0.024:** If `verify_sub` is specified and
    claim `sub` (Subject) is completely missing it is a failure since 0.024

    `CODE ref` - subroutine (with 'sub' claim value passed as argument) should return `true` otherwise verification fails

    `Regexp ref` - 'sub' claim value has to match given regexp otherwise verification fails

    `Scalar` - 'sub' claim value has to be equal to given string (since 0.029)

    `undef` (default) - do not verify 'sub' claim

- verify\_jti

    **INCOMPATIBLE CHANGE in 0.024:** If `verify_jti` is specified and
    claim `jti` (JWT ID) is completely missing it is a failure since 0.024

    `CODE ref` - subroutine (with 'jti' claim value passed as argument) should return `true` otherwise verification fails

    `Regexp ref` - 'jti' claim value has to match given regexp otherwise verification fails

    `Scalar` - 'jti' claim value has to be equal to given string (since 0.029)

    `undef` (default) - do not verify 'jti' claim

- verify\_iat

    `undef` - Issued At 'iat' claim must be valid (not in the future) if present

    `0` (default) - ignore 'iat' claim

    `1` - require valid 'iat' claim

- verify\_nbf

    `undef` (default) - Not Before 'nbf' claim must be valid if present

    `0` - ignore 'nbf' claim

    `1` - require valid 'nbf' claim

- verify\_exp

    `undef` (default) - Expiration Time 'exp' claim must be valid if present

    `0` - ignore 'exp' claim

    `1` - require valid 'exp' claim

- leeway

    Tolerance in seconds related to `verify_exp`, `verify_nbf` and `verify_iat`. Default is `0`.

- ignore\_claims

    `1` - do not check claims (iat, exp, nbf, iss, aud, sub, jti), **BEWARE: DANGEROUS, UNSECURE!!!**

    `0` (default) - check claims

- verify\_typ

    **SINCE 0.036**

    `CODE ref` - subroutine (with 'typ' header parameter value passed as argument) should return `true` otherwise verification fails

    `Regexp ref` - 'typ' header parameter value has to match given regexp otherwise verification fails

    `Scalar` - 'typ' header parameter value has to be equal to given string

    `undef` (default) - do not verify 'typ' header parameter

## encode\_jwt

    my $token = encode_jwt(%named_args);

Named arguments:

- payload

    Value of this mandatory parameter can be a string/buffer or HASH ref or ARRAY ref

        my $token = encode_jwt(payload=>"any raw data", key=>$k, alg=>'HS256');
        #or
        my $token = encode_jwt(payload=>{a=>1,b=>2}, key=>$k, alg=>'HS256');
        #or
        my $token = encode_jwt(payload=>[11,22,33,44], key=>$k, alg=>'HS256');

    HASH refs and ARRAY refs payloads are serialized as JSON strings

- alg

    The 'alg' header value is mandatory for both JWE and JWS tokens.

    Supported JWE 'alg' algorithms:

        dir
        A128KW
        A192KW
        A256KW
        A128GCMKW
        A192GCMKW
        A256GCMKW
        PBES2-HS256+A128KW
        PBES2-HS384+A192KW
        PBES2-HS512+A256KW
        RSA-OAEP
        RSA-OAEP-256
        RSA1_5
        ECDH-ES+A128KW
        ECDH-ES+A192KW
        ECDH-ES+A256KW
        ECDH-ES

    Supported JWS algorithms:

        none   ...  no integrity (NOTE: disabled by default)
        HS256  ...  HMAC+SHA256 integrity
        HS384  ...  HMAC+SHA384 integrity
        HS512  ...  HMAC+SHA512 integrity
        RS256  ...  RSA+PKCS1-V1_5 + SHA256 signature
        RS384  ...  RSA+PKCS1-V1_5 + SHA384 signature
        RS512  ...  RSA+PKCS1-V1_5 + SHA512 signature
        PS256  ...  RSA+PSS + SHA256 signature
        PS384  ...  RSA+PSS + SHA384 signature
        PS512  ...  RSA+PSS + SHA512 signature
        ES256  ...  ECDSA + SHA256 signature
        ES256K ...  ECDSA + SHA256 signature
        ES384  ...  ECDSA + SHA384 signature
        ES512  ...  ECDSA + SHA512 signature
        EdDSA  ...  Ed25519 signature

- enc

    The 'enc' header is mandatory for JWE tokens.

    Supported 'enc' algorithms:

        A128GCM
        A192GCM
        A256GCM
        A128CBC-HS256
        A192CBC-HS384
        A256CBC-HS512

- key

    A key used for token encryption (JWE) or token signing (JWS). The value depends on `alg` token header value.

        JWS alg header      key value
        ------------------  ----------------------------------
        none                no key required
        HS256               string (raw octects) of any length (or perl HASH ref with JWK, kty=>'oct')
        HS384               dtto
        HS512               dtto
        RS256               private RSA key, perl HASH ref with JWK key structure,
                            a reference to SCALAR string with PEM or DER or JSON/JWK data,
                            object: Crypt::PK::RSA, Crypt::OpenSSL::RSA, Crypt::X509 or Crypt::OpenSSL::X509
        RS384               private RSA key, see RS256
        RS512               private RSA key, see RS256
        PS256               private RSA key, see RS256
        PS384               private RSA key, see RS256
        PS512               private RSA key, see RS256
        ES256               private ECC key, perl HASH ref with JWK key structure,
                            a reference to SCALAR string with PEM or DER or JSON/JWK data,
                            an instance of Crypt::PK::ECC
        ES256K              private ECC key, see ES256
        ES384               private ECC key, see ES256
        ES512               private ECC key, see ES256
        EdDSA               private Ed25519 key

        JWE alg header      key value
        ------------------  ----------------------------------
        dir                 string (raw octects) or perl HASH ref with JWK, kty=>'oct', length depends on 'enc' algorithm
        A128KW              string (raw octects) 16 bytes (or perl HASH ref with JWK, kty=>'oct')
        A192KW              string (raw octects) 24 bytes (or perl HASH ref with JWK, kty=>'oct')
        A256KW              string (raw octects) 32 bytes (or perl HASH ref with JWK, kty=>'oct')
        A128GCMKW           string (raw octects) 16 bytes (or perl HASH ref with JWK, kty=>'oct')
        A192GCMKW           string (raw octects) 24 bytes (or perl HASH ref with JWK, kty=>'oct')
        A256GCMKW           string (raw octects) 32 bytes (or perl HASH ref with JWK, kty=>'oct')
        PBES2-HS256+A128KW  string (raw octects) of any length (or perl HASH ref with JWK, kty=>'oct')
        PBES2-HS384+A192KW  string (raw octects) of any length (or perl HASH ref with JWK, kty=>'oct')
        PBES2-HS512+A256KW  string (raw octects) of any length (or perl HASH ref with JWK, kty=>'oct')
        RSA-OAEP            public RSA key, perl HASH ref with JWK key structure,
                            a reference to SCALAR string with PEM or DER or JSON/JWK data,
                            an instance of Crypt::PK::RSA or Crypt::OpenSSL::RSA
        RSA-OAEP-256        public RSA key, see RSA-OAEP
        RSA1_5              public RSA key, see RSA-OAEP
        ECDH-ES             public ECC or X25519 key, perl HASH ref with JWK key structure,
                            a reference to SCALAR string with PEM or DER or JSON/JWK data,
                            an instance of Crypt::PK::ECC
        ECDH-ES+A128KW      public ECC or X25519 key, see ECDH-ES
        ECDH-ES+A192KW      public ECC or X25519 key, see ECDH-ES
        ECDH-ES+A256KW      public ECC or X25519 key, see ECDH-ES

- keypass

    When 'key' parameter is an encrypted private RSA or ECC key this optional parameter may contain a password for private key decryption.

- allow\_none

    `1` - allow JWS with `none` 'alg' header value (which means that token has no signature), **BEWARE: DANGEROUS, UNSECURE!!!**

    `0` (default) - do not allow JWS with `none` 'alg' header value

- extra\_headers

    This optional parameter may contain a HASH ref with items that will be added to JWT header.

    If you want to use PBES2-based 'alg' like `PBES2-HS512+A256KW` you can set PBES2 salt len (p2s) in bytes and
    iteration count (p2c) via `extra_headers` like this:

        my $token = encode_jwt(payload=>$p, key=>$k, alg=>'PBES2-HS512+A256KW', extra_headers=>{p2c=8000, p2s=>32});
        #NOTE: handling of p2s header is a special case, in the end it is replaced with the generated salt

    You can also use this to specify a kid value (see ["kid\_keys"](#kid_keys))

        my $token = encode_jwt(payload=>$p, key=>$k, alg => 'RS256', extra_headers=>{kid=>'key1'});

- unprotected\_headers

    A hash with additional integrity unprotected headers - JWS and JWE (not available for `compact` serialization);

- shared\_unprotected\_headers

    A hash with additional integrity unprotected headers - JWE only (not available for `compact` serialization);

- aad

    Additional Authenticated Data - scalar value with any (even raw octects) data - JWE only (not available for `compact` serialization);

- serialization

    Specify serialization method: `compat` (= default) for Compact JWS/JWE serialization or `flattened` for Flattened JWS/JWE JSON serialization.

    General JSON serialization is not supported yet.

- zip

    Compression method, currently 'deflate' is the only one supported. `undef` (default) means no compression.

        my $token = encode_jwt(payload=>$p, key=>$k, alg=>'HS256', zip=>'deflate');
        #or define compression level
        my $token = encode_jwt(payload=>$p, key=>$k, alg=>'HS256', zip=>['deflate', 9]);

- auto\_iat

    `1` - set 'iat' (Issued At) claim to current time (epoch seconds since 1970) at the moment of token encoding

    `0` (default) - do not set 'iat' claim

    NOTE: claims are part of the payload and can be used only if the payload is a HASH ref!

- relative\_exp

    Set 'exp' claim (Expiration Time) to current time + `relative_exp` value (in seconds).

    NOTE: claims are part of the payload and can be used only if the payload is a HASH ref!

- relative\_nbf

    Set 'nbf' claim (Not Before) to current time + `relative_nbf` value (in seconds).

    NOTE: claims are part of the payload and can be used only if the payload is a HASH ref!

# SEE ALSO

[Crypt::Cipher::AES](https://metacpan.org/pod/Crypt%3A%3ACipher%3A%3AAES), [Crypt::AuthEnc::GCM](https://metacpan.org/pod/Crypt%3A%3AAuthEnc%3A%3AGCM), [Crypt::PK::RSA](https://metacpan.org/pod/Crypt%3A%3APK%3A%3ARSA), [Crypt::PK::ECC](https://metacpan.org/pod/Crypt%3A%3APK%3A%3AECC), [Crypt::KeyDerivation](https://metacpan.org/pod/Crypt%3A%3AKeyDerivation), [Crypt::KeyWrap](https://metacpan.org/pod/Crypt%3A%3AKeyWrap)

# LICENSE

This program is free software; you can redistribute it and/or modify it under the same terms as Perl itself.

# COPYRIGHT

Copyright (c) 2015-2025 DCIT, a.s. [https://www.dcit.cz](https://www.dcit.cz) / Karel Miko
