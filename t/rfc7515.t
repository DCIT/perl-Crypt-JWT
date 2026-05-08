use strict;
use warnings;
use Test::More;
use JSON qw(decode_json);

use Crypt::JWT qw(decode_jwt encode_jwt);
use Crypt::Misc qw(decode_b64u);

# Test vectors from RFC 7515 (JSON Web Signature) Appendix A.
# https://www.rfc-editor.org/rfc/rfc7515.txt
#
# The compact JWS strings, payloads and JWK keys reproduced below are
# verbatim copies of the RFC. RSA and ECDSA signatures are randomised
# (or, for ECDSA, depend on the chosen nonce), so for those algorithms
# we only verify the RFC-supplied tokens; we do not re-encode them.
# The HMAC and "none" cases are deterministic and are also re-encoded.

my $rfc_payload = '{"iss":"joe",'."\r\n".' "exp":1300819380,'."\r\n".' "http://example.com/is_root":true}';

# Confirm our reconstructed payload matches the BASE64URL-encoded one
# from the RFC, so the byte-exact CRLF handling is right.
my $rfc_payload_b64u = "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ";
is(decode_b64u($rfc_payload_b64u), $rfc_payload, "A.1 reference payload bytes match");

#----------------------------------------------------------------------
# A.1 Example JWS Using HMAC SHA-256
#----------------------------------------------------------------------
{
  my $jwk = {
    kty => "oct",
    k   => "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
  };
  my $jws = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9".
            ".eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ".
            ".dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

  my ($header, $payload) = decode_jwt(token=>$jws, key=>$jwk, decode_header=>1, verify_exp=>0);
  is($header->{alg}, "HS256",   "A.1 header alg");
  is($header->{typ}, "JWT",     "A.1 header typ");
  is($payload->{iss}, "joe",    "A.1 payload iss");
  is($payload->{exp}, 1300819380, "A.1 payload exp");
  ok($payload->{"http://example.com/is_root"}, "A.1 payload is_root true");

  # HMAC is deterministic, but the RFC's exact bytes use a non-canonical
  # JSON encoding (CRLF + leading space) that JSON.pm does not produce.
  # Verify by signing the RFC's exact signing input instead.
  use Crypt::Mac::HMAC qw(hmac);
  use Crypt::Misc qw(encode_b64u);
  my $key_raw = decode_b64u($jwk->{k});
  my ($h_b64, $p_b64, $s_b64) = split /\./, $jws;
  my $sig = encode_b64u(hmac('SHA256', $key_raw, "$h_b64.$p_b64"));
  is($sig, $s_b64, "A.1 HMAC signature reproduced from signing input");
}

#----------------------------------------------------------------------
# A.2 Example JWS Using RSASSA-PKCS1-v1_5 SHA-256
#----------------------------------------------------------------------
{
  my $jwk = {
    kty => "RSA",
    n   => "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ",
    e   => "AQAB",
    d   => "Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97IjlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYTCBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLhBOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ",
    p   => "4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdiYrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPGBY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc",
    q   => "uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxaewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc",
    dp  => "BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3QLdhrqE2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0",
    dq  => "h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-kyNlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU",
    qi  => "IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2oy26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLUW0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U",
  };
  my $jws = "eyJhbGciOiJSUzI1NiJ9".
            ".eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ".
            ".cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw";

  my ($header, $payload) = decode_jwt(token=>$jws, key=>$jwk, decode_header=>1, verify_exp=>0);
  is($header->{alg}, "RS256", "A.2 header alg");
  is($payload->{iss}, "joe",  "A.2 payload iss");
  is($payload->{exp}, 1300819380, "A.2 payload exp");
}

#----------------------------------------------------------------------
# A.3 Example JWS Using ECDSA P-256 SHA-256
#----------------------------------------------------------------------
{
  my $jwk = {
    kty => "EC",
    crv => "P-256",
    x   => "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
    y   => "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
    d   => "jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI",
  };
  my $jws = "eyJhbGciOiJFUzI1NiJ9".
            ".eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ".
            ".DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q";

  my ($header, $payload) = decode_jwt(token=>$jws, key=>$jwk, decode_header=>1, verify_exp=>0);
  is($header->{alg}, "ES256", "A.3 header alg");
  is($payload->{iss}, "joe",  "A.3 payload iss");
}

#----------------------------------------------------------------------
# A.4 Example JWS Using ECDSA P-521 SHA-512
#----------------------------------------------------------------------
{
  my $jwk = {
    kty => "EC",
    crv => "P-521",
    x   => "AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk",
    y   => "ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDly79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2",
    d   => "AY5pb7A0UFiB3RELSD64fTLOSV_jazdF7fLYyuTw8lOfRhWg6Y6rUrPAxerEzgdRhajnu0ferB0d53vM9mE15j2C",
  };
  my $jws = "eyJhbGciOiJFUzUxMiJ9".
            ".UGF5bG9hZA".
            ".AdwMgeerwtHoh-l192l60hp9wAHZFVJbLfD_UxMi70cwnZOYaRI1bKPWROc-mZZqwqT2SI-KGDKB34XO0aw_7XdtAG8GaSwFKdCAPZgoXD2YBJZCPEX3xKpRwcdOO8KpEHwJjyqOgzDO7iKvU8vcnwNrmxYbSW9ERBXukOXolLzeO_Jn";

  my ($header, $payload) = decode_jwt(token=>$jws, key=>$jwk, decode_header=>1, decode_payload=>0);
  is($header->{alg}, "ES512", "A.4 header alg");
  is($payload, "Payload",     "A.4 payload bytes");
}

#----------------------------------------------------------------------
# A.5 Example Unsecured JWS
#----------------------------------------------------------------------
{
  my $jws = "eyJhbGciOiJub25lIn0".
            ".eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ".
            ".";

  my ($header, $payload) = decode_jwt(token=>$jws, allow_none=>1, decode_header=>1, verify_exp=>0);
  is($header->{alg}, "none",   "A.5 header alg");
  is($payload->{iss}, "joe",   "A.5 payload iss");
  is($payload->{exp}, 1300819380, "A.5 payload exp");

  # Re-encoding is not byte-identical because JSON.pm doesn't emit the
  # RFC's CRLF + leading space; verify only the signature segment is empty.
  my $reencoded = encode_jwt(payload => $payload, alg => 'none', allow_none=>1, key => '');
  my ($h, $p, $s) = split /\./, $reencoded, -1;
  is($s, "", "A.5 unsecured token has empty signature");
}

#----------------------------------------------------------------------
# A.6 Example JWS Using General JWS JSON Serialization
# The compact form for the second signature is also tested by A.7.
# The general JSON form is not directly accepted by Crypt::JWT, so we
# verify the inner per-signature compact tokens here.
#----------------------------------------------------------------------
{
  my $jwk_rsa = {
    kty => "RSA",
    n   => "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ",
    e   => "AQAB",
  };
  my $jwk_ec = {
    kty => "EC",
    crv => "P-256",
    x   => "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
    y   => "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
  };

  my $payload_b64u = "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ";

  # First signature (same RSA computation as A.2)
  my $jws_rs = "eyJhbGciOiJSUzI1NiJ9.$payload_b64u".
               ".cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw";
  my $p_rs = decode_jwt(token=>$jws_rs, key=>$jwk_rsa, verify_exp=>0);
  is($p_rs->{iss}, "joe", "A.6 RSA-signed JWS verifies");

  # Second signature (same ECDSA computation as A.3)
  my $jws_es = "eyJhbGciOiJFUzI1NiJ9.$payload_b64u".
               ".DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q";
  my $p_es = decode_jwt(token=>$jws_es, key=>$jwk_ec, verify_exp=>0);
  is($p_es->{iss}, "joe", "A.6 ECDSA-signed JWS verifies");
}

#----------------------------------------------------------------------
# A.7 Example JWS Using Flattened JWS JSON Serialization
#----------------------------------------------------------------------
{
  my $jwk_ec = {
    kty => "EC",
    crv => "P-256",
    x   => "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
    y   => "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
  };

  my $flat = '{"payload":"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ","protected":"eyJhbGciOiJFUzI1NiJ9","header":{"kid":"e9bc097a-ce51-4036-9562-d2ade882db0d"},"signature":"DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"}';

  my ($header, $payload) = decode_jwt(token=>$flat, key=>$jwk_ec, decode_header=>1, verify_exp=>0);
  is($header->{alg}, "ES256",                            "A.7 protected alg");
  is($header->{kid}, "e9bc097a-ce51-4036-9562-d2ade882db0d", "A.7 unprotected kid");
  is($payload->{iss}, "joe",                             "A.7 payload iss");
}

done_testing;
