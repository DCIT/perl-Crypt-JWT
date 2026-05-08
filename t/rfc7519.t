use strict;
use warnings;
use Test::More;

use Crypt::JWT qw(decode_jwt);

# Test vectors from RFC 7519 (JSON Web Token).
# https://www.rfc-editor.org/rfc/rfc7519.txt
#
# RFC 7519 Section 3.1 contains the canonical "joe" JWT example, and
# Appendix A.1/A.2 give an Encrypted JWT and a Nested JWT. The HMAC
# signing key for Section 3.1 is taken from RFC 7515 Appendix A.1; the
# RSA key for Appendix A.1/A.2 is taken from RFC 7516 Appendix A.2.
# Both key sources are referenced explicitly by RFC 7519.

my $hs256_jwk = {
    kty => "oct",
    k   => "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
};

my $rsa_jwk = {
    kty => "RSA",
    n   => "sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1WlUzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDprecbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBIY2EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU7-VTdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw",
    e   => "AQAB",
    d   => "VFCWOqXr8nvZNyaaJLXdnNPXZKRaWCjkU5Q2egQQpTBMwhprMzWzpR8Sxq1OPThh_J6MUD8Z35wky9b8eEO0pwNS8xlh1lOFRRBoNqDIKVOku0aZb-rynq8cxjDTLZQ6Fz7jSjR1Klop-YKaUHc9GsEofQqYruPhzSA-QgajZGPbE_0ZaVDJHfyd7UUBUKunFMScbflYAAOYJqVIVwaYR5zWEEceUjNnTNo_CVSj-VvXLO5VZfCUAVLgW4dpf1SrtZjSt34YLsRarSb127reG_DUwg9Ch-KyvjT1SkHgUWRVGcyly7uvVGRSDwsXypdrNinPA4jlhoNdizK2zF2CWQ",
    p   => "9gY2w6I6S6L0juEKsbeDAwpd9WMfgqFoeA9vEyEUuk4kLwBKcoe1x4HG68ik918hdDSE9vDQSccA3xXHOAFOPJ8R9EeIAbTi1VwBYnbTp87X-xcPWlEPkrdoUKW60tgs1aNd_Nnc9LEVVPMS390zbFxt8TN_biaBgelNgbC95sM",
    q   => "uKlCKvKv_ZJMVcdIs5vVSU_6cPtYI1ljWytExV_skstvRSNi9r66jdd9-yBhVfuG4shsp2j7rGnIio901RBeHo6TPKWVVykPu1iYhQXw1jIABfw-MVsN-3bQ76WLdt2SDxsHs7q7zPyUyHXmps7ycZ5c72wGkUwNOjYelmkiNS0",
    dp  => "w0kZbV63cVRvVX6yk3C8cMxo2qCM4Y8nsq1lmMSYhG4EcL6FWbX5h9yuvngs4iLEFk6eALoUS4vIWEwcL4txw9LsWH_zKI-hwoReoP77cOdSL4AVcraHawlkpyd2TWjE5evgbhWtOxnZee3cXJBkAi64Ik6jZxbvk-RR3pEhnCs",
    dq  => "o_8V14SezckO6CNLKs_btPdFiO9_kC1DsuUTd2LAfIIVeMZ7jn1Gus_Ff7B7IVx3p5KuBGOVF8L-qifLb6nQnLysgHDh132NDioZkhH7mI7hPG-PYE_odApKdnqECHWw0J-F0JWnUd6D2B_1TvF9mXA2Qx-iGYn8OVV1Bsmp6qU",
    qi  => "eNho5yRBEBxhGBtQRww9QirZsB66TrfFReG_CcteI1aCneT0ELGhYlRlCtUkTRclIfuEPmNsNDPbLoLqqCVznFbvdB7x-Tl-m0l_eFTj2KiqwGqE9PZB9nNTwMVvH3VRRSLWACvPnSiwP8N5Usy-WRXS-V7TbpxIhvepTfE0NNo",
};

#----------------------------------------------------------------------
# Section 3.1: Example JWT (HS256, identical to RFC 7515 A.1)
#----------------------------------------------------------------------
{
    my $jwt = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9".
              ".eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ".
              ".dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

    my ($header, $payload) = decode_jwt(token=>$jwt, key=>$hs256_jwk, decode_header=>1, verify_exp=>0);
    is($header->{typ}, "JWT",   "Section 3.1 header typ");
    is($header->{alg}, "HS256", "Section 3.1 header alg");
    is($payload->{iss}, "joe",  "Section 3.1 payload iss");
    is($payload->{exp}, 1300819380, "Section 3.1 payload exp");
    ok($payload->{"http://example.com/is_root"}, "Section 3.1 payload http://example.com/is_root");
}

#----------------------------------------------------------------------
# Section 6.1: Unsecured JWT (alg=none)
#----------------------------------------------------------------------
{
    my $jwt = "eyJhbGciOiJub25lIn0".
              ".eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ".
              ".";

    my ($header, $payload) = decode_jwt(token=>$jwt, allow_none=>1, decode_header=>1, verify_exp=>0);
    is($header->{alg}, "none", "Section 6.1 alg=none header");
    is($payload->{iss}, "joe", "Section 6.1 payload iss");
}

#----------------------------------------------------------------------
# Appendix A.1: Example Encrypted JWT (RSA1_5 + A128CBC-HS256).
# Same JWE computation/keys as RFC 7516 Appendix A.2, but the JWE
# Plaintext is the JWT Claims Set from Section 3.1.
#----------------------------------------------------------------------
{
    my $jwt = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0".
              ".QR1Owv2ug2WyPBnbQrRARTeEk9kDO2w8qDcjiHnSJflSdv1iNqhWXaKH4MqAkQtMoNfABIPJaZm0HaA415sv3aeuBWnD8J-Ui7Ah6cWafs3ZwwFKDFUUsWHSK-IPKxLGTkND09XyjORj_CHAgOPJ-Sd8ONQRnJvWn_hXV1BNMHzUjPyYwEsRhDhzjAD26imasOTsgruobpYGoQcXUwFDn7moXPRfDE8-NoQX7N7ZYMmpUDkR-Cx9obNGwJQ3nM52YCitxoQVPzjbl7WBuB7AohdBoZOdZ24WlN1lVIeh8v1K4krB8xgKvRU8kgFrEn_a1rZgN5TiysnmzTROF869lQ".
              ".AxY8DCtDaGlsbGljb3RoZQ".
              ".MKOle7UQrG6nSxTLX6Mqwt0orbHvAKeWnDYvpIAeZ72deHxz3roJDXQyhxx0wKaMHDjUEOKIwrtkHthpqEanSBNYHZgmNOV7sln1Eu9g3J8".
              ".fiK51VwhsxJ-siBMR-YFiA";

    my ($header, $payload) = decode_jwt(token=>$jwt, key=>$rsa_jwk, decode_header=>1, verify_exp=>0);
    is($header->{alg}, "RSA1_5",        "Appendix A.1 header alg");
    is($header->{enc}, "A128CBC-HS256", "Appendix A.1 header enc");
    is($payload->{iss}, "joe",          "Appendix A.1 payload iss");
    is($payload->{exp}, 1300819380,     "Appendix A.1 payload exp");
    ok($payload->{"http://example.com/is_root"}, "Appendix A.1 payload http://example.com/is_root");
}

#----------------------------------------------------------------------
# Appendix A.2: Nested JWT (JWE wrapping a JWS).
# The plaintext of the JWE is the JWS from RFC 7515 Appendix A.2; the
# JWE uses RSA1_5 + A128CBC-HS256 with cty=JWT to mark nesting.
# Crypt::JWT walks the cty=JWT chain when decode_payload defaults
# apply, so the inner JWS payload is what comes back.
#----------------------------------------------------------------------
{
    my $jwt = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiY3R5IjoiSldUIn0".
              ".g_hEwksO1Ax8Qn7HoN-BVeBoa8FXe0kpyk_XdcSmxvcM5_P296JXXtoHISr_DD_MqewaQSH4dZOQHoUgKLeFly-9RI11TG-_Ge1bZFazBPwKC5lJ6OLANLMd0QSL4fYEb9ERe-epKYE3xb2jfY1AltHqBO-PM6j23Guj2yDKnFv6WO72tteVzm_2n17SBFvhDuR9a2nHTE67pe0XGBUS_TK7ecA-iVq5COeVdJR4U4VZGGlxRGPLRHvolVLEHx6DYyLpw30Ay9R6d68YCLi9FYTq3hIXPK_-dmPlOUlKvPr1GgJzRoeC9G5qCvdcHWsqJGTO_z3Wfo5zsqwkxruxwA".
              ".UmVkbW9uZCBXQSA5ODA1Mg".
              ".VwHERHPvCNcHHpTjkoigx3_ExK0Qc71RMEParpatm0X_qpg-w8kozSjfNIPPXiTBBLXR65CIPkFqz4l1Ae9w_uowKiwyi9acgVztAi-pSL8GQSXnaamh9kX1mdh3M_TT-FZGQFQsFhu0Z72gJKGdfGE-OE7hS1zuBD5oEUfk0Dmb0VzWEzpxxiSSBbBAzP10l56pPfAtrjEYw-7ygeMkwBl6Z_mLS6w6xUgKlvW6ULmkV-uLC4FUiyKECK4e3WZYKw1bpgIqGYsw2v_grHjszJZ-_I5uM-9RA8ycX9KqPRp9gc6pXmoU_-27ATs9XCvrZXUtK2902AUzqpeEUJYjWWxSNsS-r1TJ1I-FMJ4XyAiGrfmo9hQPcNBYxPz3GQb28Y5CLSQfNgKSGt0A4isp1hBUXBHAndgtcslt7ZoQJaKe_nNJgNliWtWpJ_ebuOpEl8jdhehdccnRMIwAmU1n7SPkmhIl1HlSOpvcvDfhUN5wuqU955vOBvfkBOh5A11UzBuo2WlgZ6hYi9-e3w29bR0C2-pp3jbqxEDw3iWaf2dc5b-LnR0FEYXvI_tYk5rd_J9N0mg0tQ6RbpxNEMNoA9QWk5lgdPvbh9BaO195abQ".
              ".AVO9iT5AV4CzvDJCdhSFlQ";

    # Decrypt the outer JWE; the plaintext is the inner JWS compact form.
    my ($header, $inner) = decode_jwt(token=>$jwt, key=>$rsa_jwk,
                                      decode_header=>1, decode_payload=>0,
                                      verify_exp=>0);
    is($header->{alg}, "RSA1_5",        "Appendix A.2 outer alg");
    is($header->{enc}, "A128CBC-HS256", "Appendix A.2 outer enc");
    is($header->{cty}, "JWT",           "Appendix A.2 outer cty=JWT (nested)");

    # The inner JWS is the RFC 7515 Appendix A.2 example.
    my $expected_inner = "eyJhbGciOiJSUzI1NiJ9".
        ".eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ".
        ".cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw";
    is($inner, $expected_inner, "Appendix A.2 inner JWS recovered byte-for-byte");

    # The inner JWS is signed with the RSA key from RFC 7515 Appendix A.2
    # (a different key than the one that wraps the JWE above).
    my $inner_signing_jwk = {
        kty => "RSA",
        n   => "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ",
        e   => "AQAB",
    };
    my $inner_payload = decode_jwt(token=>$inner, key=>$inner_signing_jwk, verify_exp=>0);
    is($inner_payload->{iss}, "joe", "Appendix A.2 inner JWS payload iss");
    is($inner_payload->{exp}, 1300819380, "Appendix A.2 inner JWS payload exp");
}

done_testing;
