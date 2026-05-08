use strict;
use warnings;
use Test::More;

use Crypt::JWT qw(decode_jwt);

# Test vectors from RFC 7516 (JSON Web Encryption) Appendix A.
# https://www.rfc-editor.org/rfc/rfc7516.txt
#
# The compact-serialized JWE strings, JWK keys and the expected
# plaintexts ("The true sign of intelligence is not knowledge but
# imagination." / "Live long and prosper.") are reproduced verbatim
# from the RFC. We decrypt and assert the recovered plaintext.

my $plain_oaep = "The true sign of intelligence is not knowledge but imagination.";
my $plain_pksp = "Live long and prosper.";

#----------------------------------------------------------------------
# A.1 Example JWE using RSAES-OAEP and AES GCM
#----------------------------------------------------------------------
{
  my $jwk = {
    kty => "RSA",
    n   => "oahUIoWw0K0usKNuOR6H4wkf4oBUXHTxRvgb48E-BVvxkeDNjbC4he8rUWcJoZmds2h7M70imEVhRU5djINXtqllXI4DFqcI1DgjT9LewND8MW2Krf3Spsk_ZkoFnilakGygTwpZ3uesH-PFABNIUYpOiN15dsQRkgr0vEhxN92i2asbOenSZeyaxziK72UwxrrKoExv6kc5twXTq4h-QChLOln0_mtUZwfsRaMStPs6mS6XrgxnxbWhojf663tuEQueGC-FCMfra36C9knDFGzKsNa7LZK2djYgyD3JR_MB_4NUJW_TqOQtwHYbxevoJArm-L5StowjzGy-_bq6Gw",
    e   => "AQAB",
    d   => "kLdtIj6GbDks_ApCSTYQtelcNttlKiOyPzMrXHeI-yk1F7-kpDxY4-WY5NWV5KntaEeXS1j82E375xxhWMHXyvjYecPT9fpwR_M9gV8n9Hrh2anTpTD93Dt62ypW3yDsJzBnTnrYu1iwWRgBKrEYY46qAZIrA2xAwnm2X7uGR1hghkqDp0Vqj3kbSCz1XyfCs6_LehBwtxHIyh8Ripy40p24moOAbgxVw3rxT_vlt3UVe4WO3JkJOzlpUf-KTVI2Ptgm-dARxTEtE-id-4OJr0h-K-VFs3VSndVTIznSxfyrj8ILL6MG_Uv8YAu7VILSB3lOW085-4qE3DzgrTjgyQ",
    p   => "1r52Xk46c-LsfB5P442p7atdPUrxQSy4mti_tZI3Mgf2EuFVbUoDBvaRQ-SWxkbkmoEzL7JXroSBjSrK3YIQgYdMgyAEPTPjXv_hI2_1eTSPVZfzL0lffNn03IXqWF5MDFuoUYE0hzb2vhrlN_rKrbfDIwUbTrjjgieRbwC6Cl0",
    q   => "wLb35x7hmQWZsWJmB_vle87ihgZ19S8lBEROLIsZG4ayZVe9Hi9gDVCOBmUDdaDYVTSNx_8Fyw1YYa9XGrGnDew00J28cRUoeBB_jKI1oma0Orv1T9aXIWxKwd4gvxFImOWr3QRL9KEBRzk2RatUBnmDZJTIAfwTs0g68UZHvtc",
    dp  => "ZK-YwE7diUh0qR1tR7w8WHtolDx3MZ_OTowiFvgfeQ3SiresXjm9gZ5KLhMXvo-uz-KUJWDxS5pFQ_M0evdo1dKiRTjVw_x4NyqyXPM5nULPkcpU827rnpZzAJKpdhWAgqrXGKAECQH0Xt4taznjnd_zVpAmZZq60WPMBMfKcuE",
    dq  => "Dq0gfgJ1DdFGXiLvQEZnuKEN0UUmsJBxkjydc3j4ZYdBiMRAy86x0vHCjywcMlYYg4yoC4YZa9hNVcsjqA3FeiL19rk8g6Qn29Tt0cj8qqyFpz9vNDBUfCAiJVeESOjJDZPYHdHY8v1b-o-Z2X5tvLx-TCekf7oxyeKDUqKWjis",
    qi  => "VIMpMYbPf47dT1w_zDUXfPimsSegnMOA1zTaX7aGk_8urY6R8-ZW1FxU7AlWAyLWybqq6t16VFd7hQd0y6flUK4SlOydB61gwanOsXGOAOv82cHq0E3eL4HrtZkUuKvnPrMnsUUFlfUdybVzxyjz9JF_XyaY14ardLSjf4L_FNY",
  };
  my $jwe = "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ".
            ".OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGeipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDbSv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaVmqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je81860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi6UklfCpIMfIjf7iGdXKHzg".
            ".48V1_ALb6US04U3b".
            ".5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6jiSdiwkIr3ajwQzaBtQD_A".
            ".XFBoMYUZodetZdvTiFvSkQ";

  my ($header, $payload) = decode_jwt(token=>$jwe, key=>$jwk, decode_header=>1, decode_payload=>0);
  is($header->{alg}, "RSA-OAEP", "A.1 header alg");
  is($header->{enc}, "A256GCM",  "A.1 header enc");
  is($payload, $plain_oaep,      "A.1 plaintext recovered");
}

#----------------------------------------------------------------------
# A.2 Example JWE using RSAES-PKCS1-v1_5 and AES_128_CBC_HMAC_SHA_256
#----------------------------------------------------------------------
{
  my $jwk = {
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
  my $jwe = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0".
            ".UGhIOguC7IuEvf_NPVaXsGMoLOmwvc1GyqlIKOK1nN94nHPoltGRhWhw7Zx0-kFm1NJn8LE9XShH59_i8J0PH5ZZyNfGy2xGdULU7sHNF6Gp2vPLgNZ__deLKxGHZ7PcHALUzoOegEI-8E66jX2E4zyJKx-YxzZIItRzC5hlRirb6Y5Cl_p-ko3YvkkysZIFNPccxRU7qve1WYPxqbb2Yw8kZqa2rMWI5ng8OtvzlV7elprCbuPhcCdZ6XDP0_F8rkXds2vE4X-ncOIM8hAYHHi29NX0mcKiRaD0-D-ljQTP-cFPgwCp6X-nZZd9OHBv-B3oWh2TbqmScqXMR4gp_A".
            ".AxY8DCtDaGlsbGljb3RoZQ".
            ".KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY".
            ".9hH0vgRfYgPnAHOd8stkvw";

  my ($header, $payload) = decode_jwt(token=>$jwe, key=>$jwk, decode_header=>1, decode_payload=>0);
  is($header->{alg}, "RSA1_5",        "A.2 header alg");
  is($header->{enc}, "A128CBC-HS256", "A.2 header enc");
  is($payload, $plain_pksp,           "A.2 plaintext recovered");
}

#----------------------------------------------------------------------
# A.3 Example JWE Using AES Key Wrap and AES_128_CBC_HMAC_SHA_256
#----------------------------------------------------------------------
{
  my $jwk = { kty => "oct", k => "GawgguFyGrWKav7AX4VKUg" };
  my $jwe = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0".
            ".6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ".
            ".AxY8DCtDaGlsbGljb3RoZQ".
            ".KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY".
            ".U0m_YmjN04DJvceFICbCVQ";

  my ($header, $payload) = decode_jwt(token=>$jwe, key=>$jwk, decode_header=>1, decode_payload=>0);
  is($header->{alg}, "A128KW",        "A.3 header alg");
  is($header->{enc}, "A128CBC-HS256", "A.3 header enc");
  is($payload, $plain_pksp,           "A.3 plaintext recovered");
}

#----------------------------------------------------------------------
# A.5 Flattened JWE JSON Serialization (same payload as A.3)
#----------------------------------------------------------------------
{
  my $jwk = { kty => "oct", k => "GawgguFyGrWKav7AX4VKUg" };
  my $flat = '{"protected":"eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",'.
             '"unprotected":{"jku":"https://server.example.com/keys.jwks"},'.
             '"header":{"alg":"A128KW","kid":"7"},'.
             '"encrypted_key":"6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",'.
             '"iv":"AxY8DCtDaGlsbGljb3RoZQ",'.
             '"ciphertext":"KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY",'.
             '"tag":"Mz-VPPyU4RlcuYv1IwIvzw"}';

  my ($header, $payload) = decode_jwt(token=>$flat, key=>$jwk, decode_header=>1, decode_payload=>0);
  is($header->{alg}, "A128KW",                                   "A.5 header alg (per-recipient)");
  is($header->{enc}, "A128CBC-HS256",                            "A.5 header enc (protected)");
  is($header->{jku}, "https://server.example.com/keys.jwks",     "A.5 header jku (shared)");
  is($header->{kid}, "7",                                        "A.5 header kid (per-recipient)");
  is($payload, $plain_pksp,                                      "A.5 plaintext recovered");
}

done_testing;
