use strict;
use warnings;
use Test::More tests => 4;

use Crypt::JWT qw(decode_jwt encode_jwt);

### JWS - test case from https://github.com/Spomky-Labs/jose

my $key1 = {
        'kid' => 'e9bc097a-ce51-4036-9562-d2ade882db0d',
        'kty' => 'EC',
        'crv' => 'P-256',
        'x'   => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
        'y'   => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
        'd'   => 'jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI',
};

my $jws = '{"payload":"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ","protected":"eyJhbGciOiJFUzI1NiJ9","header":{"kid":"e9bc097a-ce51-4036-9562-d2ade882db0d"},"signature":"DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"}';

my ($header, $data) = decode_jwt(token=>$jws, key=>$key1, verify_exp=>0, decode_header=>1);
is($data->{iss}, "joe");
is($data->{exp}, 1300819380);
is($header->{alg}, "ES256");
is($header->{kid}, "e9bc097a-ce51-4036-9562-d2ade882db0d");

#-------------------------------------------------------------------------------
#Example from RFC 7516 (JWE)

{
    require JSON;

    #https://tools.ietf.org/html/rfc7516#appendix-A.2.3
    my $jwk_hr = {
        kty => "RSA",
        n => "sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1WlUzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDprecbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBIY2EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU7-VTdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw",
        e => "AQAB",
        d => "VFCWOqXr8nvZNyaaJLXdnNPXZKRaWCjkU5Q2egQQpTBMwhprMzWzpR8Sxq1OPThh_J6MUD8Z35wky9b8eEO0pwNS8xlh1lOFRRBoNqDIKVOku0aZb-rynq8cxjDTLZQ6Fz7jSjR1Klop-YKaUHc9GsEofQqYruPhzSA-QgajZGPbE_0ZaVDJHfyd7UUBUKunFMScbflYAAOYJqVIVwaYR5zWEEceUjNnTNo_CVSj-VvXLO5VZfCUAVLgW4dpf1SrtZjSt34YLsRarSb127reG_DUwg9Ch-KyvjT1SkHgUWRVGcyly7uvVGRSDwsXypdrNinPA4jlhoNdizK2zF2CWQ",
        p => "9gY2w6I6S6L0juEKsbeDAwpd9WMfgqFoeA9vEyEUuk4kLwBKcoe1x4HG68ik918hdDSE9vDQSccA3xXHOAFOPJ8R9EeIAbTi1VwBYnbTp87X-xcPWlEPkrdoUKW60tgs1aNd_Nnc9LEVVPMS390zbFxt8TN_biaBgelNgbC95sM",
        q => "uKlCKvKv_ZJMVcdIs5vVSU_6cPtYI1ljWytExV_skstvRSNi9r66jdd9-yBhVfuG4shsp2j7rGnIio901RBeHo6TPKWVVykPu1iYhQXw1jIABfw-MVsN-3bQ76WLdt2SDxsHs7q7zPyUyHXmps7ycZ5c72wGkUwNOjYelmkiNS0",
        dp => "w0kZbV63cVRvVX6yk3C8cMxo2qCM4Y8nsq1lmMSYhG4EcL6FWbX5h9yuvngs4iLEFk6eALoUS4vIWEwcL4txw9LsWH_zKI-hwoReoP77cOdSL4AVcraHawlkpyd2TWjE5evgbhWtOxnZee3cXJBkAi64Ik6jZxbvk-RR3pEhnCs",
        dq => "o_8V14SezckO6CNLKs_btPdFiO9_kC1DsuUTd2LAfIIVeMZ7jn1Gus_Ff7B7IVx3p5KuBGOVF8L-qifLb6nQnLysgHDh132NDioZkhH7mI7hPG-PYE_odApKdnqECHWw0J-F0JWnUd6D2B_1TvF9mXA2Qx-iGYn8OVV1Bsmp6qU",
        qi => "eNho5yRBEBxhGBtQRww9QirZsB66TrfFReG_CcteI1aCneT0ELGhYlRlCtUkTRclIfuEPmNsNDPbLoLqqCVznFbvdB7x-Tl-m0l_eFTj2KiqwGqE9PZB9nNTwMVvH3VRRSLWACvPnSiwP8N5Usy-WRXS-V7TbpxIhvepTfE0NNo",
    };

    #https://tools.ietf.org/html/rfc7516#appendix-A.3.3
    my $key = { "kty" => "oct", "k" => "GawgguFyGrWKav7AX4VKUg" };

    #https://tools.ietf.org/html/rfc7516#appendix-A.5
    my $jwe_flattened = JSON::encode_json(
        {
            protected     => "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
            unprotected   => { "jku" => "https://server.example.com/keys.jwks" },
            header        => { "alg" => "A128KW", "kid" => "7" },
            encrypted_key => "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
            iv            => "AxY8DCtDaGlsbGljb3RoZQ",
            ciphertext    => "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY",
            tag           => "Mz-VPPyU4RlcuYv1IwIvzw",
        },
    );

    my ($header, $data) = decode_jwt(token=>$jwe_flattened, key=>$key, verify_exp=>0, decode_header=>1);

    #diag explain $header;
    #diag explain $data;
}
