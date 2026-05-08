use strict;
use warnings;
use utf8;
use Test::More;

use Crypt::JWT qw(decode_jwt encode_jwt);
use Crypt::Misc qw(decode_b64u encode_b64u);
use Crypt::Mac::HMAC qw(hmac);

# Test vectors from RFC 7520 (Examples of Protection of Content Using
# JSON Object Signing and Encryption (JOSE)).
# https://www.rfc-editor.org/rfc/rfc7520.txt
#
# This RFC is the JOSE "cookbook" — every section bundles input keys,
# generated material and the resulting compact + JSON serializations.
# Algorithms whose key/key-encryption step is randomised (RSA-PSS,
# ECDSA, RSAES-OAEP, RSA1_5, PBES2, ECDH-ES) cannot be re-produced
# byte-for-byte, so for those we verify only the *decode* side. The
# deterministic ones (HS256, A128KW for the wrap part) are also used as
# verify-only because the library doesn't expose CEK/IV injection.

#----------------------------------------------------------------------
# §3 — JWK examples (used as inputs to the §4/§5 sections below)
#----------------------------------------------------------------------

# §3.2 EC P-521 private key (used by §4.3 ES512 signature)
my $jwk_ec_p521 = {
    kty => "EC",
    kid => "bilbo.baggins\@hobbiton.example",
    use => "sig",
    crv => "P-521",
    x => "AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt",
    y => "AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVySsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1",
    d => "AAhRON2r9cqXX1hg-RoI6R1tX5p2rUAYdmpHZoC1XNM56KtscrX6zbKipQrCW9CGZH3T4ubpnoTKLDYJ_fF3_rJt",
};

# §3.4 RSA 2048-bit key (used by §4.1 RS256 and §4.2 PS384)
my $jwk_rsa_bilbo = {
    kty => "RSA",
    kid => "bilbo.baggins\@hobbiton.example",
    use => "sig",
    n => "n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqVwGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuCLqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5gHdrNP5zw",
    e => "AQAB",
    d => "bWUC9B-EFRIo8kpGfh0ZuyGPvMNKvYWNtB_ikiH9k20eT-O1q_I78eiZkpXxXQ0UTEs2LsNRS-8uJbvQ-A1irkwMSMkK1J3XTGgdrhCku9gRldY7sNA_AKZGh-Q661_42rINLRCe8W-nZ34ui_qOfkLnK9QWDDqpaIsA-bMwWWSDFu2MUBYwkHTMEzLYGqOe04noqeq1hExBTHBOBdkMXiuFhUq1BU6l-DqEiWxqg82sXt2h-LMnT3046AOYJoRioz75tSUQfGCshWTBnP5uDjd18kKhyv07lhfSJdrPdM5Plyl21hsFf4L_mHCuoFau7gdsPfHPxxjVOcOpBrQzwQ",
    p => "3Slxg_DwTXJcb6095RoXygQCAZ5RnAvZlno1yhHtnUex_fp7AZ_9nRaO7HX_-SFfGQeutao2TDjDAWU4Vupk8rw9JR0AzZ0N2fvuIAmr_WCsmGpeNqQnev1T7IyEsnh8UMt-n5CafhkikzhEsrmndH6LxOrvRJlsPp6Zv8bUq0k",
    q => "uKE2dh-cTf6ERF4k4e_jy78GfPYUIaUyoSSJuBzp3Cubk3OCqs6grT8bR_cu0Dm1MZwWmtdqDyI95HrUeq3MP15vMMON8lHTeZu2lmKvwqW7anV5UzhM1iZ7z4yMkuUwFWoBvyY898EXvRD-hdqRxHlSqAZ192zB3pVFJ0s7pFc",
    dp => "B8PVvXkvJrj2L-GYQ7v3y9r6Kw5g9SahXBwsWUzp19TVlgI-YV85q1NIb1rxQtD-IsXXR3-TanevuRPRt5OBOdiMGQp8pbt26gljYfKU_E9xn-RULHz0-ed9E9gXLKD4VGngpz-PfQ_q29pk5xWHoJp009Qf1HvChixRX59ehik",
    dq => "CLDmDGduhylc9o7r84rEUVn7pzQ6PF83Y-iBZx5NT-TpnOZKF1pErAMVeKzFEl41DlHHqqBLSM0W1sOFbwTxYWZDm6sI6og5iTbwQGIC3gnJKbi_7k_vJgGHwHxgPaX2PnvP-zyEkDERuf-ry4c_Z11Cq9AqC2yeL6kdKT1cYF8",
    qi => "3PiqvXQN0zwMeE-sBvZgi289XP9XCQF3VWqPzMKnIgQp7_Tugo6-NZBKCQsMf3HaEGBjTVJs_jcK8-TRXvaKe-7ZMaQj8VfBdYkssbu0NKDDhjJ-GtiseaDVWt7dcH0cfwxgFUHpQh7FoCrjFJ6h6ZEpMF6xmujs4qMpPz8aaI4",
};

# §3.5 HMAC SHA-256 symmetric key
my $jwk_hs256 = {
    kty => "oct",
    kid => "018c0ae5-4d9b-471b-bfd6-eef314bc7037",
    use => "sig",
    alg => "HS256",
    k   => "hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg",
};

# Common payload for the §4 signature examples (JWS Payload from §4 intro).
my $sig_payload_b64u =
    "SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IH".
    "lvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBk".
    "b24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcm".
    "UgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4";
my $sig_payload = decode_b64u($sig_payload_b64u);

# Sanity-check: the RFC's payload starts with "It’s a dangerous business"
like($sig_payload, qr/^It.*dangerous business/, "§4 payload decodes to RFC text");

#----------------------------------------------------------------------
# §4.1 RSA v1.5 (RS256) Signature
#----------------------------------------------------------------------
{
    my $jws =
        "eyJhbGciOiJSUzI1NiIsImtpZCI6ImJpbGJvLmJhZ2dpbnNAaG9iYml0b24uZXhhbXBsZSJ9".
        ".$sig_payload_b64u".
        ".MRjdkly7_-oTPTS3AXP41iQIGKa80A0ZmTuV5MEaHoxnW2e5CZ5NlKtainoFmKZopdHM1O2U4mwzJdQx996ivp83xuglII7PNDi84wnB-BDkoBwA78185hX-Es4JIwmDLJK3lfWRa-XtL0RnltuYv746iYTh_qHRD68BNt1uSNCrUCTJDt5aAE6x8wW1Kt9eRo4QPocSadnHXFxnt8Is9UzpERV0ePPQdLuW3IS_de3xyIrDaLGdjluPxUAhb6L2aXic1U12podGU0KLUQSE_oI-ZnmKJ3F4uOZDnd6QZWJushZ41Axf_fcIe8u9ipH84ogoree7vjbU5y18kDquDg";

    my ($header, $payload) = decode_jwt(token=>$jws, key=>$jwk_rsa_bilbo, decode_header=>1, decode_payload=>0);
    is($header->{alg}, "RS256",                              "§4.1 header alg");
    is($header->{kid}, "bilbo.baggins\@hobbiton.example",    "§4.1 header kid");
    is($payload, $sig_payload,                               "§4.1 payload recovered");
}

#----------------------------------------------------------------------
# §4.2 RSA-PSS (PS384) Signature — randomised, decode-only
#----------------------------------------------------------------------
{
    my $jws =
        "eyJhbGciOiJQUzM4NCIsImtpZCI6ImJpbGJvLmJhZ2dpbnNAaG9iYml0b24uZXhhbXBsZSJ9".
        ".$sig_payload_b64u".
        ".cu22eBqkYDKgIlTpzDXGvaFfz6WGoz7fUDcfT0kkOy42miAh2qyBzk1xEsnk2IpN6-tPid6VrklHkqsGqDqHCdP6O8TTB5dDDItllVo6_1OLPpcbUrhiUSMxbbXUvdvWXzg-UD8biiReQFlfz28zGWVsdiNAUf8ZnyPEgVFn442ZdNqiVJRmBqrYRXe8P_ijQ7p8Vdz0TTrxUeT3lm8d9shnr2lfJT8ImUjvAA2Xez2Mlp8cBE5awDzT0qI0n6uiP1aCN_2_jLAeQTlqRHtfa64QQSUmFAAjVKPbByi7xho0uTOcbH510a6GYmJUAfmWjwZ6oD4ifKo8DYM-X72Eaw";

    my ($header, $payload) = decode_jwt(token=>$jws, key=>$jwk_rsa_bilbo, decode_header=>1, decode_payload=>0);
    is($header->{alg}, "PS384",  "§4.2 header alg");
    is($payload, $sig_payload,   "§4.2 RSA-PSS payload recovered");
}

#----------------------------------------------------------------------
# §4.3 ECDSA P-521 (ES512) Signature — randomised, decode-only
#----------------------------------------------------------------------
{
    my $jws =
        "eyJhbGciOiJFUzUxMiIsImtpZCI6ImJpbGJvLmJhZ2dpbnNAaG9iYml0b24uZXhhbXBsZSJ9".
        ".$sig_payload_b64u".
        ".AE_R_YZCChjn4791jSQCrdPZCNYqHXCTZH0-JZGYNlaAjP2kqaluUIIUnC9qvbu9Plon7KRTzoNEuT4Va2cmL1eJAQy3mtPBu_u_sDDyYjnAMDxXPn7XrT0lw-kvAD890jl8e2puQens_IEKBpHABlsbEPX6sFY8OcGDqoRuBomu9xQ2";

    my ($header, $payload) = decode_jwt(token=>$jws, key=>$jwk_ec_p521, decode_header=>1, decode_payload=>0);
    is($header->{alg}, "ES512",  "§4.3 header alg");
    is($payload, $sig_payload,   "§4.3 ECDSA payload recovered");
}

#----------------------------------------------------------------------
# §4.4 HMAC-SHA256 (HS256) — deterministic, also test signature byte
#----------------------------------------------------------------------
{
    my $protected_b64u = "eyJhbGciOiJIUzI1NiIsImtpZCI6IjAxOGMwYWU1LTRkOWItNDcxYi1iZmQ2LWVlZjMxNGJjNzAzNyJ9";
    my $sig_b64u       = "s0h6KThzkfBBBkLspW1h84VsJZFTsPPqMDA7g1Md7p0";
    my $jws            = "$protected_b64u.$sig_payload_b64u.$sig_b64u";

    my ($header, $payload) = decode_jwt(token=>$jws, key=>$jwk_hs256, decode_header=>1, decode_payload=>0);
    is($header->{alg}, "HS256", "§4.4 header alg");
    is($payload, $sig_payload,  "§4.4 HMAC payload recovered");

    # Recompute the HMAC over the RFC's exact signing input.
    my $key_raw = decode_b64u($jwk_hs256->{k});
    my $sig = encode_b64u(hmac('SHA256', $key_raw, "$protected_b64u.$sig_payload_b64u"));
    is($sig, $sig_b64u, "§4.4 HMAC signature reproduced byte-for-byte");
}

#----------------------------------------------------------------------
# §4.4 — Flattened JWS JSON Serialization (Figure 36)
#----------------------------------------------------------------------
{
    my $flat =
        '{"payload":"'.$sig_payload_b64u.'",'.
        '"protected":"eyJhbGciOiJIUzI1NiIsImtpZCI6IjAxOGMwYWU1LTRkOWItNDcxYi1iZmQ2LWVlZjMxNGJjNzAzNyJ9",'.
        '"signature":"s0h6KThzkfBBBkLspW1h84VsJZFTsPPqMDA7g1Md7p0"}';
    my ($header, $payload) = decode_jwt(token=>$flat, key=>$jwk_hs256, decode_header=>1, decode_payload=>0);
    is($header->{alg}, "HS256",  "§4.4 flattened JSON header alg");
    is($payload, $sig_payload,   "§4.4 flattened JSON payload");
}

#----------------------------------------------------------------------
# §5.1 RSA1_5 + A128CBC-HS256 — randomised RSA wrap, decode-only
#----------------------------------------------------------------------
my $rfc7520_plaintext =
    "You can trust us to stick with you through thick and ".
    "thin\x{2013}to the bitter end. And you can trust us to ".
    "keep any secret of yours\x{2013}closer than you keep it ".
    "yourself. But you cannot trust us to let you face trouble ".
    "alone, and go off without a word. We are your friends, Frodo.";
utf8::encode($rfc7520_plaintext);

# §5.1 RSA 2048 key (Figure 73)
my $jwk_rsa_frodo = {
    kty => "RSA",
    kid => "frodo.baggins\@hobbiton.example",
    use => "enc",
    n => "maxhbsmBtdQ3CNrKvprUE6n9lYcregDMLYNeTAWcLj8NnPU9XIYegTHVHQjxKDSHP2l-F5jS7sppG1wgdAqZyhnWvXhYNvcM7RfgKxqNx_xAHx6f3yy7s-M9PSNCwPC2lh6UAkR4I00EhV9lrypM9Pi4lBUop9t5fS9W5UNwaAllhrd-osQGPjIeI1deHTwx-ZTHu3C60Pu_LJIl6hKn9wbwaUmA4cR5Bd2pgbaY7ASgsjCUbtYJaNIHSoHXprUdJZKUMAzV0WOKPfA6OPI4oypBadjvMZ4ZAj3BnXaSYsEZhaueTXvZB4eZOAjIyh2e_VOIKVMsnDrJYAVotGlvMQ",
    e => "AQAB",
    d => "Kn9tgoHfiTVi8uPu5b9TnwyHwG5dK6RE0uFdlpCGnJN7ZEi963R7wybQ1PLAHmpIbNTztfrheoAniRV1NCIqXaW_qS461xiDTp4ntEPnqcKsyO5jMAji7-CL8vhpYYowNFvIesgMoVaPRYMYT9TW63hNM0aWs7USZ_hLg6Oe1mY0vHTI3FucjSM86Nff4oIENt43r2fspgEPGRrdE6fpLc9Oaq-qeP1GFULimrRdndm-P8q8kvN3KHlNAtEgrQAgTTgz80S-3VD0FgWfgnb1PNmiuPUxO8OpI9KDIfu_acc6fg14nsNaJqXe6RESvhGPH2afjHqSy_Fd2vpzj85bQQ",
    p => "2DwQmZ43FoTnQ8IkUj3BmKRf5Eh2mizZA5xEJ2MinUE3sdTYKSLtaEoekX9vbBZuWxHdVhM6UnKCJ_2iNk8Z0ayLYHL0_G21aXf9-unynEpUsH7HHTklLpYAzOOx1ZgVljoxAdWNn3hiEFrjZLZGS7lOH-a3QQlDDQoJOJ2VFmU",
    q => "te8LY4-W7IyaqH1ExujjMqkTAlTeRbv0VLQnfLY2xINnrWdwiQ93_VF099aP1ESeLja2nw-6iKIe-qT7mtCPozKfVtUYfz5HrJ_XY2kfexJINb9lhZHMv5p1skZpeIS-GPHCC6gRlKo1q-idn_qxyusfWv7WAxlSVfQfk8d6Et0",
    dp => "UfYKcL_or492vVc0PzwLSplbg4L3-Z5wL48mwiswbpzOyIgd2xHTHQmjJpFAIZ8q-zf9RmgJXkDrFs9rkdxPtAsL1WYdeCT5c125Fkdg317JVRDo1inX7x2Kdh8ERCreW8_4zXItuTl_KiXZNU5lvMQjWbIw2eTx1lpsflo0rYU",
    dq => "iEgcO-QfpepdH8FWd7mUFyrXdnOkXJBCogChY6YKuIHGc_p8Le9MbpFKESzEaLlN1Ehf3B6oGBl5Iz_ayUlZj2IoQZ82znoUrpa9fVYNot87ACfzIG7q9Mv7RiPAderZi03tkVXAdaBau_9vs5rS-7HMtxkVrxSUvJY14TkXlHE",
    qi => "kC-lzZOqoFaZCr5l0tOVtREKoVqaAYhQiqIRGL-MzS4sCmRkxm5vZlXYx6RtE1n_AagjqajlkjieGlxTTThHD8Iga6foGBMaAr5uR1hGQpSc7Gl7CF1DZkBJMTQN6EshYzZfxW08mIO8M6Rzuh0beL6fG9mkDcIyPrBXx2bQ_mM",
};

{
    my $jwe =
        "eyJhbGciOiJSU0ExXzUiLCJraWQiOiJmcm9kby5iYWdnaW5zQGhvYmJpdG9uLmV4YW1wbGUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0".
        ".laLxI0j-nLH-_BgLOXMozKxmy9gffy2gTdvqzfTihJBuuzxg0V7yk1WClnQePFvG2K-pvSlWc9BRIazDrn50RcRai__3TDON395H3c62tIouJJ4XaRvYHFjZTZ2GXfz8YAImcc91Tfk0WXC2F5Xbb71ClQ1DDH151tlpH77f2ff7xiSxh9oSewYrcGTSLUeeCt36r1Kt3OSj7EyBQXoZlN7IxbyhMAfgIe7Mv1rOTOI5I8NQqeXXW8VlzNmoxaGMny3YnGir5Wf6Qt2nBq4qDaPdnaAuuGUGEecelIO1wx1BpyIfgvfjOhMBs9M8XL223Fg47xlGsMXdfuY-4jaqVw".
        ".bbd5sTkYwhAIqfHsx8DayA".
        ".0fys_TY_na7f8dwSfXLiYdHaA2DxUjD67ieF7fcVbIR62JhJvGZ4_FNVSiGc_raa0HnLQ6s1P2sv3Xzl1p1l_o5wR_RsSzrS8Z-wnI3Jvo0mkpEEnlDmZvDu_k8OWzJv7eZVEqiWKdyVzFhPpiyQU28GLOpRc2VbVbK4dQKPdNTjPPEmRqcaGeTWZVyeSUvf5k59yJZxRuSvWFf6KrNtmRdZ8R4mDOjHSrM_s8uwIFcqt4r5GX8TKaI0zT5CbL5Qlw3sRc7u_hg0yKVOiRytEAEs3vZkcfLkP6nbXdC_PkMdNS-ohP78T2O6_7uInMGhFeX4ctHG7VelHGiT93JfWDEQi5_V9UN1rhXNrYu-0fVMkZAKX3VWi7lzA6BP430m".
        ".kvKuFBXHe5mQr4lqgobAUg";
    my ($header, $payload) = decode_jwt(token=>$jwe, key=>$jwk_rsa_frodo, decode_header=>1, decode_payload=>0);
    is($header->{alg}, "RSA1_5",         "§5.1 header alg");
    is($header->{enc}, "A128CBC-HS256",  "§5.1 header enc");
    is($payload, $rfc7520_plaintext,     "§5.1 plaintext recovered");
}

#----------------------------------------------------------------------
# §5.2 RSA-OAEP + A256GCM — RSA-OAEP is randomised, decode-only
#----------------------------------------------------------------------
my $jwk_rsa_samwise = {
    kty => "RSA",
    kid => "samwise.gamgee\@hobbiton.example",
    use => "enc",
    alg => "RSA-OAEP",
    n => "wbdxI55VaanZXPY29Lg5hdmv2XhvqAhoxUkanfzf2-5zVUxa6prHRrI4pP1AhoqJRlZfYtWWd5mmHRG2pAHIlh0ySJ9wi0BioZBl1XP2e-C-FyXJGcTy0HdKQWlrfhTm42EW7Vv04r4gfao6uxjLGwfpGrZLarohiWCPnkNrg71S2CuNZSQBIPGjXfkmIy2tl_VWgGnL22GplyXj5YlBLdxXp3XeStsqo571utNfoUTU8E4qdzJ3U1DItoVkPGsMwlmmnJiwA7sXRItBCivR4M5qnZtdw-7v4WuR4779ubDuJ5nalMv2S66-RPcnFAzWSKxtBDnFJJDGIUe7Tzizjg1nms0Xq_yPub_UOlWn0ec85FCft1hACpWG8schrOBeNqHBODFskYpUc2LC5JA2TaPF2dA67dg1TTsC_FupfQ2kNGcE1LgprxKHcVWYQb86B-HozjHZcqtauBzFNV5tbTuB-TpkcvJfNcFLlH3b8mb-H_ox35FjqBSAjLKyoeqfKTpVjvXhd09knwgJf6VKq6UC418_TOljMVfFTWXUxlnfhOOnzW6HSSzD1c9WrCuVzsUMv54szidQ9wf1cYWf3g5qFDxDQKis99gcDaiCAwM3yEBIzuNeeCa5dartHDb1xEB_HcHSeYbghbMjGfasvKn0aZRsnTyC0xhWBlsolZE",
    e => "AQAB",
    d => "n7fzJc3_WG59VEOBTkayzuSMM780OJQuZjN_KbH8lOZG25ZoA7T4Bxcc0xQn5oZE5uSCIwg91oCt0JvxPcpmqzaJZg1nirjcWZ-oBtVk7gCAWq-B3qhfF3izlbkosrzjHajIcY33HBhsy4_WerrXg4MDNE4HYojy68TcxT2LYQRxUOCf5TtJXvM8olexlSGtVnQnDRutxEUCwiewfmmrfveEogLx9EA-KMgAjTiISXxqIXQhWUQX1G7v_mV_Hr2YuImYcNcHkRvp9E7ook0876DhkO8v4UOZLwA1OlUX98mkoqwc58A_Y2lBYbVx1_s5lpPsEqbbH-nqIjh1fL0gdNfihLxnclWtW7pCztLnImZAyeCWAG7ZIfv-Rn9fLIv9jZ6r7r-MSH9sqbuziHN2grGjD_jfRluMHa0l84fFKl6bcqN1JWxPVhzNZo01yDF-1LiQnqUYSepPf6X3a2SOdkqBRiquE6EvLuSYIDpJq3jDIsgoL8Mo1LoomgiJxUwL_GWEOGu28gplyzm-9Q0U0nyhEf1uhSR8aJAQWAiFImWH5W_IQT9I7-yrindr_2fWQ_i1UgMsGzA7aOGzZfPljRy6z-tY_KuBG00-28S_aWvjyUc-Alp8AUyKjBZ-7CWH32fGWK48j1t-zomrwjL_mnhsPbGs0c9WsWgRzI-K8gE",
    p => "7_2v3OQZzlPFcHyYfLABQ3XP85Es4hCdwCkbDeltaUXgVy9l9etKghvM4hRkOvbb01kYVuLFmxIkCDtpi-zLCYAdXKrAK3PtSbtzld_XZ9nlsYa_QZWpXB_IrtFjVfdKUdMz94pHUhFGFj7nr6NNxfpiHSHWFE1zD_AC3mY46J961Y2LRnreVwAGNw53p07Db8yD_92pDa97vqcZOdgtybH9q6uma-RFNhO1AoiJhYZj69hjmMRXx-x56HO9cnXNbmzNSCFCKnQmn4GQLmRj9sfbZRqL94bbtE4_e0Zrpo8RNo8vxRLqQNwIy85fc6BRgBJomt8QdQvIgPgWCv5HoQ",
    q => "zqOHk1P6WN_rHuM7ZF1cXH0x6RuOHq67WuHiSknqQeefGBA9PWs6ZyKQCO-O6mKXtcgE8_Q_hA2kMRcKOcvHil1hqMCNSXlflM7WPRPZu2qCDcqssd_uMbP-DqYthH_EzwL9KnYoH7JQFxxmcv5An8oXUtTwk4knKjkIYGRuUwfQTus0w1NfjFAyxOOiAQ37ussIcE6C6ZSsM3n41UlbJ7TCqewzVJaPJN5cxjySPZPD3Vp01a9YgAD6a3IIaKJdIxJS1ImnfPevSJQBE79-EXe2kSwVgOzvt-gsmM29QQ8veHy4uAqca5dZzMs7hkkHtw1z0jHV90epQJJlXXnH8Q",
    dp => "19oDkBh1AXelMIxQFm2zZTqUhAzCIr4xNIGEPNoDt1jK83_FJA-xnx5kA7-1erdHdms_Ef67HsONNv5A60JaR7w8LHnDiBGnjdaUmmuO8XAxQJ_ia5mxjxNjS6E2yD44USo2JmHvzeeNczq25elqbTPLhUpGo1IZuG72FZQ5gTjXoTXC2-xtCDEUZfaUNh4IeAipfLugbpe0JAFlFfrTDAMUFpC3iXjxqzbEanflwPvj6V9iDSgjj8SozSM0dLtxvu0LIeIQAeEgT_yXcrKGmpKdSO08kLBx8VUjkbv_3Pn20Gyu2YEuwpFlM_H1NikuxJNKFGmnAq9LcnwwT0jvoQ",
    dq => "S6p59KrlmzGzaQYQM3o0XfHCGvfqHLYjCO557HYQf72O9kLMCfd_1VBEqeD-1jjwELKDjck8kOBl5UvohK1oDfSP1DleAy-cnmL29DqWmhgwM1ip0CCNmkmsmDSlqkUXDi6sAaZuntyukyflI-qSQ3C_BafPyFaKrt1fgdyEwYa08pESKwwWisy7KnmoUvaJ3SaHmohFS78TJ25cfc10wZ9hQNOrIChZlkiOdFCtxDqdmCqNacnhgE3bZQjGp3n83ODSz9zwJcSUvODlXBPc2AycH6Ci5yjbxt4Ppox_5pjm6xnQkiPgj01GpsUssMmBN7iHVsrE7N2iznBNCeOUIQ",
    qi => "FZhClBMywVVjnuUud-05qd5CYU0dK79akAgy9oX6RX6I3IIIPckCciRrokxglZn-omAY5CnCe4KdrnjFOT5YUZE7G_Pg44XgCXaarLQf4hl80oPEf6-jJ5Iy6wPRx7G2e8qLxnh9cOdf-kRqgOS3F48Ucvw3ma5V6KGMwQqWFeV31XtZ8l5cVI-I3NzBS7qltpUVgz2Ju021eyc7IlqgzR98qKONl27DuEES0aK0WE97jnsyO27Yp88Wa2RiBrEocM89QZI1seJiGDizHRUP4UZxw9zsXww46wy0P6f9grnYp7t8LkyDDk8eoI4KX6SNMNVcyVS9IWjlq8EzqZEKIA",
};

{
    my $jwe =
        "eyJhbGciOiJSU0EtT0FFUCIsImtpZCI6InNhbXdpc2UuZ2FtZ2VlQGhvYmJpdG9uLmV4YW1wbGUiLCJlbmMiOiJBMjU2R0NNIn0".
        ".rT99rwrBTbTI7IJM8fU3Eli7226HEB7IchCxNuh7lCiud48LxeolRdtFF4nzQibeYOl5S_PJsAXZwSXtDePz9hk-BbtsTBqC2UsPOdwjC9NhNupNNu9uHIVftDyucvI6hvALeZ6OGnhNV4v1zx2k7O1D89mAzfw-_kT3tkuorpDU-CpBENfIHX1Q58-Aad3FzMuo3Fn9buEP2yXakLXYa15BUXQsupM4A1GD4_H4Bd7V3u9h8Gkg8BpxKdUV9ScfJQTcYm6eJEBz3aSwIaK4T3-dwWpuBOhROQXBosJzS1asnuHtVMt2pKIIfux5BC6huIvmY7kzV7W7aIUrpYm_3H4zYvyMeq5pGqFmW2k8zpO878TRlZx7pZfPYDSXZyS0CfKKkMozT_qiCwZTSz4duYnt8hS4Z9sGthXn9uDqd6wycMagnQfOTs_lycTWmY-aqWVDKhjYNRf03NiwRtb5BE-tOdFwCASQj3uuAgPGrO2AWBe38UjQb0lvXn1SpyvYZ3WFc7WOJYaTa7A8DRn6MC6T-xDmMuxC0G7S2rscw5lQQU06MvZTlFOt0UvfuKBa03cxA_nIBIhLMjY2kOTxQMmpDPTr6Cbo8aKaOnx6ASE5Jx9paBpnNmOOKH35j_QlrQhDWUN6A2Gg8iFayJ69xDEdHAVCGRzN3woEI2ozDRs".
        ".-nBoKLH0YkLZPSI9".
        ".o4k2cnGN8rSSw3IDo1YuySkqeS_t2m1GXklSgqBdpACm6UJuJowOHC5ytjqYgRL-I-soPlwqMUf4UgRWWeaOGNw6vGW-xyM01lTYxrXfVzIIaRdhYtEMRBvBWbEwP7ua1DRfvaOjgZv6Ifa3brcAM64d8p5lhhNcizPersuhw5f-pGYzseva-TUaL8iWnctc-sSwy7SQmRkfhDjwbz0fz6kFovEgj64X1I5s7E6GLp5fnbYGLa1QUiML7Cc2GxgvI7zqWo0YIEc7aCflLG1-8BboVWFdZKLK9vNoycrYHumwzKluLWEbSVmaPpOslY2n525DxDfWaVFUfKQxMF56vn4B9QMpWAbnypNimbM8zVOw".
        ".UCGiqJxhBI3IFVdPalHHvA";

    my ($header, $payload) = decode_jwt(token=>$jwe, key=>$jwk_rsa_samwise, decode_header=>1, decode_payload=>0);
    is($header->{alg}, "RSA-OAEP",  "§5.2 header alg");
    is($header->{enc}, "A256GCM",   "§5.2 header enc");
    is($payload, $rfc7520_plaintext, "§5.2 plaintext recovered");
}

#----------------------------------------------------------------------
# §5.3 PBES2-HS512+A256KW + A128CBC-HS256 — decode-only
#----------------------------------------------------------------------
{
    my $password = "entrap_o\x{2013}peter_long\x{2013}credit_tun";
    utf8::encode($password);

    my $jwe =
        "eyJhbGciOiJQQkVTMi1IUzUxMitBMjU2S1ciLCJwMnMiOiI4UTFTemluYXNSM3hjaFl6NlpaY0hBIiwicDJjIjo4MTkyLCJjdHkiOiJqd2stc2V0K2pzb24iLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0".
        ".d3qNhUWfqheyPp4H8sjOWsDYajoej4c5Je6rlUtFPWdgtURtmeDV1g".
        ".VBiCzVHNoLiR3F4V82uoTQ".
        ".23i-Tb1AV4n0WKVSSgcQrdg6GRqsUKxjruHXYsTHAJLZ2nsnGIX86vMXqIi6IRsfywCRFzLxEcZBRnTvG3nhzPk0GDD7FMyXhUHpDjEYCNA_XOmzg8yZR9oyjo6lTF6si4q9FZ2EhzgFQCLO_6h5EVg3vR75_hkBsnuoqoM3dwejXBtIodN84PeqMb6asmas_dpSsz7H10fC5ni9xIz424givB1YLldF6exVmL93R3fOoOJbmk2GBQZL_SEGllv2cQsBgeprARsaQ7Bq99tT80coH8ItBjgV08AtzXFFsx9qKvC982KLKdPQMTlVJKkqtV4Ru5LEVpBZXBnZrtViSOgyg6AiuwaS-rCrcD_ePOGSuxvgtrokAKYPqmXUeRdjFJwafkYEkiuDCV9vWGAi1DH2xTafhJwcmywIyzi4BqRpmdn_N-zl5tuJYyuvKhjKv6ihbsV_k1hJGPGAxJ6wUpmwC4PTQ2izEm0TuSE8oMKdTw8V3kobXZ77ulMwDs4p".
        ".0HlwodAhOCILG5SQ2LQ9dg";

    my ($header, $payload) = decode_jwt(token=>$jwe, key=>$password,
                                        decode_header=>1, decode_payload=>0);
    is($header->{alg}, "PBES2-HS512+A256KW", "§5.3 header alg");
    is($header->{enc}, "A128CBC-HS256",      "§5.3 header enc");
    is($header->{p2c}, 8192,                 "§5.3 PBES2 iteration count");
    is($header->{cty}, "jwk-set+json",       "§5.3 cty");
    like($payload, qr/"keys"\s*:/,           "§5.3 plaintext is a JWK Set");
}

#----------------------------------------------------------------------
# §5.4 ECDH-ES+A128KW + A128GCM — decode-only (random ephemeral)
#----------------------------------------------------------------------
my $jwk_ec_p384 = {
    kty => "EC",
    kid => "peregrin.took\@tuckborough.example",
    use => "enc",
    crv => "P-384",
    x => "YU4rRUzdmVqmRtWOs2OpDE_T5fsNIodcG8G5FWPrTPMyxpzsSOGaQLpe2FpxBmu2",
    y => "A8-yxCHxkfBz3hKZfI1jUYMjUhsEveZ9THuwFjH2sCNdtksRJU7D5-SkgaFL1ETP",
    d => "iTx2pk7wW-GqJkHcEkFQb2EFyYcO7RugmaW3mRrQVAOUiPommT0IdnYK2xDlZh-j",
};

{
    my $jwe =
        "eyJhbGciOiJFQ0RILUVTK0ExMjhLVyIsImtpZCI6InBlcmVncmluLnRvb2tAdHVja2Jvcm91Z2guZXhhbXBsZSIsImVwayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMzg0IiwieCI6InVCbzRrSFB3Nmtiang1bDB4b3dyZF9vWXpCbWF6LUdLRlp1NHhBRkZrYllpV2d1dEVLNml1RURzUTZ3TmROZzMiLCJ5Ijoic3AzcDVTR2haVkMyZmFYdW1JLWU5SlUyTW84S3BvWXJGRHI1eVBOVnRXNFBnRXdaT3lRVEEtSmRhWTh0YjdFMCJ9LCJlbmMiOiJBMTI4R0NNIn0".
        ".0DJjBXri_kBcC46IkU5_Jk9BqaQeHdv2".
        ".mH-G2zVqgztUtnW_".
        ".tkZuOO9h95OgHJmkkrfLBisku8rGf6nzVxhRM3sVOhXgz5NJ76oID7lpnAi_cPWJRCjSpAaUZ5dOR3Spy7QuEkmKx8-3RCMhSYMzsXaEwDdXta9Mn5B7cCBoJKB0IgEnj_qfo1hIi-uEkUpOZ8aLTZGHfpl05jMwbKkTe2yK3mjF6SBAsgicQDVCkcY9BLluzx1RmC3ORXaM0JaHPB93YcdSDGgpgBWMVrNU1ErkjcMqMoT_wtCex3w03XdLkjXIuEr2hWgeP-nkUZTPU9EoGSPj6fAS-bSz87RCPrxZdj_iVyC6QWcqAu07WNhjzJEPc4jVntRJ6K53NgPQ5p99l3Z408OUqj4ioYezbS6vTPlQ".
        ".WuGzxmcreYjpHGJoa17EBg";

    my ($header, $payload) = decode_jwt(token=>$jwe, key=>$jwk_ec_p384,
                                        decode_header=>1, decode_payload=>0);
    is($header->{alg}, "ECDH-ES+A128KW", "§5.4 header alg");
    is($header->{enc}, "A128GCM",        "§5.4 header enc");
    is($header->{epk}{crv}, "P-384",     "§5.4 epk uses P-384");
    is($payload, $rfc7520_plaintext,     "§5.4 plaintext recovered");
}

#----------------------------------------------------------------------
# §5.8 A128KW + A128GCM — decode (deterministic key wrap, but encode
# can't pin the IV; verify-only suffices)
#----------------------------------------------------------------------
my $jwk_a128kw = {
    kty => "oct",
    kid => "81b20965-8332-43d9-a468-82160ad91ac8",
    use => "enc",
    alg => "A128KW",
    k   => "GZy6sIZ6wl9NJOKB-jnmVQ",
};

{
    my $jwe =
        "eyJhbGciOiJBMTI4S1ciLCJraWQiOiI4MWIyMDk2NS04MzMyLTQzZDktYTQ2OC04MjE2MGFkOTFhYzgiLCJlbmMiOiJBMTI4R0NNIn0".
        ".CBI6oDw8MydIx1IBntf_lQcw2MmJKIQx".
        ".Qx0pmsDa8KnJc9Jo".
        ".AwliP-KmWgsZ37BvzCefNen6VTbRK3QMA4TkvRkH0tP1bTdhtFJgJxeVmJkLD61A1hnWGetdg11c9ADsnWgL56NyxwSYjU1ZEHcGkd3EkU0vjHi9gTlb90qSYFfeF0LwkcTtjbYKCsiNJQkcIp1yeM03OmuiYSoYJVSpf7ej6zaYcMv3WwdxDFl8REwOhNImk2Xld2JXq6BR53TSFkyT7PwVLuq-1GwtGHlQeg7gDT6xW0JqHDPn_H-puQsmthc9Zg0ojmJfqqFvETUxLAF-KjcBTS5dNy6egwkYtOt8EIHK-oEsKYtZRaa8Z7MOZ7UGxGIMvEmxrGCPeJa14slv2-gaqK0kEThkaSqdYw0FkQZF".
        ".ER7MWJZ1FBI_NKvn7Zb1Lw";

    my ($header, $payload) = decode_jwt(token=>$jwe, key=>$jwk_a128kw,
                                        decode_header=>1, decode_payload=>0);
    is($header->{alg}, "A128KW",  "§5.8 header alg");
    is($header->{enc}, "A128GCM", "§5.8 header enc");
    is($payload, $rfc7520_plaintext, "§5.8 plaintext recovered");
}

#----------------------------------------------------------------------
# §5.9 A128KW + A128GCM with DEFLATE compression — decode (zip=DEF)
#----------------------------------------------------------------------
{
    my $jwe =
        "eyJhbGciOiJBMTI4S1ciLCJraWQiOiI4MWIyMDk2NS04MzMyLTQzZDktYTQ2OC04MjE2MGFkOTFhYzgiLCJlbmMiOiJBMTI4R0NNIiwiemlwIjoiREVGIn0".
        ".5vUT2WOtQxKWcekM_IzVQwkGgzlFDwPi".
        ".p9pUq6XHY0jfEZIl".
        ".HbDtOsdai1oYziSx25KEeTxmwnh8L8jKMFNc1k3zmMI6VB8hry57tDZ61jXyezSPt0fdLVfe6Jf5y5-JaCap_JQBcb5opbmT60uWGml8blyiMQmOn9J--XhhlYg0m-BHaqfDO5iTOWxPxFMUedx7WCy8mxgDHj0aBMG6152PsM-w5E_o2B3jDbrYBKhpYA7qi3AyijnCJ7BP9rr3U8kxExCpG3mK420TjOw".
        ".VILuUwuIxaLVmh5X-T7kmA";

    my ($header, $payload) = decode_jwt(token=>$jwe, key=>$jwk_a128kw,
                                        decode_header=>1, decode_payload=>0);
    is($header->{alg}, "A128KW",  "§5.9 header alg");
    is($header->{enc}, "A128GCM", "§5.9 header enc");
    is($header->{zip}, "DEF",     "§5.9 zip header");
    is($payload, $rfc7520_plaintext, "§5.9 compressed plaintext recovered");
}

done_testing;
