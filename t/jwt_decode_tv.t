use strict;
use warnings;
use Test::More;

use Crypt::JWT qw(decode_jwt);
use Crypt::Misc qw(encode_b64u);

my $key = "a0a2abd8-6162-41c3-83d6-1cf559b46afc";

my $aes128Key = join '', map { chr($_) } (194,164,235,6,138,248,171,239,24,216,11,22,137,199,215,133);
my $aes192Key = join '', map { chr($_) } (139, 156, 136, 148, 17, 147, 27, 233, 145, 80, 115, 197, 223, 11, 100, 221, 5, 50, 155, 226, 136, 222, 216, 14);
my $aes256Key = join '', map { chr($_) } (164,60,194,0,161,189,41,38,130,89,141,164,45,170,159,209,69,137,243,216,191,131,47,250,32,107,231,117,37,158,225,234);
my $aes384Key = join '', map { chr($_) } (185, 30, 233, 199, 32, 98, 209, 3, 114, 250, 30, 124, 207, 173, 227, 152, 243, 202, 238, 165, 227, 199, 202, 230, 218, 185, 216, 113, 13, 53, 40, 100, 100, 20, 59, 67, 88, 97, 191, 3, 161, 37, 147, 223, 149, 237, 190, 156);
my $aes512Key = join '', map { chr($_) } (238, 71, 183, 66, 57, 207, 194, 93, 82, 80, 80, 152, 92, 242, 84, 206, 194, 46, 67, 43, 231, 118, 208, 168, 156, 212, 33, 105, 27, 45, 60, 160, 232, 63, 61, 235, 68, 171, 206, 35, 152, 11, 142, 121, 174, 165, 140, 11, 172, 212, 13, 101, 13, 190, 82, 244, 109, 113, 70, 150, 251, 82, 215, 226);

my $Ecc256Public_PEM = <<'EOF';
t/jwt_decode_tv.t ...... 46/? -----BEGIN PUBLIC KEY-----
MIIBMzCB7AYHKoZIzj0CATCB4AIBATAsBgcqhkjOPQEBAiEA/////wAAAAEAAAAA
AAAAAAAAAAD///////////////8wRAQg/////wAAAAEAAAAAAAAAAAAAAAD/////
//////////wEIFrGNdiqOpPns+u9VXaYhrxlHQawzFOw9jvOPD4n0mBLBEEEaxfR
8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpZP40Li/hp/m47n60p8D54WK84z
V2sxXs7LtkBoN79R9QIhAP////8AAAAA//////////+85vqtpxeehPO5ysL8YyVR
AgEBA0IABARyHd86A7+qQ4DlIfKynZaFGdGLpkU3GlQwqaVD6GIJg3QIDhaWEksY
tZ9OWjNHn9a6+i/P9o5/NrdISP0VWDU=
-----END PUBLIC KEY-----
EOF

my $Ecc256Public = {
  kty => "EC",
  crv => "P-256",
  x => encode_b64u(join '', map { chr($_) } (4, 114, 29, 223, 58, 3, 191, 170, 67, 128, 229, 33, 242, 178, 157, 150, 133, 25, 209, 139, 166, 69, 55, 26, 84, 48, 169, 165, 67, 232, 98, 9)),
  y => encode_b64u(join '', map { chr($_) } (131, 116, 8, 14, 22, 150, 18, 75, 24, 181, 159, 78, 90, 51, 71, 159, 214, 186, 250, 47, 207, 246, 142, 127, 54, 183, 72, 72, 253, 21, 88, 53)),
};
my $Ecc256Private = {
  kty => "EC",
  crv => "P-256",
  x => encode_b64u(join '', map { chr($_) } (4, 114, 29, 223, 58, 3, 191, 170, 67, 128, 229, 33, 242, 178, 157, 150, 133, 25, 209, 139, 166, 69, 55, 26, 84, 48, 169, 165, 67, 232, 98, 9)),
  y => encode_b64u(join '', map { chr($_) } (131, 116, 8, 14, 22, 150, 18, 75, 24, 181, 159, 78, 90, 51, 71, 159, 214, 186, 250, 47, 207, 246, 142, 127, 54, 183, 72, 72, 253, 21, 88, 53)),
  d => encode_b64u(join '', map { chr($_) } (42, 148, 231, 48, 225, 196, 166, 201, 23, 190, 229, 199, 20, 39, 226, 70, 209, 148, 29, 70, 125, 14, 174, 66, 9, 198, 80, 251, 95, 107, 98, 206)),
};
my $Ecc384Public = {
  kty => "EC",
  crv => "P-384",
  x => encode_b64u(join '', map { chr($_) } (70, 151, 220, 179, 62, 0, 79, 232, 114, 64, 58, 75, 91, 209, 232, 128, 7, 137, 151, 42, 13, 148, 15, 133, 93, 215, 7, 3, 136, 124, 14, 101, 242, 207, 192, 69, 212, 145, 88, 59, 222, 33, 127, 46, 30, 218, 175, 79)),
  y => encode_b64u(join '', map { chr($_) } (189, 202, 196, 30, 153, 53, 22, 122, 171, 4, 188, 42, 71, 2, 9, 193, 191, 17, 111, 180, 78, 6, 110, 153, 240, 147, 203, 45, 152, 236, 181, 156, 232, 223, 227, 148, 68, 148, 221, 176, 57, 149, 44, 203, 83, 85, 75, 55)),
};
my $Ecc384Private = {
  kty => "EC",
  crv => "P-384",
  x => encode_b64u(join '', map { chr($_) } (70, 151, 220, 179, 62, 0, 79, 232, 114, 64, 58, 75, 91, 209, 232, 128, 7, 137, 151, 42, 13, 148, 15, 133, 93, 215, 7, 3, 136, 124, 14, 101, 242, 207, 192, 69, 212, 145, 88, 59, 222, 33, 127, 46, 30, 218, 175, 79)),
  y => encode_b64u(join '', map { chr($_) } (189, 202, 196, 30, 153, 53, 22, 122, 171, 4, 188, 42, 71, 2, 9, 193, 191, 17, 111, 180, 78, 6, 110, 153, 240, 147, 203, 45, 152, 236, 181, 156, 232, 223, 227, 148, 68, 148, 221, 176, 57, 149, 44, 203, 83, 85, 75, 55)),
  d => encode_b64u(join '', map { chr($_) } (137, 199, 183, 105, 188, 90, 128, 82, 116, 47, 161, 100, 221, 97, 208, 64, 173, 247, 9, 42, 186, 189, 181, 110, 24, 225, 254, 136, 75, 156, 242, 209, 94, 218, 58, 14, 33, 190, 15, 82, 141, 238, 207, 214, 159, 140, 247, 139)),
};
my $Ecc512Public = {
  kty => "EC",
  crv => "P-521",
  x => encode_b64u(join '', map { chr($_) } (0, 248, 73, 203, 53, 184, 34, 69, 111, 217, 230, 255, 108, 212, 241, 229, 95, 239, 93, 131, 100, 37, 86, 152, 87, 98, 170, 43, 25, 35, 80, 137, 62, 112, 197, 113, 138, 116, 114, 55, 165, 128, 8, 139, 148, 237, 109, 121, 40, 205, 3, 61, 127, 28, 195, 58, 43, 228, 224, 228, 82, 224, 219, 148, 204, 96)),
  y => encode_b64u(join '', map { chr($_) } (0, 60, 71, 97, 112, 106, 35, 121, 80, 182, 20, 167, 143, 8, 246, 108, 234, 160, 193, 10, 3, 148, 45, 11, 58, 177, 190, 172, 26, 178, 188, 240, 91, 25, 67, 79, 64, 241, 203, 65, 223, 218, 12, 227, 82, 178, 66, 160, 19, 194, 217, 172, 61, 250, 23, 78, 218, 130, 160, 105, 216, 208, 235, 124, 46, 32)),
};
my $Ecc512Private = {
  kty => "EC",
  crv => "P-521",
  x => encode_b64u(join '', map { chr($_) } (0, 248, 73, 203, 53, 184, 34, 69, 111, 217, 230, 255, 108, 212, 241, 229, 95, 239, 93, 131, 100, 37, 86, 152, 87, 98, 170, 43, 25, 35, 80, 137, 62, 112, 197, 113, 138, 116, 114, 55, 165, 128, 8, 139, 148, 237, 109, 121, 40, 205, 3, 61, 127, 28, 195, 58, 43, 228, 224, 228, 82, 224, 219, 148, 204, 96)),
  y => encode_b64u(join '', map { chr($_) } (0, 60, 71, 97, 112, 106, 35, 121, 80, 182, 20, 167, 143, 8, 246, 108, 234, 160, 193, 10, 3, 148, 45, 11, 58, 177, 190, 172, 26, 178, 188, 240, 91, 25, 67, 79, 64, 241, 203, 65, 223, 218, 12, 227, 82, 178, 66, 160, 19, 194, 217, 172, 61, 250, 23, 78, 218, 130, 160, 105, 216, 208, 235, 124, 46, 32)),
  d => encode_b64u(join '', map { chr($_) } (0, 222, 129, 9, 133, 207, 123, 116, 176, 83, 95, 169, 29, 121, 160, 137, 22, 21, 176, 59, 203, 129, 62, 111, 19, 78, 14, 174, 20, 211, 56, 160, 83, 42, 74, 219, 208, 39, 231, 33, 84, 114, 71, 106, 109, 161, 116, 243, 166, 146, 252, 231, 137, 228, 99, 149, 152, 123, 201, 157, 155, 131, 181, 106, 179, 112)),
};

my $rsaPub = <<'EOF';
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqFZv0pea/jn5Mo4qEUmS
tuhlulso8n1inXbEotd/zTrQp9K0RK0hf7t0K4BjKVhaiqIam4tVVQvkmYeBeYr1
MmnO/0N97dMBz/7fmvyv0hgHaBdQ5mR5u3LTlHo8tjRE7+GzZmGs6jMcyj7HbXob
DPQJZpqNy6JjliDVXxW8nWJDetxGBlqmTj1E1fr2RCsZLreDOPSDIedG1upz9Rra
ShsIDzeefOcKibcAaKeeVI3rkAU8/mOauLSXv37hlk0h6sStJb3qZQXyOUkVkjXI
khvNu/ve0v7LiLT4G/OxYGzpOQcCnimKdojzNP6GtVDaMPh+QkSJE32UCos9R3wI
2QIDAQAB
-----END PUBLIC KEY-----
EOF

my $rsaPriv = <<'EOF';
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCoVm/Sl5r+Ofky
jioRSZK26GW6WyjyfWKddsSi13/NOtCn0rRErSF/u3QrgGMpWFqKohqbi1VVC+SZ
h4F5ivUyac7/Q33t0wHP/t+a/K/SGAdoF1DmZHm7ctOUejy2NETv4bNmYazqMxzK
PsdtehsM9Almmo3LomOWINVfFbydYkN63EYGWqZOPUTV+vZEKxkut4M49IMh50bW
6nP1GtpKGwgPN5585wqJtwBop55UjeuQBTz+Y5q4tJe/fuGWTSHqxK0lveplBfI5
SRWSNciSG827+97S/suItPgb87FgbOk5BwKeKYp2iPM0/oa1UNow+H5CRIkTfZQK
iz1HfAjZAgMBAAECggEBAJSYcG9KSpQdor8gxTurYWo6LQpazAN58SIkpCFG71a/
k06BbYWt+oMhesOnumDV0F7OB4TEctf2/p0UA5PBuP3+bq3f6vqTp+buCn5qjd18
PpWA93XYvahdDS3k1VDVRQEnj9BRamz2H3TcA/i8r8I4bU/4IDDgMN5mL1OXAX8+
vt7j3YZdwsEBQk4MDrnfwQPadjDzFBxvNsDCv7DTtSNE2KY5u058DQcIimzH/ouQ
ip7qIYKGKxA2C3jIN399ngZY5QhTWGqArU/pq9WXtDkyTQ9OL23y6LVfgQSrpSKW
zjknlaShu4CcWR5r+4p+zxOf1s2sShVaB1t8Eer/xs0CgYEA0qaOkT174vRG3E/6
7gU3lgOgoT6L3pVHuu7wfrIEoxycPa5/mZVG54SgvQUofGUYEGjR0lavUAjClw9t
OzcODHX8RAxkuDntAFntBxgRM+IzAy8QzeRl/cbhgVjBTAhBcxg+3VySv5GdxFyr
QaIo8Oy/PPI1L4EFKZHmicBd3tsCgYEAzJPqCDKqaJH9TAGfzt6b4aNt9fpirEcd
pAF1bCedFfQmUZM0LG3rMtOAIhjEXgADt5GB8ZNK3BQl8BJyMmKs57oKmbVcODER
CtPqjECXXsxH+az9nzxatPvcb7imFW8OlWslwr4IIRKdEjzEYs4syQJz7k2ktqOp
YI5/UfYnw1sCgYApNaZMaZ/T3YADV646ZFDkix8gjFDmoYOf4WCxGHhpxI4YTwvt
atOtNTgQ4nJyK4DSrP7nTEgNuzj+PmlbHUElVOueEGKf280utWj2a1HqOYVLSSjb
bqQ5SnARUuC11COhtYuO2K5oxb78jDiApY2m3FnpPWUEPxRYdo+IQVbb4wKBgCZ9
JajJL3phDRDBtXlMNHOtNcDzjKDw+Eik5Zylj05UEumCEmzReVCkrhS8KCWvRwPA
Ynw6w/jH6aNTNRz5p6IpRFlK38DKqnQpDpW4iUISmPAGdekBh+dJA14ZlVWvAUVn
VUFgU1M1l0uZFzGnrJFc3sbU4Mpj3DgIVzfqYezFAoGBALEQD4oCaZfEv77H9c4S
U6xzPe8UcLgdukek5vifLCkT2+6eccTZZjgQRb1plsXbaPHQRJTZcnUmWp9+98gS
8c1vm2YFafgdkSk9Qd1oU2Fv1aOQy4VovOFzJ3CcR+2r7cbRfcpLGnintHtp9yek
02p+d5g4OChfFNDhDtnIqjvY
-----END PRIVATE KEY-----
EOF

### Plaintext
{
  my $token = "eyJhbGciOiJub25lIn0.eyJoZWxsbyI6ICJ3b3JsZCJ9.";
  my $json = eval { decode_jwt(token=>$token, decode_payload=>0, key=>$key, allow_none=>1) } or warn $@;
  my $expected = '{"hello": "world"}';
  is($json, $expected, 'Plaintext');
  is($json, $expected, 'Plaintext');
}
### HS256
{
  my $token = "eyJhbGciOiJIUzI1NiIsImN0eSI6InRleHRcL3BsYWluIn0.eyJoZWxsbyI6ICJ3b3JsZCJ9.chIoYWrQMA8XL5nFz6oLDJyvgHk2KA4BrFGrKymjC8E";
  my $json = eval { decode_jwt(token=>$token, decode_payload=>0, key=>$key) } or warn $@;
  my $expected = '{"hello": "world"}';
  is($json, $expected, 'HS256');
}
### HS384
{
  my $token = "eyJhbGciOiJIUzM4NCIsImN0eSI6InRleHRcL3BsYWluIn0.eyJoZWxsbyI6ICJ3b3JsZCJ9.McDgk0h4mRdhPM0yDUtFG_omRUwwqVS2_679Yeivj-a7l6bHs_ahWiKl1KoX_hU_";
  my $json = eval { decode_jwt(token=>$token, decode_payload=>0, key=>$key) } or warn $@;
  my $expected = '{"hello": "world"}';
  is($json, $expected, 'HS384');
}
### HS512
{
  my $token = "eyJhbGciOiJIUzUxMiIsImN0eSI6InRleHRcL3BsYWluIn0.eyJoZWxsbyI6ICJ3b3JsZCJ9.9KirTNe8IRwFCBLjO8BZuXf3U2ZVagdsg7F9ZsvMwG3FuqY9W0vqwjzPOjLqPN-GkjPm6C3qWPnINhpr5bEDJQ";
  my $json = eval { decode_jwt(token=>$token, decode_payload=>0, key=>$key) } or warn $@;
  my $expected = '{"hello": "world"}';
  is($json, $expected, 'HS512');
}
### RS256
{
  my $token = "eyJhbGciOiJSUzI1NiIsImN0eSI6InRleHRcL3BsYWluIn0.eyJoZWxsbyI6ICJ3b3JsZCJ9.NL_dfVpZkhNn4bZpCyMq5TmnXbT4yiyecuB6Kax_lV8Yq2dG8wLfea-T4UKnrjLOwxlbwLwuKzffWcnWv3LVAWfeBxhGTa0c4_0TX_wzLnsgLuU6s9M2GBkAIuSMHY6UTFumJlEeRBeiqZNrlqvmAzQ9ppJHfWWkW4stcgLCLMAZbTqvRSppC1SMxnvPXnZSWn_Fk_q3oGKWw6Nf0-j-aOhK0S0Lcr0PV69ZE4xBYM9PUS1MpMe2zF5J3Tqlc1VBcJ94fjDj1F7y8twmMT3H1PI9RozO-21R0SiXZ_a93fxhE_l_dj5drgOek7jUN9uBDjkXUwJPAyp9YPehrjyLdw";
  my $json = eval { decode_jwt(token=>$token, decode_payload=>0, key=>\$rsaPub) } or warn $@;
  my $expected = '{"hello": "world"}';
  is($json, $expected, 'RS256');
}
### RS384
{
  my $token = "eyJhbGciOiJSUzM4NCIsImN0eSI6InRleHRcL3BsYWluIn0.eyJoZWxsbyI6ICJ3b3JsZCJ9.cOPca7YEOxnXVdIi7cJqfgRMmDFPCrZG1M7WCJ23U57rAWvCTaQgEFdLjs7aeRAPY5Su_MVWV7YixcawKKYOGVG9eMmjdGiKHVoRcfjwVywGIb-nuD1IBzGesrQe7mFQrcWKtYD9FurjCY1WuI2FzGPp5YhW5Zf4TwmBvOKz6j2D1vOFfGsogzAyH4lqaMpkHpUAXddQxzu8rmFhZ54Rg4T-jMGVlsdrlAAlGA-fdRZ-V3F2PJjHQYUcyS6n1ULcy6ljEOgT5fY-_8DDLLpI8jAIdIhcHUAynuwvvnDr9bJ4xIy4olFRqcUQIHbcb5-WDeWul_cSGzTJdxDZsnDuvg";
  my $json = eval { decode_jwt(token=>$token, decode_payload=>0, key=>\$rsaPub) } or warn $@;
  my $expected = '{"hello": "world"}';
  is($json, $expected, 'RS384');
}
### RS512
{
  my $token = "eyJhbGciOiJSUzUxMiIsImN0eSI6InRleHRcL3BsYWluIn0.eyJoZWxsbyI6ICJ3b3JsZCJ9.KP_mwCVRIxcF6ErdrzNcXZQDFGcL-Hlyocc4tIl3tJfzSfc7rz7qOLPjHpZ6UFH1ncd5TlpRc1B_pgvY-l0BNtx_s7n_QA55X4c1oeD8csrIoXQ6A6mtvdVGoSlGu2JnP6N2aqlDmlcefKqjl_Z-8nwDMGTMkDNhHKfHlIb2_Dliwxeq8LmNMREEdvNH2XVp_ffxBjiaKv2Eqbwc6I17241GCEmjDCvnagSgjX_5uu-da2H7TK2gtPJYUo8r9nzC7uzZJ5SB8suZH0COSofsP-9wvH0FESO40evCyEBylqg3bh9M9dIzeq8_bdTiC5kG93Fal44OEY8_Zm88wB_VjQ";
  my $json = eval { decode_jwt(token=>$token, decode_payload=>0, key=>\$rsaPub) } or warn $@;
  my $expected = '{"hello": "world"}';
  is($json, $expected, 'RS512');
}
### ES256
{
  my $token = "eyJhbGciOiJFUzI1NiIsImN0eSI6InRleHRcL3BsYWluIn0.eyJoZWxsbyI6ICJ3b3JsZCJ9.EVnmDMlz-oi05AQzts-R3aqWvaBlwVZddWkmaaHyMx5Phb2NSLgyI0kccpgjjAyo1S5KCB3LIMPfmxCX_obMKA";
  my $json = eval { decode_jwt(token=>$token, decode_payload=>0, key=>$Ecc256Public) } or warn $@;
  my $expected = '{"hello": "world"}';
  is($json, $expected, 'ES256');
}
### ES384
{
  my $token = "eyJhbGciOiJFUzM4NCIsImN0eSI6InRleHRcL3BsYWluIn0.eyJoZWxsbyI6ICJ3b3JsZCJ9.jVTHd9T0fIQDJLNvAq3LPpgj_npXtWb64FfEK8Sm65Nr9q2goUWASrM9jv3h-71UrP4cBpM3on3yN--o6B-Tl6bscVUfpm1swPp94f7XD9VYLEjGMjQOaozr13iBZJCY";
  my $json = eval { decode_jwt(token=>$token, decode_payload=>0, key=>$Ecc384Public) } or warn $@;
  my $expected = '{"hello": "world"}';
  is($json, $expected, 'ES384');
}
### ES512
{
  my $token = "eyJhbGciOiJFUzUxMiIsImN0eSI6InRleHRcL3BsYWluIn0.eyJoZWxsbyI6ICJ3b3JsZCJ9.AHxJYFeTVpZmrfZsltpQKkkplmbkycQKFOFucD7hE4Sm3rCswUDi8hlSCfeYByugySYLFzogTQGk79PHP6vdl39sAUc9k2bhnv-NxRmJsN8ZxEx09qYKbc14qiNWZztLweQg0U-pU0DQ66rwJ0HikzSqgmyD1bJ6RxitJwceYLAovv0v";
  my $json = eval { decode_jwt(token=>$token, decode_payload=>0, key=>$Ecc512Public) } or warn $@;
  my $expected = '{"hello": "world"}';
  is($json, $expected, 'ES512');
}
### PS256
{
  my $token = "eyJhbGciOiJQUzI1NiIsImN0eSI6InRleHRcL3BsYWluIn0.eyJoZWxsbyI6ICJ3b3JsZCJ9.S9xuR-IGfXEj5qsHcMtK-jcj1lezvVstw1AISp8dEQVRNgwOMZhUQnSCx9i1CA-pMucxR-lv4e7zd6h3cYCfMnyv7iuxraxNiNAgREhOT-bkBCZMNgb5t15xEtDSJ3MuBlK3YBtXyVcDDIdKH_Bwj-u363y6LuvZ8FEOGmIK5WSFi18Xjg-ihhvH1C6UzH1G82wrRbX6DyJKqrUnHAg8yzUJVP1AdgjWRt5BKpuYbXSib-MKZZkaE4q_hCb-j25xCzn8Ez8a7PO7p0fDGvZuOk_yzSfvXSavg7iE0GLuUTNv3nQ_xW-rfbrpYeyXNtstoK3JPFpdtORTyH1iIh7VVA";
  my $json = eval { decode_jwt(token=>$token, decode_payload=>0, key=>\$rsaPub) } or warn $@;
  my $expected = '{"hello": "world"}';
  is($json, $expected, 'PS256');
}
### PS384
{
  my $token = "eyJhbGciOiJQUzM4NCIsImN0eSI6InRleHRcL3BsYWluIn0.eyJoZWxsbyI6ICJ3b3JsZCJ9.EKqVLw6nLGNt1h7KNFZbzkKhf788VBYCfnigYc0dBZBa64MrfbIFHtJuFgIGkCVSDYH-qs-i4w9ke6mD8mxTZFniMgzFXXaCFIrv6QZeMbKh6VYtSEPp7l0B1zMZiQw6egZbZ6a8VBkCRipuZggSlUTg5tHMMTj_jNVxxlY4uUwXlz7vakpbqgXe19pCDJrzEoXE0cNKV13eRCNA1tXOHx0dFL7Jm9NUq7blvhJ8iTw1jMFzK8bV6g6L7GclHBMoJ3MIvRp71m6idir-QeW1KCUfVtBs3HRn3a822LW02vGqopSkaGdRzQZOI28136AMeW4679UXE852srA2v3mWHQ";
  my $json = eval { decode_jwt(token=>$token, decode_payload=>0, key=>\$rsaPub) } or warn $@;
  my $expected = '{"hello": "world"}';
  is($json, $expected, 'PS384');
}
### PS512
{
  my $token = "eyJhbGciOiJQUzUxMiIsImN0eSI6InRleHRcL3BsYWluIn0.eyJoZWxsbyI6ICJ3b3JsZCJ9.IvbnmxhKvM70C0n0grkF807wOQLyPOBwJOee-p7JHCQcSstNeml3Owdyw9C3HGHzOdK9db51yAkjJ2TCojxqHW4OR5Apna8tvafYgD2femn1V3GdkGj6ZvYdV3q4ldnmahVeO36vHYy5P0zFcEGU1_j3S3DwGmhw2ktZ4p5fLZ2up2qwhzlOjbtsQpWywHj7cLdeA32MLId9MTAPVGUHIZHw_W0xwjJRS6TgxD9vPQQnP70MY-q_2pVAhfRCM_pauPYO1XH5ldizrTvVr27q_-Uqtw-wV-UDUnyWYQUDDiMTpLBoX1EEXmsbvUGx0OH3yWEaNINoCsepgZvTKbiEQQ";
  my $json = eval { decode_jwt(token=>$token, decode_payload=>0, key=>\$rsaPub) } or warn $@;
  my $expected = '{"hello": "world"}';
  is($json, $expected, 'PS512');
}
### RSA_OAEP_A128CBC_HS256
{
  my $token = "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkExMjhDQkMtSFMyNTYifQ.dgIoddBRTBLi8b6fwjaIU5uUP_J-6jL5AtIvoNZDwN0JSmsXkm9SIFz7kQfwavBz_PPG6h0yId55YVFnCqrB5qCIbifmBQPEcB5acKCybHuoHhEBCnQpqxVtHLXZ0dUyd6Xs5h9ymgbbZMjpAoCUK7si90m4O5BCSdedZNQvdXWQW599CRftFVVe_mZOcgABuNIDMfIwyxmi2DVR5c2bSA0ji2Sy27SE_X0lCVHqrAwI-8Rlz1WTWLI6bhRh2jsUPK-6958E4fsXOWsTOp9fW97eW85InZPniv8B5HSG_D0NALhu5AIMsNt-ENeR0sefcphZGUzfyFoxK7EMpY7gAQ.jNw5xfYCvwHvviSuUFYpfw.0_Rvs5cA_QKSVMGbPr5ntFrd_BQhTql-hB9fzLhndAy9vLeHBLtv-bXeZatw4QJIufnpsSnXmRYjKqvWVCp-x-AKpPWzkaj6fvsQ8Mns1kWw5XZr-8SJrbT72LOnRBcTd4qjOYXEJZad8uIwQHDFkkmpm4d7FQ6PhW0-1gOS8FGuYjUupYDQX2ia-4jzqWisv2bE-mKn65q5wy_dT0w04rF-Mk_USyOG5d09kne3ZBv42stpS_xyDS3euVtPuxhQT5TzfPpBkG3CNwwm_HvTTg.E2opVK9nQXPXJbDKb06FBg";
  my $json = eval { decode_jwt(token=>$token, decode_payload=>0, key=>\$rsaPriv) } or warn $@;
  my $expected = '{"exp":1391196668,"sub":"alice","nbf":1391196068,"aud":["https:\/\/app-one.com","https:\/\/app-two.com"],"iss":"https:\/\/openid.net","jti":"03ac026e-55aa-4475-a806-f09e83048922","iat":1391196068}';
  is($json, $expected, 'RSA_OAEP_A128CBC_HS256');
}
### RSA_OAEP_A128CBC_HS256_Compressed
{
  my $token = "eyJhbGciOiJSU0EtT0FFUCIsInppcCI6IkRFRiIsImVuYyI6IkExMjhDQkMtSFMyNTYifQ.nXSS9jDwE0dXkcGI7UquZBhn2nsB2P8u-YSWEuTAgEeuV54qNU4SlE76bToI1z4LUuABHmZOv9S24xkF45b7Mrap_Fu4JXH8euXrQgKQb9o_HL5FvE8m4zk5Ow13MKGPvHvWKOaNEBFriwYIfPi6QBYrpuqn0BaANc_aMyInV0Fn7e8EAgVmvoagmy7Hxic2sPUeLEIlRCDSGa82mpiGusjo7VMJxymkhnMdKufpGPh4wod7pvgb-jDWasUHpsUkHqSKZxlrDQxcy1-Pu1G37TAnImlWPa9NU7500IXc-W07IJccXhR3qhA5QaIyBbmHY0j1Dn3808oSFOYSF85A9w.uwbZhK-8iNzcjvKRb1a2Ig.jxj1GfH9Ndu1y0b7NRz_yfmjrvX2rXQczyK9ZJGWTWfeNPGR_PZdJmddiam15Qtz7R-pzIeyR4_qQoMzOISkq6fDEvEWVZdHnnTUHQzCoGX1dZoG9jXEwfAk2G1vXYT2vynEQZ72xk0V_OBtKhpIAUEFsXwCUeLAAgjFNY4OGWZl_Kmv9RTGhnePZfVbrbwg.WuV64jlV03OZm99qHMP9wQ";
  my $json = eval { decode_jwt(token=>$token, decode_payload=>0, key=>\$rsaPriv) } or warn $@;
  my $expected = '{"exp":1392963710,"sub":"alice","nbf":1392963110,"aud":["https:\/\/app-one.com","https:\/\/app-two.com"],"iss":"https:\/\/openid.net","jti":"9fa7a38a-28fd-421c-825c-8fab3bbf3fb4","iat":1392963110}';
  is($json, $expected, 'RSA_OAEP_A128CBC_HS256_Compressed');
}
### RSA_OAEP_A256CBC_HS512
{
  my $token = "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZDQkMtSFM1MTIifQ.gCLatpLEIHdwqXGNQ6pI2azteXmksiGvHZoXaFmGjvN6T71ky5Ov8DHmXyaFdxWVPxiPAf6RDpJlokSR34e1W9ey0m9xWELJ_hH_bEoH4s7-wI74edS06i35let0YvCubl3eIemuQNkaJEqoEaHx8sLZ-SsoRxi7tRAIABl4f_THC8CDLw7SXrVcp_b6xRtB9oSI2_y_vSAZXOTZPJBw_t4jwZLnsOUbBXXGKAGIpG0rrL8qMt1KwRW_79qQie2U1kDclD7EVMQ-ji5upayxaXOMLkPqfISgvyGKyaLs-8e_aRyVKbMpkCZNWaLnSAA6aJHynNsnuM8O4iEN-wRXmw.r2SOQ2k_YqZRpoIB6wSbqA.DeYxdBzfRiiJeAm8H58SO8NJCa4yg3beciqZRGiAqQDrFYdp9q1RHuNrd0UY7DfzBChW5Gp37FqMA3eRpZ_ERbMiYMSgBtqJgUTKWyXGYItThpg92-1Nm7LN_Sp16UOSBHMJmbXeS30NMEfudgk3qUzE2Qmec7msk3X3ylbgn8EIwSIeVpGcEi6OWFCX1lTIRm1bqV2JDxY3gbWUB2H2YVtgL7AaioMttBM8Mm5plDY1pTHXZzgSBrTCtqtmysCothzGkRRzuHDzeaWYbznkVg.Hpk41zlPhLX4UQvb_lbCLZ0zAhOI8A0dA-V31KFGs6A";
  my $json = eval { decode_jwt(token=>$token, decode_payload=>0, key=>\$rsaPriv) } or warn $@;
  my $expected = '{"exp":1391196668,"sub":"alice","nbf":1391196068,"aud":["https:\/\/app-one.com","https:\/\/app-two.com"],"iss":"https:\/\/openid.net","jti":"19539b79-e5cf-4f99-a66e-00a980e1b0a9","iat":1391196068}';
  is($json, $expected, 'RSA_OAEP_A256CBC_HS512');
}
### RSA_OAEP_A192CBC_HS384
{
  my $token = "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkExOTJDQkMtSFMzODQifQ.BZ8MgMgby05auOw-Gb4ii-fgcRWAlCHd6pMZNFafle6BAT1accRGUsMGRzJRETUFFqoy3rzfdSdFcqgc7lmUQUXrVei6XCRei5VZJo1YlzIPN9rEig3sSJ99hg1mrXh3ezFX_JczTn7xEaRRzdatnkSvWBMMmbMWVjqlpkXSOr7P7x2Ctf-GQwXOKEVUrRFwe2D0qXC0ynWKrm7mkV-tlRHJf5NRdWLT5Tmxka8OJZ0W1MyJKNEemEMt1dThcnedPMBjb8y0IwPZ8Aiam87fWdqk20MDknNyxRoC_epBFZFaWFpZ383mKI2Ev-EqO2lCnFOkSvwcNmhnlOPXHJ40qQ.1aAvdZ8g580VUE55RqRBVw.IkoVJF73DSzi-ebiErrCAtpWPepbFZS6DX0S9Ka85aRfgmLQRQxBucxm48MixkRJ5QYCPGmtXRPyiQQE9zT1aA5Js6BoV8U2JK44HWga4cNkyUUr0Wpu0uz6GEBU620i9DmJasTb4iA3iTMboCpdrCTlzhJrYhSYc09Jo0WJRM83LjorxRjpUmLGqR4SgV1WYFKaben4iSqOVPThzQc7HEGrkbycZRNKj-BAkll7qRtN_1e5k83W9Wlf5taAWwSXMF2VL6XqR0bZXpPcpLi_vw.kePqK6KpRWohWEpSg8vfeCd0PQAqBmjW";
  my $json = eval { decode_jwt(token=>$token, decode_payload=>0, key=>\$rsaPriv) } or warn $@;
  my $expected = '{"exp":1391196668,"sub":"alice","nbf":1391196068,"aud":["https:\/\/app-one.com","https:\/\/app-two.com"],"iss":"https:\/\/openid.net","jti":"59f54c91-5224-4484-9c3a-e57b87b6f212","iat":1391196068}';
  is($json, $expected, 'RSA_OAEP_A192CBC_HS384');
}
### RSA_OAEP_256_A128CBC_HS256
{
  my $token = "eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.bje66yTjMUpyGzbt3QvPNOmCmUPowgEmoBHXw-pByhST2VBSs0_67JKDymKW0VpmQC5Qb7ZLC6nNG8YW5pxTZDOeTQLodhAvzoNAsrx4M2R_N58ZVqBPLKTq7FKi1NNd8oJ80dwWbOJ13dkLH68SlhOK5bhqKFgtbzalnglL2kq8Fki1GkN4YyFnS8-chC-mlrS5bJrPSHUF7oAsG_flL_e9-KzYqYTQgGCB3GYSo_pgalsp2rUO3Oz2Pfe9IEJNlX7R9wOT1nTT0UUg-lSzQ2oOaXNvNyaPgEa76mJ1nk7ZQq7ZNix1m8snjk0Vizd8EOFCSRyOGcp4mHMn7-s00Q.tMFMCdFNQXbhEnwE6mP_XQ.E_O_ZBtJ8P0FvhKOV_W98oxIySDgdd0up0c8FAjo-3OVZ_6XMEQYFDKVG_Zc3zkbaz1Z2hmc7D7M28RbhRdya3yJN6Hcv1KuXeZ9ociI7o739Ni_bPvv8xCmGxlASS5AF7N4JR7XjrWL-SYKGNL1p0XNTlPo3B3qYqgAY6jFNvlcjWupim-pQbWKNqPbO2KmSCtUzyKE5oHjsomH0hnQs0_DXv3cgQ_ZFLFZBc1tC4AjQ8QZex5kWg5BmlJDM5F_jD7QRhb7B1u4Mi563-AKVA.0lraw3IXMM6wPqUZVYA8pg";
  my $json = eval { decode_jwt(token=>$token, decode_payload=>0, key=>\$rsaPriv) } or warn $@;
  my $expected = '{"exp":1392553211,"sub":"alice","nbf":1392552611,"aud":["https:\/\/app-one.com","https:\/\/app-two.com"],"iss":"https:\/\/openid.net","jti":"586dd129-a29f-49c8-9de7-454af1155e27","iat":1392552611}';
  is($json, $expected, 'RSA_OAEP_256_A128CBC_HS256');
}
### RSA_OAEP_256_A192CBC_HS384
{
  my $token = "eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMTkyQ0JDLUhTMzg0In0.COuKvozBVi2vkEPpFdx0HTMpU9tmpP1lLngbmGn8RVphY-vjhVaduv8D_Ay_1j8LuMz4tgP98xWtbJkTyhxY1kBwXe0CgqFUOSJ1mTEPRkKSXpdFR7rT1Pv68qug2yKaXT_qcviyBerIcUVFbXBmtiYAosYO4kaPSOE1IvLadFOrMkxdZv6QiiCROzWgJNCCMgNQZGRoPhqLe3wrcxi86DhNO7Bpqq_yeNVyHdU_qObMuMVZIWWEQIDhiU4nE8WGJLG_NtKElc_nQwbmclL_YYgTiHsIAKWZCdj0nwfLe5mwJQN4r7pjakiUVzCbNNgI1-iBH1vJD5VCPxgWldzfYA.7cDs4wzbNDt1Kq40Q5ae4w.u1bR6ChVd90QkFIp3H6IkOCIMwf5aIKsQOvqgFangRLrDjctl5qO5jTHr1o1GwBQvAkRmaGSE7fRIwWB_l-Ayx2c2WDFOkVXFSR_D23GrWaLMLbugPItQd2Mny6H4QOzO3O0EK_Qm7frqwKQI3og72SB8DUqzEaKsrz7HR2z_qMa2CEEApxai_R6NIlAdMUbYvOfZx262MWFGrITBDmma-Mnqiz9WJUv2wexfwjROaaS4wXfkGy5B6ltESifpZZk5NerExR3GA6yX7cFqJc4pQ.FKcbLyB9eP1UXmxyliTu1_GQrnS-JtAB";
  my $json = eval { decode_jwt(token=>$token, decode_payload=>0, key=>\$rsaPriv) } or warn $@;
  my $expected = '{"exp":1392553211,"sub":"alice","nbf":1392552611,"aud":["https:\/\/app-one.com","https:\/\/app-two.com"],"iss":"https:\/\/openid.net","jti":"586dd129-a29f-49c8-9de7-454af1155e27","iat":1392552611}';
  is($json, $expected, 'RSA_OAEP_256_A192CBC_HS384');
}
### RSA_OAEP_256_A256CBC_HS512
{
  my $token = "eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0.Pt1q6MNdaiVWhMnY7r6DVpkYQmzyIjhb0cj10LowP_FgMu1dOQVuNwhK14MO1ki1y1Pvxouct9wwmb5gE7jNJBy6vU-FrrY62WNr_hKL3Cq2030LlJwauv1XQrEE-GCw1srxOAsw6LNT14v4f0qjeW46mIHNX4CZMEO9ntwojWsHTNsh4Qk6SU1QlS3WbbVl7gjjfqTP54j2ZwZM38s7Cs4pSAChP04UbW6Uhrm65JSi0lyg25OBXIxMEt1z9WY8lnjuh3iL_WttnFn9lf5fUuuR2N70HwANz2mxH3CxjO0ygXJtV-FhFzz3HqI2-ELrve4Igj_2f2_S6OrRTWRucA.er5K9Gk0wp3wF_sq7ib7BQ.L80B9FGSjUbEblpJ6tuiaq6NAsW89YQGD0awxtE-irKN65PT8nndBd0hlel8RRThXRF0kiYYor2GpgvVVaoOzSQcwL-aDgNO7BeRsaOL5ku2NlyT1erbg_8jEVG5BFMM0-jCb4kD0jBKWYCGoB7qs_QQxZ394H5GPwG68vlizKEa8PoaNIM0at5oFT7EHPdmGmwQyQCHR43e6uN4k28PWNxjN9Ndo5lvlYnxnAyDGVDu8lCjozaA_ZTrEPS-UBb6lOEW39CXdwVk1MgvyQfswQ.yuDMf_77Wr9Er3FG1_0FwHXJTOVQPjzBwGoKEg81mQo";
  my $json = eval { decode_jwt(token=>$token, decode_payload=>0, key=>\$rsaPriv) } or warn $@;
  my $expected = '{"exp":1392553211,"sub":"alice","nbf":1392552611,"aud":["https:\/\/app-one.com","https:\/\/app-two.com"],"iss":"https:\/\/openid.net","jti":"586dd129-a29f-49c8-9de7-454af1155e27","iat":1392552611}';
  is($json, $expected, 'RSA_OAEP_256_A256CBC_HS512');
}
### RSA_1_5_A128CBC_HS256
{
  my $token = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.bx_4TL7gh14IeM3EClP3iVfY9pbT81pflXd1lEZOVPJR6PaewRFXWmiJcaqH9fcU9IjGGQ19BS-UPtpErenL5kw7KORFgIBm4hObCYxLoAadMy8A-qQeOWyjnxbE0mbQIdoFI4nGK5qWTEQUWZCMwosvyeHLqEZDzr9CNLAAFTujvsZJJ7NLTkA0cTUzz64b57uSvMTaOK6j7Ap9ZaAgF2uaqBdZ1NzqofLeU4XYCG8pWc5Qd-Ri_1KsksjaDHk12ZU4vKIJWJ-puEnpXBLoHuko92BnN8_LXx4sfDdK7wRiXk0LU_iwoT5zb1ro7KaM0hcfidWoz95vfhPhACIsXQ.YcVAPLJ061gvPpVB-zMm4A.PveUBLejLzMjA4tViHTRXbYnxMHFu8W2ECwj9b6sF2u2azi0TbxxMhs65j-t3qm-8EKBJM7LKIlkAtQ1XBeZl4zuTeMFxsQ0VShQfwlN2r8dPFgUzb4f_MzBuFFYfP5hBs-jugm89l2ZTj8oAOOSpAlC7uTmwha3dNaDOzlJniqAl_729q5EvSjaYXMtaET9wSTNSDfMUVFcMERbB50VOhc134JDUVPTuriD0rd4tQm8Do8obFKtFeZ5l3jT73-f1tPZwZ6CmFVxUMh6gSdY5A.tR8bNx9WErquthpWZBeMaw";
  my $json = eval { decode_jwt(token=>$token, decode_payload=>0, key=>\$rsaPriv) } or warn $@;
  my $expected = '{"exp":1391196668,"sub":"alice","nbf":1391196068,"aud":["https:\/\/app-one.com","https:\/\/app-two.com"],"iss":"https:\/\/openid.net","jti":"3814fff3-db66-45d9-a29a-d2cc2407bdcf","iat":1391196068}';
  is($json, $expected, 'RSA_1_5_A128CBC_HS256');
}
### RSA_1_5_A192CBC_HS384
{
  my $token = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTkyQ0JDLUhTMzg0In0.ApUpt1SGilnXuqvFSHdTV0K9QKSf0P6wEEOTrAqWMwyEOLlyb6VR8o6fdd4wXMTkkL5Bp9BH1x0oibTrVwVa50rxbPDlRJQe0yvBm0w02nkzl3Tt4fE3sGjEXGgI8w8ZxSVAN0EkaXLqzsG1rQ631ptzqyNzg9BWfy53cHhuzh9w00ZOXZtNc7GFBQ1LRvhK1EyLS2_my8KD091KwsjvXC-_J0eOp2W8NkycP_jCIrUzAOSwz--NZyRXt9V2o609HGItKajHplbE1PJVShaXO84MdJl3X6ef8ZXz7mCP3dRlsYfK-tlnFVeEKwC1Oy_zdFsdiY4j41Mj3usvG2j7xQ.GY4Em2zkSGMZsDLNr9pnDw.GZYJSpeQHmOtx34dk4WxEPCnt7l8R5oLKd3IyoMYbjZrWRtomyTufOKfiOVT-nY9ad0Vs5w5Imr2ysy6DnkAFoOnINV_Bzq1hQU4oFfUd_9bFfHZvGuW9H-NTUVBLDhok6NHosSBaY8xLdwHL_GiztRsX_rU4I88bmWBIFiu8T_IRskrX_kSKQ_iGpIJiDy5psIxY4il9dPihLJhcI_JqysW0pIMHB9ij_JSrCnVPs4ngXBHrQoxeDv3HiHFTGXziZ8k79LZ9LywanzC0-ZC5Q.1cmUwl7MnFl__CS9Y__a8t5aVyI9IKOY";
  my $json = eval { decode_jwt(token=>$token, decode_payload=>0, key=>\$rsaPriv) } or warn $@;
  my $expected = '{"exp":1391196668,"sub":"alice","nbf":1391196068,"aud":["https:\/\/app-one.com","https:\/\/app-two.com"],"iss":"https:\/\/openid.net","jti":"c9d44ff8-ff1e-4490-8454-941e45766152","iat":1391196068}';
  is($json, $expected, 'RSA_1_5_A192CBC_HS384');
}
### RSA_1_5_A256CBC_HS512
{
  my $token = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0.GVXwkd5rfqffr4ue26IGHXuiV6r-rQa9OQ4B1LtodsTpWfraOLyhyHYseEKpXV4aSMWWN0q2HS0myj73BuGsDMP-xiIM04QxWD7dbP2OticXzktcHHhMFUx0OK_IOmc21qshTqbb0yKWizMnCuVosQqw2tg_up2sgjqIyiwzpgvC5_l9ddxnTBV334LF_nXTnL22vqrUO92rH_3YmoJ6khHUYVSXhd0fXTKqwm9liULW43prDWkex0N8a8MfgdaFPq0rGw4gRA8HvS7aFn3xCeKAO9Q_q-g32DCDwbfqYhvGZCbS49ObwfPD-fKaFS94VFSMb_Cy-WalZwrIz-aWkQ.zh6hViRORvk4b-2io1vUSA.Us26-89QEOWb85TsOZJpH6QB5_GR3wZo49rR38X1daG_kmyfzIUQQ12wBwmxFwHluNvqStVj4YUIvPgC4oZEh1L-r3Tm81Q2PctdMrwl9fRDR6uH1Hqfx-K25vEhlk_A60s060wezUa5eSttjwEHGTY0FpoQvyOmdfmnOdtW_LLyRWoRzmGocD_N4z6BxK-cVTbbTvAYVbWaZNW_eEMLL4qAnKNAhXJzAtUTqJQIn0Fbh3EE3j827hKrtcRbrwqr1BmoOtaQdYUO4VZKIJ7SNw.Zkt6yXlSu9BdknCr32uyu7uH6HVwGFOV48xc4Z7wF9Y";
  my $json = eval { decode_jwt(token=>$token, decode_payload=>0, key=>\$rsaPriv) } or warn $@;
  my $expected = '{"exp":1391196668,"sub":"alice","nbf":1391196068,"aud":["https:\/\/app-one.com","https:\/\/app-two.com"],"iss":"https:\/\/openid.net","jti":"7efcdbc6-b2b5-4480-985d-bdf741b376bb","iat":1391196068}';
  is($json, $expected, 'RSA_1_5_A256CBC_HS512');
}
### RSA_OAEP_A128GCM
{
  my $token = "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkExMjhHQ00ifQ.Izae78a1L2Z0ai_aYbvVbWjiZwz3DTlD27c4Jh44SZAz7T_w7GHiWGuxa4CYPq4Ul_9i5qpdUK1WJOTxlL8C-TXbWzxgwhs-DdmkRBmI5JWozc6RIYz2ddYBIPDTpOSbg_nwVzCUkqId6PwATSPiYjLY0ZwsSung1JGuSKU5WHzdCLh8cXKFdSNo4PA6xxuIFqDWNeshSvbUhK-xPL_ySPSLGtMfzUocPi--SDnc867a92WZpnCwLbpAqlGcj1u-nrpXjlTdECbZbPH5mggnIU8Xrzi6OIRTf2RPOxk2nYcW-KkzsERSUUmoIStaTnnq6MzRLKdF-eOolVaPEB94tQ.dBju23LfGAmbhKQl.l-hxA-_Jj9X-Kbq6W_7XNSxeeDaZc_YFoHRIBclWn2ebd_1qbZ3Td8aPsxBwe4Mc0KP7JdTnDXH53ajtdo2CQaPIaxNh-ffZkUZCi7o-tM_SRyt1MkUnoxQ5ib4i5lzJNEJyklf7lHQhjUhUa2FKTS1KJvLo0uChw5Gb-Y_7S_BUfOzTDCFQR4XFbpd7ngCWww4skpHEulhBhSr66RGog4wwac_ucfSTKeKxZw0UhHBIZFIAju4zcoN8Abh23JHh0VETiA.FFFvIyv5vq_cE1xIPYn6Wg";
  my $json = eval { decode_jwt(token=>$token, decode_payload=>0, key=>\$rsaPriv) } or warn $@;
  my $expected = '{"exp":1391705293,"sub":"alice","nbf":1391704693,"aud":["https:\/\/app-one.com","https:\/\/app-two.com"],"iss":"https:\/\/openid.net","jti":"2f3b5379-a851-4202-ac9a-85baae41459e","iat":1391704693}';
  is($json, $expected, 'RSA_OAEP_A128GCM');
}
### RSA_OAEP_A192GCM
{
  my $token = "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkExOTJHQ00ifQ.QUBq_S563qAz9KA1oQDPLQ8Upfaf5XWeLLo6w_BpZRPUUshnSsf5GYmxeakuVCGywv2mKR7pEd0EzzA4vL1l3tc8woftrA_jDSU9lQp_Icuwqg9pzBswv7ofKegK7ch7KhOuWGaeFz6mdoUESHhdEPmhVZwz7ryrKWj_TlL-Cr7UG8MpHWV_bvohdtLReTSqfbUbcT_iSY4Nid7RHca__0dmSWgEM2Sydmesv8KJzuoyI6xgGLCaw_p46GuZ4XhM88scV7doV7f3mEv7AYTDMJz4Q5_8lz_gIDDyloTx3-tC9a9KlDVSC3XkPppfQwwjSt-yWhh9SZmsPIpC_K6ubA.pUr3CK_0cTGIODJx.TBD3RZ2nJGNSns_iOOvruxC2Dr-4SsClKIwPXIt8zIjKtKub8o1lFqaRwlBfyciPNMiCqqocWR8zwyNNDFBIAUYJMBW6SPuFzJv8mrjlV_aRsfFmYjpw9U3-n0u-noYHT5U1FXy6feUY907AIqbcEKkHF0TfjEXLfuKVvJHNjaqS84-UFZqmxN0U2szRCo8-k6omS32pRDwTGgl1Co9yXSBUAXtGoi02uqOKpAFbtxfD8_6P41N7-HK86l94m5x1uNCViQ.9xj6WjYwh4OCUr-GKl7_yQ";
  my $json = eval { decode_jwt(token=>$token, decode_payload=>0, key=>\$rsaPriv) } or warn $@;
  my $expected = '{"exp":1391710436,"sub":"alice","nbf":1391709836,"aud":["https:\/\/app-one.com","https:\/\/app-two.com"],"iss":"https:\/\/openid.net","jti":"6b646d08-2871-4e0d-bfa8-48a9e1bd6de5","iat":1391709836}';
  is($json, $expected, 'RSA_OAEP_A192GCM');
}
### RSA_OAEP_A256GCM
{
  my $token = "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.M7PuAabTBMnrudthuZNYWfwkXlv1KVxsSYjpaRmuStqybglofWHK37wWWcF5JMYmJfRjswXlGf-iHjw2aSfGpmTJBdUYYbchMtn2TKnjU03piFaqWN3D9384nq_4NJeRkwwe7uYD3iGDxeemJpJLjqpXj5cXgK5Xd93TtJ-QB9hIpXtyDqOlLdoooMWKG8Y9cIBdbwCza57KzOm1S5and_3E4IgijvtRlqENzeLesH3jT3P2310nDEn60j7eqHCeXWR8lUKMZudVCY7f9lkGpotKQeJpxDG1Sd2EG_GiOK5DwpR_1CimkE3c4y1qUoFM10Pjzf7IqZJL1HBAMHcXxQ.9a8lpyZcMoPi2qJb.TKWSdvz395ZfzsjDV6r9mhMdU5XZ14pCcna5EkoA1wmolDAth9qqYAPJErbfZfUAptbUFDitLlsnnnIIhej-N_42XIQnu14Wz0G-sizAn78jKjf145ckDYt63qaX4SxBW6-SQqSCYV4Nz6t0DUBMLK9UcYsVQ2e3Ur5YvxcnTeFM9FqgUiEz9IiNlsJXwZ1HN-LTp0412YCELxoxUu3Bg7R_GWHx2iUliBnRN4WcvRhYMApI_o3qAoK4StTgCQJu-laPdg.Rztnz6rBQ2aSlDHKORI5AA";
  my $json = eval { decode_jwt(token=>$token, decode_payload=>0, key=>\$rsaPriv) } or warn $@;
  my $expected = '{"exp":1391710647,"sub":"alice","nbf":1391710047,"aud":["https:\/\/app-one.com","https:\/\/app-two.com"],"iss":"https:\/\/openid.net","jti":"0b0f3b1b-8f36-4ee2-b463-54263b4af8b7","iat":1391710047}';
  is($json, $expected, 'RSA_OAEP_A256GCM');
}
### RSA1_5_A128GCM
{
  my $token = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4R0NNIn0.FojyyzygtFOyNBjzqTRfr9HVHPrvtqbVUt9sXSuU59ZhLlzk7FrirryFnFGtj8YC9lx-IX156Ro9rBaJTCU_dfERd05DhPMffT40rdcDiLxfCLOY0E2PfsMyGQPhI6YtNBtf_sQjXWEBC59zH_VoswFAUstkvXY9eVVecoM-W9HFlIxwUXMVpEPtS96xZX5LMksDgJ9sYDTNa6EQOA0hfzw07fD_FFJShcueqJuoJjILYbad-AHbpnLTV4oTbFTYjskRxpEYQr9plFZsT4_xKiCU89slT9EFhmuaiUI_-NGdX-kNDyQZj2Vtid4LSOVv5kGxyygThuQb6wjr1AGe1g.O92pf8iqwlBIQmXA.YdGjkN7lzeKYIv743XlPRYTd3x4VA0xwa5WVoGf1hiHlhQuXGEg4Jv3elk4JoFJzgVuMMQMex8fpFFL3t5I4H9bH18pbrEo7wLXvGOsP971cuOOaXPxhX6qClkwx5qkWhcTbO_2AuJxzIaU9qBwtwWaxJm9axofAPYgYbdaMZkU4F5sFdaFY8IOe94wUA1Ocn_gxC_DYp9IEAyZut0j5RImmthPgiRO_0pK9OvusE_Xg3iGfdxu70x0KpoItuNwlEf0LUA.uP5jOGMxtDUiT6E3ubucBw";
  my $json = eval { decode_jwt(token=>$token, decode_payload=>0, key=>\$rsaPriv) } or warn $@;
  my $expected = '{"exp":1391711317,"sub":"alice","nbf":1391710717,"aud":["https:\/\/app-one.com","https:\/\/app-two.com"],"iss":"https:\/\/openid.net","jti":"cadf3d33-a109-4829-a869-94a4bfbb4cbf","iat":1391710717}';
  is($json, $expected, 'RSA1_5_A128GCM');
}
### RSA1_5_A192GCM
{
  my $token = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTkyR0NNIn0.f-g3EVuoVHRWRnhuQTa0s4V6kKWdCZrQadK27AcmjYNuBAQL26GpiZe1fBggGdREMjXejQjykDd0GGGzdk3avSLlfOuAHb6D5TJE6DB67v_Fjn29_ky-9L6fZmLUKlHOYbE5H2cnkUk9eI3mT0_VJLfhkh3uOAvs1h31NGBmVcQJOLoyH9fa6nTt1kddubsnkHLMfjS_fm4lKOBv2e1S4fosWYEVM9ylpfL-wSYJYrDtEsy_r9lTv19OmrcjtQoqoF9kZ9bMm7jOcZWiG00nw5Zbo2nze_y-bSngJcA7jIutf0zmFxa9GsIVvseQbqcLYZoiACMqEp0HgPg2xfBPmw.mzEicVwcsRKNKrHs.jW2bcx2pxSK2a8NNZSydArUd3JgRQl_dX5N8i5REBeR7WmtgL9aHXyrGqy9rl-iUb6LZMjMFG4tDqOetJjS48OUzMgvLZH3tui_oL8m9ZHWG-yl079uJZSIWU-icHuWzSjbc4ExPu1IXCcTnBGIjid5PM3HAfmWtVP5Pv0q6qeuvzMXvLG7YcZtuS5dTSu1pZTW7O5BEaxy9AvC0-xr0SlTdEEVCT_kZIprhIT7XiGnuMUztx83AxuO-FYXZeL5iXMW8hQ.H9qkfReSyqgVkiVt53fh-Q";
  my $json = eval { decode_jwt(token=>$token, decode_payload=>0, key=>\$rsaPriv) } or warn $@;
  my $expected = '{"exp":1391711482,"sub":"alice","nbf":1391710882,"aud":["https:\/\/app-one.com","https:\/\/app-two.com"],"iss":"https:\/\/openid.net","jti":"7488a8fc-345a-42c2-971e-a286c14fc5af","iat":1391710882}';
  is($json, $expected, 'RSA1_5_A192GCM');
}
### RSA1_5_A256GCM
{
  my $token = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMjU2R0NNIn0.arMHtbGJv2mi7COD9WTz_FzUPJ8Jq1qUTMc5C3IKGD7RNeV1oiv1AgCPiChTuu-UGA56iGJXbFAE7x2jSFK_foKvRvZxyCKz6Siy18seHoz1iw8gU2A_mMG7IEPVcA8MmbMVawFTXoMdLBeW9CsV_102wmZFeh2S74f80XogE63Nd3VjE3LaSbatnXQxIaD0Meq9ZqrKUFZS5SY-FyKqWrdjH82MZP8lrBLDTkTXx4bkfoZForimE1oIEykanpv-tnAlQNFlqRPJsGy-HtcEoHQ7E1Xkqxg9kULmF4TeqiyQ0HBfXXBbm3pQ43GUPmbFJW-l7W6vDAc9-41BCNChQw.kryfKm1U6NobSiyI.kMQXbCKGdeh_vqj6J7wQ1qP48q4VQv5zGZIJp0FgIlk0Lrv9XP4ExlgYlPb24mr1W43d2rY0OJ9fDgPnoTk_cQ6kpXL3nSBo82yBTBA_g6UyIJ4b1PIOpJv_RANA-b8TwQwGtg0eMr_5il4QQWfB_AxnvCe9CDyTkNo7befER3706xilqm6aHdryZx3Hk6C9hbrSe0xW96uor1Js2b-UWRcCJDFQK5Ux9IAHy2Utqsqv7qDq0Ai5pVQOMjyq3iKmUuOOEg.rqSGPBypVniu58fdHswm7g";
  my $json = eval { decode_jwt(token=>$token, decode_payload=>0, key=>\$rsaPriv) } or warn $@;
  my $expected = '{"exp":1391711482,"sub":"alice","nbf":1391710882,"aud":["https:\/\/app-one.com","https:\/\/app-two.com"],"iss":"https:\/\/openid.net","jti":"77a31aed-f546-4b1d-ba77-9455a2e0a3d5","iat":1391710882}';
  is($json, $expected, 'RSA1_5_A256GCM');
}
### RSA1_5_A256GCM_DEFLATE
{
  my $token = "eyJhbGciOiJSU0ExXzUiLCJ6aXAiOiJERUYiLCJlbmMiOiJBMjU2R0NNIn0.imMUAOkYe54TzNknmrUkWOtjgGlbSivDyFRbvebC1rT9ixxQOTN-bCGiLwyEoPLdkroEvvR1cf_abR_afZIfWsk6Om09aar9JQkA7KMNoTRBQnn7X7BX_agpZuhRzPo_gQDXA0fll10j9OdUTcXd7oSw6FVb4non2qyO2ZvwT1UANY3SbQchlQrXnQpjQluR1tkxWXo-5p3o9MQEIqyypOQyGKIIXJlBtcUkWz0PHHsqJ3OdZus7dbwajv5GpHmLfT8Q2aPZN5QX1zv4h2y8vD6RYn6evLCc7e7Gp1z7C5WOZXDA6hyYQiL3Y92zzxVVD5E7nt94WSktxjM-y65TQw.g3FCuDmLISjam69Q.PrMnFDnuYNkLvmR8QmmEu6NB9N6ecJy6gMSR1fYEkZLz2jMtxN-OTaudX901_SWCX_dDFgpmOPziQRJ1IYOiySZ3N0FFyWxemJgHjVOZaPpu5ZSTH7JYoH5CLBpD1H9VMX5vC5SUH7hWgLZ_NCgVs0eZt_3_AyUObVAInNNTH_pNjhdjV8xuCCE.rDEvIPtM1fNjpDvD62x2PA";
  my $json = eval { decode_jwt(token=>$token, decode_payload=>0, key=>\$rsaPriv) } or warn $@;
  my $expected = '{"exp":1392994388,"sub":"alice","nbf":1392993788,"aud":["https:\/\/app-one.com","https:\/\/app-two.com"],"iss":"https:\/\/openid.net","jti":"81b338eb-346e-4b04-a618-d3cbb2d64ec6","iat":1392993788}';
  is($json, $expected, 'RSA1_5_A256GCM_DEFLATE');
}
### DIR_A128GCM
{
  my $token = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4R0NNIn0..yVi-LdQQngN0C5WS.1McwSmhZzAtmmLp9y-OdnJwaJFo1nj_4ashmzl2LhubGf0Jl1OTEVJzsHZb7bkup7cGTkuxh6Vfv10ljHsjWf_URXoxP3stQqQeViVcuPV0y2Q_WHYzTNGZpmHGe-hM6gjDhyZyvu3yeXGFSvfPQmp9pWVOgDjI4RC0MQ83rzzn-rRdnZkznWjbmOPxwPrR72Qng0BISsEwbkPn4oO8-vlHkVmPpuDTaYzCT2ZR5K9JnIU8d8QdxEAGb7-s8GEJ1yqtd_w._umbK59DAKA3O89h15VoKQ";
  my $json = eval { decode_jwt(token=>$token, decode_payload=>0, key=>$aes128Key) } or warn $@;
  my $expected = '{"exp":1392548520,"sub":"alice","nbf":1392547920,"aud":["https:\/\/app-one.com","https:\/\/app-two.com"],"iss":"https:\/\/openid.net","jti":"0e659a67-1cd3-438b-8888-217e72951ec9","iat":1392547920}';
  is($json, $expected, 'DIR_A128GCM');
}
### DIR_A192GCM
{
  my $token = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTkyR0NNIn0..YW2WB0afVronbgSz.tfk1VADGjBnViYD7He5mbhxpbogoT1cmhKiDKzzoBV2AxfsgJ2Eq-vtEqPi9eY9H52FLLtht26rc5fPz9ZKOUH2hYeFdaRyKYXlpEnUR2cCT9_3TYcaFhpYBH4HCa59NruKlJHMBqM2ssWZLSEblFX9srUHFtu2OQz2ydMy1fr8ABDTdVYgaqyBoYRGykTkEsgayEyfAMz9u095N2J0JTCB5Q0IiXNdBzBSxZXG-i9f5HFEb6IliaTwFTNFnhDL66O4rsg._dh02z25W7HA6b1XiFVpUw";
  my $json = eval { decode_jwt(token=>$token, decode_payload=>0, key=>$aes192Key) } or warn $@;
  my $expected = '{"exp":1392552631,"sub":"alice","nbf":1392552031,"aud":["https:\/\/app-one.com","https:\/\/app-two.com"],"iss":"https:\/\/openid.net","jti":"a3fea096-2e96-4d8b-b7cd-070e08b533fb","iat":1392552031}';
  is($json, $expected, 'DIR_A192GCM');
}
### DIR_A256GCM
{
  my $token = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0..Fmz3PLVfv-ySl4IJ.LMZpXMDoBIll5yuEs81Bws2-iUUaBSpucJPL-GtDKXkPhFpJmES2T136Vd8xzvp-3JW-fvpRZtlhluqGHjywPctol71Zuz9uFQjuejIU4axA_XiAy-BadbRUm1-25FRT30WtrrxKltSkulmIS5N-Nsi_zmCz5xicB1ZnzneRXGaXY4B444_IHxGBIS_wdurPAN0OEGw4xIi2DAD1Ikc99a90L7rUZfbHNg_iTBr-OshZqDbR6C5KhmMgk5KqDJEN8Ik-Yw.Jbk8ZmO901fqECYVPKOAzg";
  my $json = eval { decode_jwt(token=>$token, decode_payload=>0, key=>$aes256Key) } or warn $@;
  my $expected = '{"exp":1392552841,"sub":"alice","nbf":1392552241,"aud":["https:\/\/app-one.com","https:\/\/app-two.com"],"iss":"https:\/\/openid.net","jti":"efdfc02f-945e-4e1f-85a6-9f240f6cf153","iat":1392552241}';
  is($json, $expected, 'DIR_A256GCM');
}
### DIR_A128CBC_HS256
{
  my $token = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0..3lClLoerWhxIc811QXDLbg.iFd5MNk2eWDlW3hbq7vTFLPJlC0Od_MSyWGakEn5kfYbbPk7BM_SxUMptwcvDnZ5uBKwwPAYOsHIm5IjZ79LKZul9ZnOtJONRvxWLeS9WZiX4CghOLZL7dLypKn-mB22xsmSUbtizMuNSdgJwUCxEmms7vYOpL0Che-0_YrOu3NmBCLBiZzdWVtSSvYw6Ltzbch4OAaX2ye_IIemJoU1VnrdW0y-AjPgnAUA-GY7CAKJ70leS1LyjTW8H_ecB4sDCkLpxNOUsWZs3DN0vxxSQw.bxrZkcOeBgFAo3t0585ZdQ";
  my $json = eval { decode_jwt(token=>$token, decode_payload=>0, key=>$aes256Key) } or warn $@;
  my $expected = '{"exp":1392553211,"sub":"alice","nbf":1392552611,"aud":["https:\/\/app-one.com","https:\/\/app-two.com"],"iss":"https:\/\/openid.net","jti":"586dd129-a29f-49c8-9de7-454af1155e27","iat":1392552611}';
  is($json, $expected, 'DIR_A128CBC_HS256');
}
### ECDH_ES_A128CBC_HS256
{
  my $token = "eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTEyOENCQy1IUzI1NiIsImVwayI6eyJrdHkiOiJFQyIsIngiOiItVk1LTG5NeW9IVHRGUlpGNnFXNndkRm5BN21KQkdiNzk4V3FVMFV3QVhZIiwieSI6ImhQQWNReTgzVS01Qjl1U21xbnNXcFZzbHVoZGJSZE1nbnZ0cGdmNVhXTjgiLCJjcnYiOiJQLTI1NiJ9fQ..UA3N2j-TbYKKD361AxlXUA.XxFur_nY1GauVp5W_KO2DEHfof5s7kUwvOgghiNNNmnB4Vxj5j8VRS8vMOb51nYy2wqmBb2gBf1IHDcKZdACkCOMqMIcpBvhyqbuKiZPLHiilwSgVV6ubIV88X0vK0C8ZPe5lEyRudbgFjdlTnf8TmsvuAsdtPn9dXwDjUR23bD2ocp8UGAV0lKqKzpAw528vTfD0gwMG8gt_op8yZAxqqLLljMuZdTnjofAfsW2Rq3Z6GyLUlxR51DAUlQKi6UpsKMJoXTrm1Jw8sXBHpsRqA.UHCYOtnqk4SfhAknCnymaQ";
  my $json = eval { decode_jwt(token=>$token, decode_payload=>0, key=>$Ecc256Private) } or warn $@;
  my $expected = '{"exp":1392553211,"sub":"alice","nbf":1392552611,"aud":["https:\/\/app-one.com","https:\/\/app-two.com"],"iss":"https:\/\/openid.net","jti":"586dd129-a29f-49c8-9de7-454af1155e27","iat":1392552611}';
  is($json, $expected, 'ECDH_ES_A128CBC_HS256');
}
### ECDH_ES_A128GCM
{
  my $token = "eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTEyOEdDTSIsImVwayI6eyJrdHkiOiJFQyIsIngiOiJPbDdqSWk4SDFpRTFrcnZRTmFQeGp5LXEtY3pQME40RVdPM1I3NTg0aEdVIiwieSI6Ik1kU2V1OVNudWtwOWxLZGU5clVuYmp4a3ozbV9kTWpqQXc5NFd3Q0xaa3MiLCJjcnYiOiJQLTI1NiJ9fQ..E4XwpWZ2kO-Vg0xb.lP5LWPlabtmzS-m2EPGhlPGgllLNhI5OF2nAbbV9tVvtCckKpt358IQNRk-W8-JNL9SsLdWmVUMplrw-GO-KA2qwxEeh_8-muYCw3qfdhVVhLnOF-kL4mW9a00Xls_6nIZponGrqpHCwRQM5aSr365kqTNpfOnXgJTKG2459nqv8n4oSfmwV2iRUBlXEgTO-1Tvrq9doDwZCCHj__JKvbuPfyRBp5T7d-QJio0XRF1TO4QY36GtKMXWR264lS7g-T1xxtA.vFevA9zsyOnNA5RZanKqHA";
  my $json = eval { decode_jwt(token=>$token, decode_payload=>0, key=>$Ecc256Private) } or warn $@;
  my $expected = '{"exp":1392553211,"sub":"alice","nbf":1392552611,"aud":["https:\/\/app-one.com","https:\/\/app-two.com"],"iss":"https:\/\/openid.net","jti":"586dd129-a29f-49c8-9de7-454af1155e27","iat":1392552611}';
  is($json, $expected, 'ECDH_ES_A128GCM');
}
### ECDH_ES_A192GCM
{
  my $token = "eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTE5MkdDTSIsImVwayI6eyJrdHkiOiJFQyIsIngiOiJQVHdUWWdjQ0s2aVBuNUQ4TmUwSGlERG16b0NpRWFpSnNIN0MycENFcHNjIiwieSI6IjdnVDJPVGstcTlFa2tqOE41OEd4LUo2X2NrcXRnWWVPMERyZ3E2SWFPWGMiLCJjcnYiOiJQLTI1NiJ9fQ..sK58aW_aYOIeXcd_.KCHYLUKgSpRSe01ACTS-C1dtc1vxSiqqw5GdWjTkdtdsrpG_GOLzDrPWv_W4C0GsI5yrfZNlsujAs6qCgeE9Ypk7Nh26pEAVFqYYHeGO8VIqB_KmA_Y00q6Ae0JrV9MhOx7Lk45iGZoVYHeTw8vXS_q8GIZMVPE8hiIwPZApCb11yAoupP6ZCCE7wDwGZUJebWagPssElcwe0bQDg-xhvDjCobGe-GxS-cSJD_pwATJDnwYnIkHhr8xQ5DG_A6hrKB1JJA.hYUguhKj7zVxpVAAO-mZ4Q";
  my $json = eval { decode_jwt(token=>$token, decode_payload=>0, key=>$Ecc256Private) } or warn $@;
  my $expected = '{"exp":1392553211,"sub":"alice","nbf":1392552611,"aud":["https:\/\/app-one.com","https:\/\/app-two.com"],"iss":"https:\/\/openid.net","jti":"586dd129-a29f-49c8-9de7-454af1155e27","iat":1392552611}';
  is($json, $expected, 'ECDH_ES_A192GCM');
}
### ECDH_ES_A256GCM
{
  my $token = "eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTI1NkdDTSIsImVwayI6eyJrdHkiOiJFQyIsIngiOiJtRXhiTWVyTW14X28zZkdtQ3RNNEx3UlBOc0RsRzRNREw1NXdqYzd3cEw4IiwieSI6IkMtLXZ1VlR2OFhYUzlxT1ptX1pZcU54WG4tYkRXRkxDZUwxTTZRS2pJYlkiLCJjcnYiOiJQLTI1NiJ9fQ..SmI8J0ZwK1CXwamA.VnsYpxxR9-XbS7FAPSngPNkCslTBca2otiYzZVGbDrM4fJueODgMkRSkEKXzxeYRf2zU_0cwY1sUvgU00lou2SKwcoSgT8kON0sdoxxwn-atxyUoxISd75NW_WQdaAG2WysWweYMyB5eu7XuRDUwQ4iKCLmmtD2fdQ5w3RcNOxMIC_zyr3NwrQO7zarIbdcDg0iCgc7Szflbc1EYMadtiEmU_YN5veXOvJtASEOyjRbX-U9HyQnF-Z78dTf_j_gAe-TwjQ.H10mHRYClUt8j2LulRKAog";
  my $json = eval { decode_jwt(token=>$token, decode_payload=>0, key=>$Ecc256Private) } or warn $@;
  my $expected = '{"exp":1392553211,"sub":"alice","nbf":1392552611,"aud":["https:\/\/app-one.com","https:\/\/app-two.com"],"iss":"https:\/\/openid.net","jti":"586dd129-a29f-49c8-9de7-454af1155e27","iat":1392552611}';
  is($json, $expected, 'ECDH_ES_A256GCM');
}
### ECDH_ES_A128KW_A128GCM
{
  my $token = "eyJhbGciOiJFQ0RILUVTK0ExMjhLVyIsImVuYyI6IkExMjhHQ00iLCJlcGsiOnsia3R5IjoiRUMiLCJ4IjoiNnlzVWZVd09vVWxENUpGZG9qUHFXeFd3ZkJ3b2ttWmpOVmxJRFFrcG1PMCIsInkiOiJKZVpia19QazIybWowVFUwcG5uQjNVaUwySzJJcVl6Tk0xVVRPZS1KY3dZIiwiY3J2IjoiUC0yNTYifX0.e1n3YTorJJ-H7eWby-pfGWzVx0aDScCT.VQLnlbAD3N1O-k-S.mJzcAMoxUMQxXIHFGcVjuEVKw70lC6rNbcGqverZBkycPQ2EDgZCiqMgJenHuecvG_YqShi50uZYVyYS4TTrGh1Bj4jP6iFZ8Ksww3hW_jYzKQbp9CdbmOL1f0f25RKwUq61AraXGoJ1Lrs8IM96tvTjKTGpDkNMJ8xN4kVcRcrM5fjTIx973XKo2_nbuCpn-BlAhB6wzYuw_EFsqis8-8cssPENLuGA-n-xX66akqdhycfh5RiqrTPYUnk5ss1Fo_LWWA.l0-CNccSNLTgVdGW1CZr9w";
  my $json = eval { decode_jwt(token=>$token, decode_payload=>0, key=>$Ecc256Private) } or warn $@;
  my $expected = '{"exp":1392553211,"sub":"alice","nbf":1392552611,"aud":["https:\/\/app-one.com","https:\/\/app-two.com"],"iss":"https:\/\/openid.net","jti":"586dd129-a29f-49c8-9de7-454af1155e27","iat":1392552611}';
  is($json, $expected, 'ECDH_ES_A128KW_A128GCM');
}
### ECDH_ES_A192KW_A192GCM
{
  my $token = "eyJhbGciOiJFQ0RILUVTK0ExOTJLVyIsImVuYyI6IkExOTJHQ00iLCJlcGsiOnsia3R5IjoiRUMiLCJ4IjoiWWExQlYxSVl4RW9oVWNJclhDQU9PektlMFBPTXVCUElmMmRSNmtNZVN0cyIsInkiOiJTVXVqY3NsMHZmaUpuMXVfNFk1OU1NSjV1RkdjVVpFQlRXUHU1NEFSZ0VFIiwiY3J2IjoiUC0yNTYifX0.wpPrUGVTDsthaBTuToj5D51O-bbSJCBwmDq7lK4l8dE.23LmX0dUuB4bmjx8.At6v2XSn05ew5N_mW2q4nIcHmn3unnuJkceT-cADSfHS5TGHq5_dytb8OZRDvAA_6U__MDWONdpNAAucG_2UljX8LOfRkfDIncg-KcN_8UOyTNuCSwg3wHtPfDuVR4VPgyKysxGU0L6yIvXs8as8GzLQ4vA4YbCbMjsefQQLWjJbTELON5ASVj9cwTSTydO1N0xXDWjKiPXaiwHiBAnEE-ESeTvhqc1yfS6lel1PMuoZc0teV6XX21lZfFuVJtnKWQIcTQ.AoCKtceXULOU0y74O5qJFA";
  my $json = eval { decode_jwt(token=>$token, decode_payload=>0, key=>$Ecc256Private) } or warn $@;
  my $expected = '{"exp":1392553211,"sub":"alice","nbf":1392552611,"aud":["https:\/\/app-one.com","https:\/\/app-two.com"],"iss":"https:\/\/openid.net","jti":"586dd129-a29f-49c8-9de7-454af1155e27","iat":1392552611}';
  is($json, $expected, 'ECDH_ES_A192KW_A192GCM');
}
### ECDH_ES_A256KW_A256GCM
{
  my $token = "eyJhbGciOiJFQ0RILUVTK0EyNTZLVyIsImVuYyI6IkEyNTZHQ00iLCJlcGsiOnsia3R5IjoiRUMiLCJ4IjoiQU5UZy1LOFlBVXVPazBtUW1aTERQVWlPcVZFUFBrLVBmNmtSdG42Y0IycyIsInkiOiJsSmk3UExFRGU2WndxSjQ2alpyLUZtUHp5c3dGa3BkSVU3WlUzNHQ4RURzIiwiY3J2IjoiUC0yNTYifX0.Iqp3w3xo12wCqyNV_8wNk3m2tHKpBmv66XARscHeLtZS-2FslAbfDQ.UClH3759Eeo3V8xi.Y4UQpFk-MF5Xkec035WVmMI7O_eXw5V2gF3Ov4CnnV2cac6pul598NytO_rFI-hff4dOLwz2jgD_H6nQ_fL70STi0Wrsar2s7F8TMvolcaOhOfIbzX4O0vTdrNENiM9ug7044M-lvsOX8rK3Q3usfxSfOa4g9I_7r6b6SRMbjGqz3mtp8slMZhPZraBAxsxU97qfutBNA8ohCPGHasu7INHQnE_Cf0bZtE8mSpijq4AK3FGp91ekpoowH4627l7fBnupVg.hdEFZ6RBabaq7Xzb1SOaCg";
  my $json = eval { decode_jwt(token=>$token, decode_payload=>0, key=>$Ecc256Private) } or warn $@;
  my $expected = '{"exp":1392553211,"sub":"alice","nbf":1392552611,"aud":["https:\/\/app-one.com","https:\/\/app-two.com"],"iss":"https:\/\/openid.net","jti":"586dd129-a29f-49c8-9de7-454af1155e27","iat":1392552611}';
  is($json, $expected, 'ECDH_ES_A256KW_A256GCM');
}
### PBSE2_HS256_A128KW_A128CBC_HS256
{
  my $token = "eyJhbGciOiJQQkVTMi1IUzI1NitBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwicDJjIjo4MTkyLCJwMnMiOiJiMFlFVmxMemtaNW9UUjBMIn0.dhPAhJ9kmaEbP-02VtEoPOF2QSEYM5085V6zYt1U1qIlVNRcHTGDgQ.4QAAq0dVQT41dQKDG7dhRA.H9MgJmesbU1ow6GCa0lEMwv8A_sHvgaWKkaMcdoj_z6O8LaMSgquxA-G85R_5hEILnHUnFllNJ48oJY7VmAJw0BQW73dMnn58u161S6Ftq7Mjxxq7bcksWvFTVtG5RsqqYSol5BZz5xm8Fcj-y5BMYMvrsCyQhYdeGEHkAvwzRdvZ8pGMsU2XPzl6GqxGjjuRh2vApAeNrj6MwKuD-k6AR0MH46EiNkVCmMkd2w8CNAXjJe9z97zky93xbxlOLozaC3NBRO2Q4bmdGdRg5y4Ew.xNqRi0ouQd7uo5UrPraedg";
  my $json = eval { decode_jwt(token=>$token, decode_payload=>0, key=>"top secret") } or warn $@;
  my $expected = '{"exp":1392553211,"sub":"alice","nbf":1392552611,"aud":["https:\/\/app-one.com","https:\/\/app-two.com"],"iss":"https:\/\/openid.net","jti":"586dd129-a29f-49c8-9de7-454af1155e27","iat":1392552611}';
  is($json, $expected, 'PBSE2_HS256_A128KW_A128CBC_HS256');
}
### PBSE2_HS256_A128KW_A256GCM
{
  my $token = "eyJhbGciOiJQQkVTMi1IUzI1NitBMTI4S1ciLCJlbmMiOiJBMjU2R0NNIiwicDJjIjo4MTkyLCJwMnMiOiJqVVozY0NEX2hMZ3pQVHVfIn0.cgEZLTNOoGgDJXhRj0Ca0DL_HTY2xRKzVpoRnOf_Yuxm6IsQJgf0NA.7sAUk5_ryTMO_hLB.y7arc1aQP1--WUwlUsti4SiW6O2nrmGviTYznPjw9KD9Tu4E4QQO3RCU1uo59qNF3jJ5Mgku5OXV8bJHlouMouUfZbEb2cHgH9GLwY7hbCuYfGBIEyZw6qnHCgLGatO59akKaVDa8fqPo5--V_q0T5Z3xWm7UpK8RHaR8z3kuSBEXI1JH-dgj1EikG0yHSxVkFiInrlNLGzhI-cMTSD5xfLlmhmTzqbdpNp947AQ7pix2IvkQdvdgCo3bbSQVUsSJrLZSg.cO4fVMmdniwtEikHv55cqQ";
  my $json = eval { decode_jwt(token=>$token, decode_payload=>0, key=>"top secret") } or warn $@;
  my $expected = '{"exp":1392553211,"sub":"alice","nbf":1392552611,"aud":["https:\/\/app-one.com","https:\/\/app-two.com"],"iss":"https:\/\/openid.net","jti":"586dd129-a29f-49c8-9de7-454af1155e27","iat":1392552611}';
  is($json, $expected, 'PBSE2_HS256_A128KW_A256GCM');
}
### PBSE2_HS384_A192KW_A192CBC_HS384
{
  my $token = "eyJhbGciOiJQQkVTMi1IUzM4NCtBMTkyS1ciLCJlbmMiOiJBMTkyQ0JDLUhTMzg0IiwicDJjIjo4MTkyLCJwMnMiOiIxZEdaODBpQTBqb3lGTzFqIn0.iElgf12HbQWt3enumKP_j3WDxGLfbwSePHYAbYEb_w3himk0swcdiTPo1Jm8MU7le7L_Z8rU2Uk.7LoW9-g7U8c3GNAYO3Z5Jw.guSjXuYN9deq6XIsbkbxAptU9Lp1jf9k11QdhsvjfUvaZRXKrWiE9vg3jEJRJnmF7lZq07cp2Ou8PztMg6R_ygT7gadmP_IYdgQwXD6HGQs__uzvFnqtjWALiwLWuL0V0INrKxBn3CivJ5Hg26nJwLACdVuO_k-fNTaphbox-nKefndS4UXaoe3hEuCzHFPgFivMlND4aZJb8pU8sQbGA29gx5U9qNBmWYOXwV2diYQ2q2SfUEbXoMV7uZyvfQ2juTcyqZBVnEfIYGf_8esALQ.QrgRr0TIlJDFkq2YWNXcoFoMpg4yMC6r";
  my $json = eval { decode_jwt(token=>$token, decode_payload=>0, key=>"top secret") } or warn $@;
  my $expected = '{"exp":1392553211,"sub":"alice","nbf":1392552611,"aud":["https:\/\/app-one.com","https:\/\/app-two.com"],"iss":"https:\/\/openid.net","jti":"586dd129-a29f-49c8-9de7-454af1155e27","iat":1392552611}';
  is($json, $expected, 'PBSE2_HS384_A192KW_A192CBC_HS384');
}
### PBSE2_HS512_A256KW_A256CBC_HS512
{
  my $token = "eyJhbGciOiJQQkVTMi1IUzUxMitBMjU2S1ciLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwicDJjIjo4MTkyLCJwMnMiOiJCUlkxQ1M3VXNpaTZJNzhkIn0.ovjAL7yRnB_XdJbK8lAaUDRZ-CyVeio8f4pnqOt1FPj1PoQAdEX3S5x6DlzR8aqN_WR5LUwdqDSyUDYhSurnmq8VLfzd3AEe.YAjH6g_zekXJIlPN4Ooo5Q.tutaltxpeVyayXZ9pQovGXTWTf_GWWvtu25Jeg9jgoH0sUX9KCnL00A69e4GJR6EMxalmWsa45AItffbwjUBmwdyklC4ZbTgaovVRs-UwqsZFBO2fpEb7qLajjwra7o4OegzgXDD0jhrKrUusvRWGBvenvumb5euibUxmIfBUcVF1JbdfYxx7ztFeS-QKJpDkE00zyEkViq-QxfrMVl5p7LGmTz8hMrFL3LXLokypZSDgFBfsUzChJf3mlYzxiGaGUqhs7NksQJDoUYf6prPow.XwRVfVTTPogO74RnxZD_9Mse26fTSehna1pbWy4VHfY";
  my $json = eval { decode_jwt(token=>$token, decode_payload=>0, key=>"top secret") } or warn $@;
  my $expected = '{"exp":1392553211,"sub":"alice","nbf":1392552611,"aud":["https:\/\/app-one.com","https:\/\/app-two.com"],"iss":"https:\/\/openid.net","jti":"586dd129-a29f-49c8-9de7-454af1155e27","iat":1392552611}';
  is($json, $expected, 'PBSE2_HS512_A256KW_A256CBC_HS512');
}
### A128GCMKW_A128CBC_HS256
{
  my $token = "eyJhbGciOiJBMTI4R0NNS1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiaXYiOiJ1SDVxVThlN2JVZXhGYWh3IiwidGFnIjoiamdxc2czdHoyUGo0QmhEWU1xTnBrdyJ9.peAzKiVO3_w2tAlSzRZdqqQpnUSpgPDHi_xgTd6VzP4.o8bhvYO_UTkrsxQmm__nIg.MSmgetpjXHWMs0TyuGgmWd-msfbQ7oVWC4WuCJcfAsbhLU9kLDLrd0naL5f_UkWBaM04bfcc31K4FRN20IiUxcHzLnMR-lY-HkvRFWYdur-kLWw1UXjIlPOb0nqCuyd2FRpxMdSfFnYr5Us9T45cF7DdK8p4iA7KqPToMHWBsvAcET_ycMIoERqJrBuiJzh-j7UtDzH6KtUfgD4tzZAm3iM6HWT2lq25Pqsu4qf19LYXxZaMIiFwFKboeexkJ5E0hc7P-wIeknzFJaZhkb5P4g.dTQAed1znLHX4cO-VDgxeA";
  my $json = eval { decode_jwt(token=>$token, decode_payload=>0, key=>$aes128Key) } or warn $@;
  my $expected = '{"exp":1392553211,"sub":"alice","nbf":1392552611,"aud":["https:\/\/app-one.com","https:\/\/app-two.com"],"iss":"https:\/\/openid.net","jti":"586dd129-a29f-49c8-9de7-454af1155e27","iat":1392552611}';
  is($json, $expected, 'A128GCMKW_A128CBC_HS256');
}
### A128GCMKW_A256CBC_HS512
{
  my $token = "eyJhbGciOiJBMTI4R0NNS1ciLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwiaXYiOiI5bUwxR1YzUUZIWGtVbEdUIiwidGFnIjoiU0xrTDVpdmhncy1HNjRBTS01bTBxdyJ9.S3_MudWEzKWCp8RRxIG5p6H2YOtMDCkOXXKM9J8J4lMX5N2CcUqsKkDQ4TE1rG7gD5qYgHsb8AiQFLbhjgDeAA.WiOHBPlws9hImQr6bZ8h5Q.jN9UbuvhTiS6uJi1jc0TsvpheXqHs8vdJzKOUVgFmVHZ_OG4vSNRLx408vSoAgSeqsRmj8C8i9Yi2R6kpgtRXZ-Rw7EQEjZ65kg2uwZuve1ObqK-uBm3UzDmcT_Jh6myp9Df1m28ng8ojfrY_JUz6oE5yEcJdlm7H8ahipJyznWOjFigOqhaiXosjW0kbGGpYE-njD5OX22vR5k0RxHlMCDAH2ONR69kaWbLQvDg7y4yMFSxi3ILUFSVz4uXo6qlb8RVCqMUWzlGho-5Cy9OPA.XQ0UmHH5btv14_km6CIlIUwzOFj-rQUYyEzF9VY0r70";
  my $json = eval { decode_jwt(token=>$token, decode_payload=>0, key=>$aes128Key) } or warn $@;
  my $expected = '{"exp":1392553211,"sub":"alice","nbf":1392552611,"aud":["https:\/\/app-one.com","https:\/\/app-two.com"],"iss":"https:\/\/openid.net","jti":"586dd129-a29f-49c8-9de7-454af1155e27","iat":1392552611}';
  is($json, $expected, 'A128GCMKW_A256CBC_HS512');
}
### A192GCMKW_A192CBC_HS384
{
  my $token = "eyJhbGciOiJBMTkyR0NNS1ciLCJlbmMiOiJBMTkyQ0JDLUhTMzg0IiwiaXYiOiJzRHRLdnRzZVk2UkFuU2twIiwidGFnIjoiZDFDS3dKWnlXSnlvcW5HTUFwbmR6dyJ9.2L9u7vV0P8bZddbkCKKe6_C5JTLf8wRZC8xzEe4gvmcGoF2K5AledhcqT6mIlaPx.1JY51r77jimrvKxts9EroQ.922BMD0HOscwZxn4pmYTRgV7oshegQ1dooU9njhonPcp46XbegdfsgeZAACVFpCc_CoY_XzOsM5trH1Z30QUDc7IGJmC0NKuPdK2KkrYQPXJAe6nuZMembGsyRkOHahtj7sew-ULZn9y0ztbntPqm5I9O716mv1Cu6_5_mBYu36c_VVd6jlzueUWun09yLDJLFuf5jRXDrqRrY4t6XIcqti8LF-QLowU_pa5DvRV_KzCtD_S8HvzJ217_TI9Y1qaApgvWr_BxDrfTXxO2xaZ2Q.0fnvCkg_ChWuf8F3KY8KUgbdIzifb_JT";
  my $json = eval { decode_jwt(token=>$token, decode_payload=>0, key=>$aes192Key) } or warn $@;
  my $expected = '{"exp":1392553211,"sub":"alice","nbf":1392552611,"aud":["https:\/\/app-one.com","https:\/\/app-two.com"],"iss":"https:\/\/openid.net","jti":"586dd129-a29f-49c8-9de7-454af1155e27","iat":1392552611}';
  is($json, $expected, 'A192GCMKW_A192CBC_HS384');
}
### A256GCMKW_A256CBC_HS512
{
  my $token = "eyJhbGciOiJBMjU2R0NNS1ciLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwiaXYiOiJvUV9xbDNJUHNibEVPaDBXIiwidGFnIjoieTllMEFfY1hZMnNDZ24tamxsNl9TdyJ9.K5BxtxcV0simNM-69RvjZuNBjxaavDVnBzP7EFXSjbWZi3NjZFoTcFljcu2TuzR_F9zdjjBbohEgaf4kUMVZfg.881rEerOD33OLCHKdTWDjQ.LvrzsNicH2slBjwERYFu-Fr4Bus2lcLTdFazEpsHc_0QH4NJ2tGrJJjByli6OaFOwtdWONEu_3Ax8xvEXWHc0WMhYKxaVLZI1HQwE0NnWyqfF9mtOkUCCXn9ljvSGSDQY5VUcupVUT6WQxAkaNe6mJ6qkJOxE4pBpiMskO0luW5PkPexk2N3bJVz-GwzMp3xVT6wtFimThucZm2V71594NPCKIkA0HvtBkW0gW0M66pSTfQTHkU0Uvm7WfRvr6TXpiuKntJUe7RX5pXFXbfN2g.aW8OWGfHFI5zTGfFyKuqeLFT5o0tleSYbpCb7kAv1Bs";
  my $json = eval { decode_jwt(token=>$token, decode_payload=>0, key=>$aes256Key) } or warn $@;
  my $expected = '{"exp":1392553211,"sub":"alice","nbf":1392552611,"aud":["https:\/\/app-one.com","https:\/\/app-two.com"],"iss":"https:\/\/openid.net","jti":"586dd129-a29f-49c8-9de7-454af1155e27","iat":1392552611}';
  is($json, $expected, 'A256GCMKW_A256CBC_HS512');
}
### A128KW_A128CBC_HS256
{
  my $token = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.DPRoUHQ3Ac8duyD32nUNH3eNUKzUIMYgEdf5GwJ8rW4MYQdl2PCIHA.B1dR6t93aUPcFC1c1aUjeA.lHPKTK0ehgzq70_Ihdh-svI2icUa9usgqP8sF5j50fsQAGizITZpTTXKOKd9-GSEVmJo07551hq9xscZj4vXsDEx-z-akxg0nlL5fFE24km7l4T3LfAeG17gmrMcJuLP55mFUg-F98j9duV2UCyKJPXP6RwOQ5X17VNw29c4k-_AxYM0EjTv3Fww1o3AGuVa07PfpLWE-GdJeJF9RLgaP_6Pua_mdVJud77bYXOsVxsweVtKIaBeLswMUUSU6PoC5oYURP_ybW76GOCjmgXpjA.avU8f5LK_tbJOyKW6-fRnw";
  my $json = eval { decode_jwt(token=>$token, decode_payload=>0, key=>$aes128Key) } or warn $@;
  my $expected = '{"exp":1392553211,"sub":"alice","nbf":1392552611,"aud":["https:\/\/app-one.com","https:\/\/app-two.com"],"iss":"https:\/\/openid.net","jti":"586dd129-a29f-49c8-9de7-454af1155e27","iat":1392552611}';
  is($json, $expected, 'A128KW_A128CBC_HS256');
}
### A192KW_A192CBC_HS384
{
  my $token = "eyJhbGciOiJBMTkyS1ciLCJlbmMiOiJBMTkyQ0JDLUhTMzg0In0.OLwgc7EaQdvsf54GfU69qH143C79H_eETvM_yGBgJzEB5367k9tbw6qW4TlQ56GMj__5QDJBvAg.BvYY_v4_dxxsK4M8A0T_TA.V0jBe7o-OahMkqGDgWW0Lxq1eTKPJYix7hjKmmqaKlhdVcnT0cdOU0ahdg82Ls-Vg_NaWKas8MhahHspz18Gx2abDSwLIKbU0jcaf0LxWZkEuMmFJs5dodq0ZqQeaEldDsHe9De_V_TQwPFkcMOPYqWhx2XEb13bmFTPtxNST18Cwm_j263Y_Ouz2YNyC4uZENZDWeOXfJLy7c8jt_ToOvXEVpXj7oZN7Ik1S9bGAenTcvUDORP-gdFdJ3stLe9FmKulOlb94Y-KvP_meyIZ7Q.XPPqS5YVJu2utJcAIRTUxlBHlECGRaM5";
  my $json = eval { decode_jwt(token=>$token, decode_payload=>0, key=>$aes192Key) } or warn $@;
  my $expected = '{"exp":1392553211,"sub":"alice","nbf":1392552611,"aud":["https:\/\/app-one.com","https:\/\/app-two.com"],"iss":"https:\/\/openid.net","jti":"586dd129-a29f-49c8-9de7-454af1155e27","iat":1392552611}';
  is($json, $expected, 'A192KW_A192CBC_HS384');
}
### A256KW_A256CBC_HS512
{
  my $token = "eyJhbGciOiJBMjU2S1ciLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0.91z9VM1VLIA_qyTbqeInFoit7c4PWVuQ5mHcDyNsfofDGXS1qUDdPCWRdLC8ybvJflqHej7SCjEUMxuzOtPOUOgo-8rcdeHi.rsx7FYNTunzditC8XTMJXg.k88BLb0qs8g0UnKjSq9rs2PcrhpafEaUEX2kT-wMdmviZ9UEJrECoQY7MmJgCyQYO30hnnay2psJcr_yaDhV-NpctBZ793Xf9tztLZZndIjz5omV9HjcFgheQZj4g1tbNcRLwxod5uYz-OLrKORzeROEM-wkLgHVEqs90wN98NAiyhGyVMw7CXVX5NdU2KFUacbflkJc5AcaiAZYAts1t9bo2877XLYSO1qBoI5k5QKv6ijjM8I03Uyr3H0p0tdF6EB-cdYNcxq68GvA5CTkOw.DBtOuSJTFu5AAIdcgymUR-JflpwfcXJ2AnZU8LNB3UA";
  my $json = eval { decode_jwt(token=>$token, decode_payload=>0, key=>$aes256Key) } or warn $@;
  my $expected = '{"exp":1392553211,"sub":"alice","nbf":1392552611,"aud":["https:\/\/app-one.com","https:\/\/app-two.com"],"iss":"https:\/\/openid.net","jti":"586dd129-a29f-49c8-9de7-454af1155e27","iat":1392552611}';
  is($json, $expected, 'A256KW_A256CBC_HS512');
}
### DIR_A192CBC_HS384
{
  my $token = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTkyQ0JDLUhTMzg0In0..fX42Nn8ABHClA0UfbpkX_g.ClZzxQIzg40GpTETaLejGNhCN0mqSM1BNCIU5NldeF-hGS7_u_5uFsJoWK8BLCoWRtQ3cWIeaHgOa5njCftEK1AoHvechgNCQgme-fuF3f2v5DOphU-tveYzN-uvrUthS0LIrAYrwQW0c0DKcJZ-9vQmC__EzesZgUHiDB8SnoEROPTvJcsBKI4zhFT7wOgqnFS7P7_BQZj_UnbJkzTAiE5MURBBpCYR-OS3zn--QftbdGVJ2CWmwH3HuDO9-IE2IQ5cKYHnzSwu1vyME_SpZA.qd8ZGKzmOzzPhFV-Po8KgJ5jZb5xUQtU";
  my $json = eval { decode_jwt(token=>$token, decode_payload=>0, key=>$aes384Key) } or warn $@;
  my $expected = '{"exp":1392553372,"sub":"alice","nbf":1392552772,"aud":["https:\/\/app-one.com","https:\/\/app-two.com"],"iss":"https:\/\/openid.net","jti":"f81648e9-e9b3-4e37-a655-fcfacace0ef0","iat":1392552772}';
  is($json, $expected, 'DIR_A192CBC_HS384');
}
### DIR_A256CBC_HS512
{
  my $token = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0..ZD93XtD7TOa2WMbqSuaY9g.1J5BAuxNRMWaw43s7hR82gqLiaZOHBmfD3_B9k4I2VIDKzS9oEF_NS2o7UIBa6t_fWHU7vDm9lNAN4rqq7OvtCBHJpFk31dcruQHxwYKn5xNefG7YP-o6QtpyNioNWJpaSD5VRcRO5ufRrw2bu4_nOth00yJU5jjN3O3n9f-0ewrN2UXDJIbZM-NiSuEDEgOVHImQXoOtOQd0BuaDx6xTJydw_rW5-_wtiOH2k-3YGlibfOWNu51kApGarRsAhhqKIPetYf5Mgmpv1bkUo6HJw.nVpOmg3Sxri0rh6nQXaIx5X0fBtCt7Kscg6c66NugHY";
  my $json = eval { decode_jwt(token=>$token, decode_payload=>0, key=>$aes512Key) } or warn $@;
  my $expected = '{"exp":1392553617,"sub":"alice","nbf":1392553017,"aud":["https:\/\/app-one.com","https:\/\/app-two.com"],"iss":"https:\/\/openid.net","jti":"029ea059-b8aa-44eb-a5ad-59458de678f8","iat":1392553017}';
  is($json, $expected, 'DIR_A256CBC_HS512');
}

### RS256 - BAD scalar key
{
  my $token = "eyJhbGciOiJSUzI1NiIsImN0eSI6InRleHRcL3BsYWluIn0.eyJoZWxsbyI6ICJ3b3JsZCJ9.NL_dfVpZkhNn4bZpCyMq5TmnXbT4yiyecuB6Kax_lV8Yq2dG8wLfea-T4UKnrjLOwxlbwLwuKzffWcnWv3LVAWfeBxhGTa0c4_0TX_wzLnsgLuU6s9M2GBkAIuSMHY6UTFumJlEeRBeiqZNrlqvmAzQ9ppJHfWWkW4stcgLCLMAZbTqvRSppC1SMxnvPXnZSWn_Fk_q3oGKWw6Nf0-j-aOhK0S0Lcr0PV69ZE4xBYM9PUS1MpMe2zF5J3Tqlc1VBcJ94fjDj1F7y8twmMT3H1PI9RozO-21R0SiXZ_a93fxhE_l_dj5drgOek7jUN9uBDjkXUwJPAyp9YPehrjyLdw";
  my $json = eval { decode_jwt(token=>$token, decode_payload=>0, key=>$rsaPub) };
  is($json, undef, 'RS256');
}
### ES256 - BAD scalar key
{
  my $token = "eyJhbGciOiJFUzI1NiIsImN0eSI6InRleHRcL3BsYWluIn0.eyJoZWxsbyI6ICJ3b3JsZCJ9.EVnmDMlz-oi05AQzts-R3aqWvaBlwVZddWkmaaHyMx5Phb2NSLgyI0kccpgjjAyo1S5KCB3LIMPfmxCX_obMKA";
  my $json = eval { decode_jwt(token=>$token, decode_payload=>0, key=>$Ecc256Public_PEM) };
  is($json, undef, 'ES256');
}


done_testing;