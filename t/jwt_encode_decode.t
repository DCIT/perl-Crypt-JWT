use strict;
use warnings;
use Test::More;
use utf8;

use Crypt::JWT qw(encode_jwt decode_jwt);
use Crypt::PK::ECC;
use Crypt::PK::RSA;
use Crypt::Misc qw(encode_b64u);

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

my $Ecc256KPublic = {
  kty => "EC",
  crv => "P-256K",
  x   => "BI73sZsLszl-rfZhmuigpQqIWvQuIz9vt0NE54tMbvY",
  y   => "K7X9QZsX_krlqGuqw_WYr46_N_M2rY5pq79Jf916hbc",
};
my $Ecc256KPrivate = {
  kty => "EC",
  crv => "P-256K",
  d   => "HguYHaQ8c6Ap4tJDOb-X0Hze6gYXvIfq7aENHJowIDc",
  x   => "BI73sZsLszl-rfZhmuigpQqIWvQuIz9vt0NE54tMbvY",
  y   => "K7X9QZsX_krlqGuqw_WYr46_N_M2rY5pq79Jf916hbc",
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

my @enclist = (qw/A128GCM A192GCM A256GCM A128CBC-HS256 A192CBC-HS384 A256CBC-HS512/);
my %jwealg = (
    'A128KW'             => '1234567890123456',                 #128 bits/16 bytes
    'A192KW'             => '123456789012345678901234',         #192 bits/24 bytes
    'A256KW'             => '12345678901234567890123456789012', #256 bits/32 bytes
    'A128GCMKW'          => '1234567890123456',                 #128 bits/16 bytes
    'A192GCMKW'          => '123456789012345678901234',         #192 bits/24 bytes
    'A256GCMKW'          => '12345678901234567890123456789012', #256 bits/32 bytes
    'PBES2-HS256+A128KW' => 'any length 1',
    'PBES2-HS384+A192KW' => 'any length 12',
    'PBES2-HS512+A256KW' => 'any length 123',
    'RSA-OAEP'           => [Crypt::PK::RSA->new(\$rsaPriv), Crypt::PK::RSA->new(\$rsaPub)],
    'RSA-OAEP-256'       => [Crypt::PK::RSA->new(\$rsaPriv), Crypt::PK::RSA->new(\$rsaPub)],
    'RSA1_5'             => [Crypt::PK::RSA->new(\$rsaPriv), Crypt::PK::RSA->new(\$rsaPub)],
    'ECDH-ES'            => [Crypt::PK::ECC->new($Ecc256Private), Crypt::PK::ECC->new($Ecc256Public)],
    'ECDH-ES+A128KW'     => [Crypt::PK::ECC->new($Ecc512Private), Crypt::PK::ECC->new($Ecc512Public)],
    'ECDH-ES+A192KW'     => [Crypt::PK::ECC->new($Ecc384Private), Crypt::PK::ECC->new($Ecc384Public)],
    'ECDH-ES+A256KW'     => [Crypt::PK::ECC->new($Ecc256Private), Crypt::PK::ECC->new($Ecc256Public)],
);
my %jwsalg = (
    'HS256' => 'any length 1234567890123456',
    'HS384' => 'any length 123456789012345678901234',
    'HS512' => 'any length 12345678901234567890123456789012',
    'RS256' => [Crypt::PK::RSA->new(\$rsaPriv), Crypt::PK::RSA->new(\$rsaPub)],
    'RS384' => [Crypt::PK::RSA->new(\$rsaPriv), Crypt::PK::RSA->new(\$rsaPub)],
    'RS512' => [Crypt::PK::RSA->new(\$rsaPriv), Crypt::PK::RSA->new(\$rsaPub)],
    'PS256' => [Crypt::PK::RSA->new(\$rsaPriv), Crypt::PK::RSA->new(\$rsaPub)],
    'PS384' => [Crypt::PK::RSA->new(\$rsaPriv), Crypt::PK::RSA->new(\$rsaPub)],
    'PS512' => [Crypt::PK::RSA->new(\$rsaPriv), Crypt::PK::RSA->new(\$rsaPub)],
    'ES256' => [Crypt::PK::ECC->new($Ecc256Private),  Crypt::PK::ECC->new($Ecc256Public)],
    'ES256K'=> [Crypt::PK::ECC->new($Ecc256KPrivate), Crypt::PK::ECC->new($Ecc256KPublic)],
    'ES384' => [Crypt::PK::ECC->new($Ecc512Private),  Crypt::PK::ECC->new($Ecc512Public)],
    'ES512' => [Crypt::PK::ECC->new($Ecc384Private),  Crypt::PK::ECC->new($Ecc384Public)],
);

for my $alg (sort keys %jwsalg) {
  my $k = ref $jwsalg{$alg} ? $jwsalg{$alg} : [ $jwsalg{$alg}, $jwsalg{$alg} ];
  my $payload = 'testik';
  my $token = encode_jwt(key=>$k->[0], payload=>$payload, alg=>$alg, allow_none=>1);
  ok($token, "token: alg=>$alg");
  my $decoded = decode_jwt(key=>$k->[1], token=>$token);
  is($decoded, 'testik', "decoded: alg=>$alg");
}

for my $alg (sort keys %jwealg) {
  for my $enc (@enclist) {
    my $k = ref $jwealg{$alg} ? $jwealg{$alg} : [ $jwealg{$alg}, $jwealg{$alg} ];
    my $payload = 'testik';
    my $token = encode_jwt(key=>$k->[1], payload=>$payload, alg=>$alg, enc=>$enc);
    ok($token, "token: enc=>$enc alg=>$alg");
    my $decoded = decode_jwt(key=>$k->[0], token=>$token);
    is($decoded, 'testik', "decoded: enc=>$enc alg=>$alg");
  }
}

for my $enc (@enclist) {
  my $alg = 'dir';
  my $key_size;
  if ($enc =~ /^A(128|192|256)CBC-HS/) {
    $key_size = 2*$1/8;
  }
  elsif ($enc =~ /^A(128|192|256)GCM/) {
    $key_size = $1/8;
  }
  my $k = 'x' x $key_size;
  my $payload = 'testik';
  my $token = encode_jwt(key=>$k, payload=>$payload, alg=>$alg, enc=>$enc);
  ok($token, "token: enc=>$enc alg=>$alg");
  my $decoded = decode_jwt(key=>$k, token=>$token, alg=>$alg, enc=>$enc);
  is($decoded, 'testik', "decoded: enc=>$enc alg=>$alg");

  my $payload_h = {str=>'žluťoučký kůň'};
  my $token_h = encode_jwt(key=>$k, payload=>$payload_h, alg=>$alg, enc=>$enc);
  ok($token_h, "token_h: enc=>$enc alg=>$alg");
  my $decoded_h = decode_jwt(key=>$k, token=>$token_h, alg=>$alg, enc=>$enc, decode_payload=>1);
  is($decoded_h->{str}, 'žluťoučký kůň', "decoded: enc=>$enc alg=>$alg");
}

{ # Ed25519 Signing: https://tools.ietf.org/html/rfc8037#appendix-A.4
  my $sk = '{"kty":"OKP","crv":"Ed25519","d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}';
  my $pk = '{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}';
  my $payload = 'Example of Ed25519 signing';
  my $token = encode_jwt(key=>\$sk, payload=>$payload, alg=>'EdDSA');
  is($token, "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc.hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg");
  my $decoded = decode_jwt(key=>\$pk, token=>$token);
  is($decoded, "Example of Ed25519 signing");
}

{ # ECDH-ES with X25519 (XXX-TODO are there some official test vectors?)
  my $pk = { curve => "x25519", pub => "178395b303d01458736dd006f4f004c09d4514108ea269886bf1e864d8bc9864" };
  my $sk = { curve => "x25519", priv => "a807d597e769248f2c428e38ecb401ce97e229bcbe3055d92c1c9e82dabe10c3" };
  my $payload = 'Hello!';
  my $token = encode_jwt(key=>$pk, payload=>$payload, alg=>'ECDH-ES+A256KW', enc=>'A256GCM');
  my $decoded = decode_jwt(key=>$sk, token=>$token);
  is($decoded, "Hello!");
}

{ # https://github.com/DCIT/perl-Crypt-JWT/issues/31
  # verify_xxx options do not work with decode_payload=0
  my $h = { hello => 'world' };
  my $token = encode_jwt(key=>\$rsaPriv, payload=>$h, alg=>'RS256', relative_exp => 1000);
  ok($token);
  ok( decode_jwt(key=>\$rsaPub, token=>$token) );
  ok( decode_jwt(key=>\$rsaPub, token=>$token, verify_exp=>1, decode_payload=>undef) );
  ok( decode_jwt(key=>\$rsaPub, token=>$token, verify_exp=>1, decode_payload=>1) );
  ok( decode_jwt(key=>\$rsaPub, token=>$token, verify_exp=>0, decode_payload=>1) );
  ok( decode_jwt(key=>\$rsaPub, token=>$token, verify_exp=>0, decode_payload=>0) );
  ok( !eval { decode_jwt(key=>\$rsaPub, token=>$token, verify_exp=>1, decode_payload=>0) } );
  my $tokenex = encode_jwt(key=>\$rsaPriv, payload=>$h, alg=>'RS256', relative_exp => -1000);
  ok($tokenex);
  ok( !eval { decode_jwt(key=>\$rsaPub, token=>$tokenex) } );
  ok( !eval { decode_jwt(key=>\$rsaPub, token=>$tokenex, verify_exp=>1, decode_payload=>undef) } );
  ok( !eval { decode_jwt(key=>\$rsaPub, token=>$tokenex, verify_exp=>1, decode_payload=>1) } );
  ok( decode_jwt(key=>\$rsaPub, token=>$tokenex, verify_exp=>0, decode_payload=>1) );
  ok( decode_jwt(key=>\$rsaPub, token=>$tokenex, verify_exp=>0, decode_payload=>0) );
  ok( !eval { decode_jwt(key=>\$rsaPub, token=>$tokenex, verify_exp=>1, decode_payload=>0) } );
}

done_testing;
