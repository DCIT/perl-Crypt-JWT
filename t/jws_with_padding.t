use strict;
use warnings;
use Test::More;

use Crypt::JWT qw(decode_jwt);

my $ecc256Pub = <<'EOF';
-----BEGIN PUBLIC KEY-----
MIIBMzCB7AYHKoZIzj0CATCB4AIBATAsBgcqhkjOPQEBAiEA/////wAAAAEAAAAA
AAAAAAAAAAD///////////////8wRAQg/////wAAAAEAAAAAAAAAAAAAAAD/////
//////////wEIFrGNdiqOpPns+u9VXaYhrxlHQawzFOw9jvOPD4n0mBLBEEEaxfR
8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpZP40Li/hp/m47n60p8D54WK84z
V2sxXs7LtkBoN79R9QIhAP////8AAAAA//////////+85vqtpxeehPO5ysL8YyVR
AgEBA0IABLCZs5f55I9TnS52ClM2LY7Ui+9fVn1W7BAEmsgDbrY2J74jFoU+Rw4A
xlGgQNgAcsaX6u9exFUjJHQLL8wnZ0o=
-----END PUBLIC KEY-----
EOF

# my $ecc256Priv = <<'EOF';
# -----BEGIN EC PRIVATE KEY-----
# MIIBUQIBAQQg7hVSXtl+9yGHEYCsC6f11j/y3DX3NdDW0kQoO8EO9pmggeMwgeAC
# AQEwLAYHKoZIzj0BAQIhAP////8AAAABAAAAAAAAAAAAAAAA////////////////
# MEQEIP////8AAAABAAAAAAAAAAAAAAAA///////////////8BCBaxjXYqjqT57Pr
# vVV2mIa8ZR0GsMxTsPY7zjw+J9JgSwRBBGsX0fLhLEJH+Lzm5WOkQPJ3A32BLesz
# oPShOUXYmMKWT+NC4v4af5uO5+tKfA+eFivOM1drMV7Oy7ZAaDe/UfUCIQD/////
# AAAAAP//////////vOb6racXnoTzucrC/GMlUQIBAaFEA0IABLCZs5f55I9TnS52
# ClM2LY7Ui+9fVn1W7BAEmsgDbrY2J74jFoU+Rw4AxlGgQNgAcsaX6u9exFUjJHQL
# L8wnZ0o=
# -----END EC PRIVATE KEY-----
# EOF

my $token = 'eyJhbGciOiJFUzI1NiJ9.eyJoZWxsbyI6IndvcmxkIn0=.FOGAeCGvhKs-sQPUWQEmpdM0kC_yfi986ZW7XoT4pnlTKRLn43wDw6zVHdzEFFuy_JgsQFGYCfJQQds-5FF05w==';
my $decoded;

$decoded = eval { decode_jwt(token => $token, decode_payload => 0, key => \$ecc256Pub) };
is($decoded, undef, 'default (tolerate_padding => 0)');
$decoded = eval { decode_jwt(token => $token, tolerate_padding => 0, decode_payload => 0, key => \$ecc256Pub) };
is($decoded, undef, 'tolerate_padding => 0');
$decoded = eval { decode_jwt(token => $token, tolerate_padding => 1, decode_payload => 0, key => \$ecc256Pub) };
is($decoded, '{"hello":"world"}', 'tolerate_padding => 1');

done_testing;
