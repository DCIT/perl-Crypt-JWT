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
