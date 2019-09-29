use strict;
use warnings;
use Test::More;

plan tests => 2;

use Crypt::JWT 'decode_jwt';

my $jws = '{"protected":"eyJhbGciOiJIUzI1NiJ9","payload":"","signature":"sd3ENUazK8vJX_adQ9xDR3N_oXk_pdfV9-OFlen2FmU"}';

my ( $header, $payload ) = decode_jwt( token => $jws, decode_header => 1, key => 'secret' );

is_deeply( $header, {'alg' => 'HS256'} );
is $payload, '';
