use strict;
use warnings;

use Test::More tests => 3;

use_ok('Crypt::KeyWrap');
use_ok('Crypt::JWT');

is($Crypt::KeyWrap::VERSION, $Crypt::JWT::VERSION, 'consistent version');
