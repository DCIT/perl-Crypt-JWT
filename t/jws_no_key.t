use strict;
use warnings;
use Test::More;

plan tests => 2;

use Crypt::JWT qw(encode_jwt decode_jwt);

my $jws =
  'eyJqd2siOnsiZSI6IkFRQUIiLCJuIjoieVFJdnpEU3h2a2EzQTNhVFYzS2Yza29PeElWMjNqZGlaa1BkOU8xb3RsN0JYLWZJS2dEYk00QnBHSkxZLUhrTG5aZUxpcXgwSFpKaF94U09IVXhWNnVpLUpIU00yZkFrTnEzMHd4QzMycDZmVDk2b3RuT3ZsTEhPTVVpNEZwUFR0NDVFQmcyemlqRXRfRWNFM3g0OFJjT2ZQVGk3SDBmWnhBdXVYcmJrYmU1SHFqczVxVWp2bDFKWUdKdTA1TlItdnE2NUwyUC1oOFA5eUJBT1pRZjhRMVhBSGg1RlFQd08tQjZ3T1p6aTNjeTEtRUhXZkhpWXpxeTMxWU01ZmxIaFZ4QndWRmUyMUlINEh3WWp2SE5KMURFaEl2R2FSQTBWc09ZNlFqVUxPS19XTVlQVnExc211TmdEZThlZ1V4RnV2R2N4aWJ4NTUydHJkSHVBaWFUVGlRIiwia3R5IjoiUlNBIn0sImFsZyI6IlJTMjU2Iiwibm9uY2UiOm51bGx9.eyJjb250YWN0IjpbIm1haWx0bzpmQGcudGxkIl0sInJlc291cmNlIjoibmV3LXJlZyJ9.wrY6y0kvA3qgR38ZuAA471ygN9fmSHdfWDIayjkBKGmeGbn0f30_LQBC9FiFDFgFJ8Owyy3bOkPWvHx7yhRnP5XnEYdzNtKy4t2LyKq_JSEVQf6p1zycsVaxVLCmZ6ZbRidxIFLhbkcmu2uc4BEVGQQEj3UesccIv-AS2JCQFqK5ca-HQeaLEMntXOz5p7DYZtauYjHuXQ60i25mClm51jScJfP-wk7yYnnohGYKDinwiYlH4Nw8p4yElzWL1dI-U8fiFoxnduGaflPIZ80hkk0p7delrZt3RvmaDdu4cLJ16TgrMw_nMZfbAK0IJXByAsbej78HwIAchdzHyRPmgA';

my ( $header, $payload ) = decode_jwt( token => $jws, decode_header => 1 );

is_deeply(
    $header,
    {
        'alg' => 'RS256',
        'jwk' => {
            'e'   => '010001',
            'kty' => 'RSA',
            'n' =>
              'c9022fcc34b1be46b703769357729fde4a0ec48576de37626643ddf4ed68b65ec15fe7c82a00db3380691892d8f8790b9d978b8aac741d9261ff148e1d4c55eae8be24748cd9f02436adf4c310b7da9e9f4fdea8b673af94b1ce3148b81693d3b78e44060db38a312dfc4704df1e3c45c39f3d38bb1f47d9c40bae5eb6e46dee47aa3b39a948ef975258189bb4e4d47ebeaeb92f63fe87c3fdc8100e6507fc4355c01e1e4540fc0ef81eb0399ce2ddccb5f841d67c7898ceacb7d583397e51e15710705457b6d481f81f0623bc7349d4312122f19a440d15b0e63a42350b38afd63183d5ab5b26b8d8037bc7a053116ebc673189bc79e76b6b747b8089a4d389'
        },
        'nonce' => undef
    },
);

is_deeply(
    $payload,
    {
        'contact'  => ['mailto:f@g.tld'],
        'resource' => 'new-reg'
    }
);
