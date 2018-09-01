use strict;
use warnings;
use Test::More;

plan tests => 2;

use Crypt::JWT qw(encode_jwt decode_jwt);

my $jws =
  'eyJqd2siOnsiZSI6IkFRQUIiLCJuIjoieVFJdnpEU3h2a2EzQTNhVFYzS2Yza29PeElWMjNqZGlaa1BkOU8xb3RsN0JYLWZJS2dEYk00QnBHSkxZLUhrTG5aZUxpcXgwSFpKaF94U09IVXhWNnVpLUpIU00yZkFrTnEzMHd4QzMycDZmVDk2b3RuT3ZsTEhPTVVpNEZwUFR0NDVFQmcyemlqRXRfRWNFM3g0OFJjT2ZQVGk3SDBmWnhBdXVYcmJrYmU1SHFqczVxVWp2bDFKWUdKdTA1TlItdnE2NUwyUC1oOFA5eUJBT1pRZjhRMVhBSGg1RlFQd08tQjZ3T1p6aTNjeTEtRUhXZkhpWXpxeTMxWU01ZmxIaFZ4QndWRmUyMUlINEh3WWp2SE5KMURFaEl2R2FSQTBWc09ZNlFqVUxPS19XTVlQVnExc211TmdEZThlZ1V4RnV2R2N4aWJ4NTUydHJkSHVBaWFUVGlRIiwia3R5IjoiUlNBIn0sImFsZyI6IlJTMjU2Iiwibm9uY2UiOm51bGx9.eyJjb250YWN0IjpbIm1haWx0bzpmQGcudGxkIl0sInJlc291cmNlIjoibmV3LXJlZyJ9.wrY6y0kvA3qgR38ZuAA471ygN9fmSHdfWDIayjkBKGmeGbn0f30_LQBC9FiFDFgFJ8Owyy3bOkPWvHx7yhRnP5XnEYdzNtKy4t2LyKq_JSEVQf6p1zycsVaxVLCmZ6ZbRidxIFLhbkcmu2uc4BEVGQQEj3UesccIv-AS2JCQFqK5ca-HQeaLEMntXOz5p7DYZtauYjHuXQ60i25mClm51jScJfP-wk7yYnnohGYKDinwiYlH4Nw8p4yElzWL1dI-U8fiFoxnduGaflPIZ80hkk0p7delrZt3RvmaDdu4cLJ16TgrMw_nMZfbAK0IJXByAsbej78HwIAchdzHyRPmgA';

my ( $header, $payload ) = decode_jwt( token => $jws, decode_header => 1, key_from_jwk_header => 1 );

is_deeply(
    $header,
    {
        'alg' => 'RS256',
        'jwk' => {
            'e'   => 'AQAB',
            'kty' => 'RSA',
            'n' =>
              'yQIvzDSxvka3A3aTV3Kf3koOxIV23jdiZkPd9O1otl7BX-fIKgDbM4BpGJLY-HkLnZeLiqx0HZJh_xSOHUxV6ui-JHSM2fAkNq30wxC32p6fT96otnOvlLHOMUi4FpPTt45EBg2zijEt_EcE3x48RcOfPTi7H0fZxAuuXrbkbe5Hqjs5qUjvl1JYGJu05NR-vq65L2P-h8P9yBAOZQf8Q1XAHh5FQPwO-B6wOZzi3cy1-EHWfHiYzqy31YM5flHhVxBwVFe21IH4HwYjvHNJ1DEhIvGaRA0VsOY6QjULOK_WMYPVq1smuNgDe8egUxFuvGcxibx552trdHuAiaTTiQ'
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
