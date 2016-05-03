use strict;
use warnings;
use Test::More;
use Crypt::KeyWrap qw(ecdh_key_wrap ecdh_key_unwrap);
use Crypt::PK::ECC;
use Crypt::Misc qw(decode_b64u);

my $kek_private=Crypt::PK::ECC->new(\'{"kty":"EC","crv":"P-256","x":"BHId3zoDv6pDgOUh8rKdloUZ0YumRTcaVDCppUPoYgk","y":"g3QIDhaWEksYtZ9OWjNHn9a6-i_P9o5_NrdISP0VWDU","d":"KpTnMOHEpskXvuXHFCfiRtGUHUZ9Dq5CCcZQ-19rYs4"}');

{
  my $header={
    alg => "ECDH-ES",
    enc => "A128CBC-HS256",
    epk => {
             crv => "P-256",
             kty => "EC",
             x   => "-VMKLnMyoHTtFRZF6qW6wdFnA7mJBGb798WqU0UwAXY",
             y   => "hPAcQy83U-5B9uSmqnsWpVsluhdbRdMgnvtpgf5XWN8",
           },
  };
  my $expected_hex='81cbc97bcec94c11f704a10057ecde25d0c2ad56821e15816e98308bafdf8a5c';
  my $unw = ecdh_key_unwrap($kek_private, $header->{enc}, $header->{epk}, $header->{apu}, $header->{apv});
  is(unpack("H*", $unw), $expected_hex, "ECDH-ES + A128CBC-HS256")
}

{
  my $header={
    alg => "ECDH-ES",
    enc => "A128GCM",
    epk => {
             crv => "P-256",
             kty => "EC",
             x   => "Ol7jIi8H1iE1krvQNaPxjy-q-czP0N4EWO3R7584hGU",
             y   => "MdSeu9Snukp9lKde9rUnbjxkz3m_dMjjAw94WwCLZks",
           },
  };
  my $expected_hex='20fdcc92d30215765cb346805b5335c1';
  my $unw = ecdh_key_unwrap($kek_private, $header->{enc}, $header->{epk}, $header->{apu}, $header->{apv});
  is(unpack("H*", $unw), $expected_hex, "ECDH-ES + A128GCM")
}

{
  my $header={
    alg => "ECDH-ES",
    enc => "A192GCM",
    epk => {
             crv => "P-256",
             kty => "EC",
             x   => "PTwTYgcCK6iPn5D8Ne0HiDDmzoCiEaiJsH7C2pCEpsc",
             y   => "7gT2OTk-q9Ekkj8N58Gx-J6_ckqtgYeO0Drgq6IaOXc",
           },
  };
  my $expected_hex='4183d0802022bd2fc68231a7896c1846cdb022f335b68b97';
  my $unw = ecdh_key_unwrap($kek_private, $header->{enc}, $header->{epk}, $header->{apu}, $header->{apv});
  is(unpack("H*", $unw), $expected_hex, "ECDH-ES + A192GCM")
}

{
  my $header={
    alg => "ECDH-ES",
    enc => "A256GCM",
    epk => {
             crv => "P-256",
             kty => "EC",
             x   => "mExbMerMmx_o3fGmCtM4LwRPNsDlG4MDL55wjc7wpL8",
             y   => "C--vuVTv8XXS9qOZm_ZYqNxXn-bDWFLCeL1M6QKjIbY",
           },
  };
  my $expected_hex='4ddc0f6249fb5a4f1c908cc9fbf27e1a1d275e601bd23079851a0af7a8f18646';
  my $unw = ecdh_key_unwrap($kek_private, $header->{enc}, $header->{epk}, $header->{apu}, $header->{apv});
  is(unpack("H*", $unw), $expected_hex, "ECDH-ES + A256GCM")
}

{
  my $kek_public=Crypt::PK::ECC->new(\$kek_private->export_key_jwk('public'));
  my ($k1, $epk) = ecdh_key_wrap($kek_public, "A256GCM");
  my $k2 = ecdh_key_unwrap($kek_private, "A256GCM", $epk);
  is(unpack("H*", $k2), unpack("H*", $k1), "wrap+unwrap ECDH-ES");
}

done_testing;