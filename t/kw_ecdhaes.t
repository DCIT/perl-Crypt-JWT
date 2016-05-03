use strict;
use warnings;
use Test::More;
use Crypt::KeyWrap qw(ecdhaes_key_wrap ecdhaes_key_unwrap);
use Crypt::PK::ECC;
use Crypt::Misc qw(decode_b64u);

my $kek_private=Crypt::PK::ECC->new(\'{"kty":"EC","crv":"P-256","x":"BHId3zoDv6pDgOUh8rKdloUZ0YumRTcaVDCppUPoYgk","y":"g3QIDhaWEksYtZ9OWjNHn9a6-i_P9o5_NrdISP0VWDU","d":"KpTnMOHEpskXvuXHFCfiRtGUHUZ9Dq5CCcZQ-19rYs4"}');

{
  my $header={
    alg => "ECDH-ES+A128KW",
    enc => "A128GCM",
    epk => {
             crv => "P-256",
             kty => "EC",
             x   => "6ysUfUwOoUlD5JFdojPqWxWwfBwokmZjNVlIDQkpmO0",
             y   => "JeZbk_Pk22mj0TU0pnnB3UiL2K2IqYzNM1UTOe-JcwY",
           },
  };
  my $ct_hex='7b59f7613a2b249f87ede59bcbea5f196cd5c7468349c093';
  my $expected_hex='db216b638fb064b0f3cf64a0ac73735e';
  my $unw = ecdhaes_key_unwrap($kek_private, pack("H*", $ct_hex), $header->{alg}, $header->{epk}, $header->{apu}, $header->{apv});
  is(unpack("H*", $unw), $expected_hex, "ECDH-ES+A128KW");
}

{
  my $header={
    alg => "ECDH-ES+A192KW",
    enc => "A192GCM",
    epk => {
             crv => "P-256",
             kty => "EC",
             x   => "Ya1BV1IYxEohUcIrXCAOOzKe0POMuBPIf2dR6kMeSts",
             y   => "SUujcsl0vfiJn1u_4Y59MMJ5uFGcUZEBTWPu54ARgEE",
           },
  };
  my $ct_hex='c293eb5065530ecb616814ee4e88f90f9d4ef9b6d2242070983abb94ae25f1d1';
  my $expected_hex='919ef94365dd2fcca9abf69ee51258c7424e39c05e5f4ea0';
  my $unw = ecdhaes_key_unwrap($kek_private, pack("H*", $ct_hex), $header->{alg}, $header->{epk}, $header->{apu}, $header->{apv});
  is(unpack("H*", $unw), $expected_hex, "ECDH-ES+A192KW");
}

{
  my $header={
    alg => "ECDH-ES+A256KW",
    enc => "A256GCM",
    epk => {
             crv => "P-256",
             kty => "EC",
             x   => "ANTg-K8YAUuOk0mQmZLDPUiOqVEPPk-Pf6kRtn6cB2s",
             y   => "lJi7PLEDe6ZwqJ46jZr-FmPzyswFkpdIU7ZU34t8EDs",
           },
  };
  my $ct_hex='22aa77c37c68d76c02ab2355ffcc0d9379b6b472a9066bfae97011b1c1de2ed652fb616c9406df0d';
  my $expected_hex='bf9279a16dd7f284204387bcf9220c0ae9c6061c50ad28d7a42be6a902aedae3';
  my $unw = ecdhaes_key_unwrap($kek_private, pack("H*", $ct_hex), $header->{alg}, $header->{epk}, $header->{apu}, $header->{apv});
  is(unpack("H*", $unw), $expected_hex, "ECDH-ES+A256KW");
}

{
  my $kek_public=Crypt::PK::ECC->new(\$kek_private->export_key_jwk('public'));
  my ($wrp, $epk) = ecdhaes_key_wrap($kek_public, 'plaintext', "ECDH-ES+A256KW");
  my $unw = ecdhaes_key_unwrap($kek_private, $wrp, "ECDH-ES+A256KW", $epk);
  is($unw, 'plaintext', "wrap+unwrap ECDH-ES+A256KW");
}

done_testing;