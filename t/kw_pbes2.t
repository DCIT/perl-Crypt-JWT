use strict;
use warnings;
use Test::More;
use Crypt::KeyWrap qw(pbes2_key_wrap pbes2_key_unwrap);
use Crypt::Misc qw(decode_b64u);

{
  ### PBES2HS256A128KW test vector from https://github.com/Spomky-Labs/jose/blob/master/tests/PBES2_HS_AESKWKeyEncryptionTest.php
  my $header = {
    'alg' => 'PBES2-HS256+A128KW',
    'p2s' => '2WCTcJZ1Rvd_CJuJripQ1w',
    'p2c' => 4096,
    'enc' => 'A128CBC-HS256',
    'cty' => 'jwk+json',
  };
  my $b64u_wcek = 'TrqXOwuNUfDV9VPTNbyGvEJ9JMjefAVn-TR1uIxR9p6hsRQh9Tk7BA';
  my $key = join '', map { chr($_) } (84, 104, 117, 115, 32, 102, 114, 111, 109, 32, 109, 121, 32, 108, 105, 112, 115, 44, 32, 98, 121, 32, 121, 111, 117, 114, 115, 44, 32, 109, 121, 32, 115, 105, 110, 32, 105, 115, 32, 112, 117, 114, 103, 101, 100, 46);
  my $cek = join '', map { chr($_) } (111, 27, 25, 52, 66, 29, 20, 78, 92, 176, 56, 240, 65, 208, 82, 112, 161, 131, 36, 55, 202, 236, 185, 172, 129, 23, 153, 194, 195, 48, 253, 182);
  my $wcek = decode_b64u($b64u_wcek);
  my $salt = decode_b64u($header->{p2s});
  my $iter = $header->{p2c};
  
  my $unw = pbes2_key_unwrap($key, $wcek, $header->{alg}, $salt, $iter);
  is(unpack("H*", $unw), unpack("H*", $cek), "pbes2_key_unwrap");
  
  my $wrp = pbes2_key_wrap($key, $cek, $header->{alg}, $salt, $iter);
  is(unpack("H*", $wrp), unpack("H*", $wcek), "pbes2_key_wrap");
}

done_testing;