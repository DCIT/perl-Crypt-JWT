use strict;
use warnings;
use Test::More;
use Crypt::KeyWrap qw(gcm_key_wrap gcm_key_unwrap);
use Crypt::Misc qw(decode_b64u);

{
  ### test vector from https://github.com/rohe/pyjwkest/blob/5c1e321237dd2affb8b8434f0ca2a15c4da5e2b1/src/jwkest/aes_gcm.py
  my $iv  = pack("H*", 'cafebabefacedbaddecaf888');
  my $kek = pack("H*", 'feffe9928665731c6d6a8f9467308308');
  my $pt  = pack("H*", 'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39');
  my $ct  = pack("H*", '42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091');
  my $aad = pack("H*", 'feedfacedeadbeeffeedfacedeadbeefabaddad2');
  my $tag = pack("H*", '5bc94fbc3221a5db94fae95ae7121a47');
  
  my $rv_pt = gcm_key_unwrap($kek, $ct, $tag, $iv, $aad, 'AES');
  is(unpack("H*", $rv_pt), unpack("H*", $pt), "unwrap aes_gcm.py test vector");

  my ($rv_ct, $rv_tag, $rv_iv) = gcm_key_wrap($kek, $pt, $aad, 'AES', $iv);
  is(unpack("H*", $rv_ct),  unpack("H*", $ct),  "wrap aes_gcm.py test vector / ct");
  is(unpack("H*", $rv_iv),  unpack("H*", $iv),  "wrap aes_gcm.py test vector / iv");
  is(unpack("H*", $rv_tag), unpack("H*", $tag), "wrap aes_gcm.py test vector / tag");
}

done_testing;