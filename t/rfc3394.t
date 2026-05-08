use strict;
use warnings;
use Test::More;
use Crypt::KeyWrap qw(aes_key_wrap aes_key_unwrap);

# Test vectors from RFC 3394, Section 4 "Test Vectors".
# https://www.rfc-editor.org/rfc/rfc3394.txt
#
# Each entry holds the KEK, the plaintext key data and the expected
# ciphertext exactly as printed in the RFC. KW uses the default
# all-A6 IV; padding is disabled (RFC 3394 KW, not RFC 5649 KWP).

my @tv = (
  {
    name => "4.1 Wrap 128 bits of Key Data with a 128-bit KEK",
    kek  => "000102030405060708090A0B0C0D0E0F",
    key  => "00112233445566778899AABBCCDDEEFF",
    ct   => "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5",
  },
  {
    name => "4.2 Wrap 128 bits of Key Data with a 192-bit KEK",
    kek  => "000102030405060708090A0B0C0D0E0F1011121314151617",
    key  => "00112233445566778899AABBCCDDEEFF",
    ct   => "96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D",
  },
  {
    name => "4.3 Wrap 128 bits of Key Data with a 256-bit KEK",
    kek  => "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
    key  => "00112233445566778899AABBCCDDEEFF",
    ct   => "64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7",
  },
  {
    name => "4.4 Wrap 192 bits of Key Data with a 192-bit KEK",
    kek  => "000102030405060708090A0B0C0D0E0F1011121314151617",
    key  => "00112233445566778899AABBCCDDEEFF0001020304050607",
    ct   => "031D33264E15D33268F24EC260743EDCE1C6C7DDEE725A936BA814915C6762D2",
  },
  {
    name => "4.5 Wrap 192 bits of Key Data with a 256-bit KEK",
    kek  => "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
    key  => "00112233445566778899AABBCCDDEEFF0001020304050607",
    ct   => "A8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1",
  },
  {
    name => "4.6 Wrap 256 bits of Key Data with a 256-bit KEK",
    kek  => "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
    key  => "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F",
    ct   => "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21",
  },
);

for my $t (@tv) {
  my $kek = pack("H*", $t->{kek});
  my $pt  = pack("H*", $t->{key});
  my $exp = lc $t->{ct};

  my $ct = aes_key_wrap($kek, $pt, 'AES', 0);
  is(unpack("H*", $ct), $exp, "wrap: $t->{name}");

  my $back = aes_key_unwrap($kek, pack("H*", $exp), 'AES', 0);
  is(unpack("H*", $back), lc $t->{key}, "unwrap: $t->{name}");
}

done_testing;
