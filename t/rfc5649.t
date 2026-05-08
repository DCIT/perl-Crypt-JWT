use strict;
use warnings;
use Test::More;
use Crypt::KeyWrap qw(aes_key_wrap aes_key_unwrap);

# Test vectors from RFC 5649, Section 6 "Padded Key Wrap Examples".
# https://www.rfc-editor.org/rfc/rfc5649.txt
#
# The AES Key Wrap with Padding (KWP) algorithm uses the alternate
# initial value A65959A6 || msg-len. Both example sizes (20 and 7
# octets) are non-multiples of 8 and exercise the padding logic.

my @tv = (
  {
    name => "Section 6 example 1: wrap 20 octets with a 192-bit KEK",
    kek  => "5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8",
    key  => "c37b7e6492584340bed12207808941155068f738",
    ct   => "138bdeaa9b8fa7fc61f97742e72248ee5ae6ae5360d1ae6a5f54f373fa543b6a",
  },
  {
    name => "Section 6 example 2: wrap 7 octets with a 192-bit KEK",
    kek  => "5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8",
    key  => "466f7250617369",
    ct   => "afbeb0f07dfbf5419200f2ccb50bb24f",
  },
);

for my $t (@tv) {
  my $kek = pack("H*", $t->{kek});
  my $pt  = pack("H*", $t->{key});
  my $exp = lc $t->{ct};

  my $ct = aes_key_wrap($kek, $pt, 'AES', 1);
  is(unpack("H*", $ct), $exp, "wrap: $t->{name}");

  my $back = aes_key_unwrap($kek, pack("H*", $exp), 'AES', 1);
  is(unpack("H*", $back), lc $t->{key}, "unwrap: $t->{name}");
}

done_testing;
