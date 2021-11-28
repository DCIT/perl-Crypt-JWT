package Crypt::KeyWrap;

use strict;
use warnings;

our $VERSION = '0.034';

use Exporter 'import';
our %EXPORT_TAGS = ( all => [qw(aes_key_wrap aes_key_unwrap gcm_key_wrap gcm_key_unwrap pbes2_key_wrap pbes2_key_unwrap ecdh_key_wrap ecdh_key_unwrap ecdhaes_key_wrap ecdhaes_key_unwrap rsa_key_wrap rsa_key_unwrap)] );
our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );
our @EXPORT = qw();

use Carp;
use Crypt::Mode::ECB;
use Crypt::AuthEnc::GCM qw(gcm_encrypt_authenticate gcm_decrypt_verify);
use Crypt::PRNG qw(random_bytes);
use Crypt::KeyDerivation qw(pbkdf2);
use Crypt::Digest qw(digest_data);
use Config;

# JWS: https://tools.ietf.org/html/rfc7515
# JWE: https://tools.ietf.org/html/rfc7516
# JWK: https://tools.ietf.org/html/rfc7517
# JWA: https://tools.ietf.org/html/rfc7518 - !!! this is important !!!

sub _LSB {
  my ($bytes, $data) = @_;
  my $len = length $data;
  return $len > $bytes ? substr($data, $len-$bytes, $bytes) : $data;
}

sub _MSB {
  my ($bytes, $data) = @_;
  my $len = length $data;
  return $len > $bytes ? substr($data, 0, $bytes) : $data;
}

sub _N2RAW {
  my ($bytes, $n) = @_;
  if ($bytes == 8) {
    return pack("N", 0) . pack("N", $n) if $Config{uvsize} == 4; #workaround
    return pack("N", $n >> 32) . pack("N", $n & 0xFFFFFFFF);
  }
  return pack("N", $n & 0xFFFFFFFF) if $bytes == 4;
}

sub aes_key_wrap {
  my ($kek, $pt_data, $cipher, $padding, $inverse) = @_;
  $cipher  = 'AES' unless defined $cipher;
  $padding = $cipher eq 'AES' ? 1 : 0 unless defined $padding;

  my ($A, $B, $P, $R);

  croak "aes_key_wrap: no KEK"     unless defined $kek;
  croak "aes_key_wrap: no PT data" unless defined $pt_data;
  my $klen = length $kek;
  croak "aes_key_wrap: invalid KEK length" unless $klen == 16 || $klen == 24 || $klen == 32;
  croak "aes_key_wrap: cipher must be AES or DES_EDE" unless $cipher eq 'AES' || $cipher eq 'DES_EDE';
  croak "aes_key_wrap: padding not allowed with DES_EDE" if $padding && $cipher eq 'DES_EDE';

  my $ECB = Crypt::Mode::ECB->new($cipher, 0);
  my $blck = $cipher eq 'DES_EDE' ? 4 : 8; # semiblock size in bytes, for AES 8, for 3DES 4

  my $IV = pack("H*", "A6" x $blck);
  my $len = length $pt_data;
  if ($len % $blck > 0) {
    croak "aes_key_wrap: pt_data length not multiply of $blck" if !$padding;
    $pt_data .= chr(0) x ($blck - ($len % $blck));
    $IV = pack("H*", "A65959A6") . pack("N", $len);
  }

  my $n = length($pt_data) / $blck;
  $P->[$_] = substr($pt_data, $_*$blck, $blck) for (0..$n-1);

  if ($n == 1) {
    return $inverse ? $ECB->decrypt($IV . $P->[0], $kek)
                    : $ECB->encrypt($IV . $P->[0], $kek);
  }

  $A = $IV;
  $R->[$_] = $P->[$_] for (0..$n-1);

  for my $j (0..5) {
    for my $i (0..$n-1) {
      $B = $inverse ? $ECB->decrypt($A . $R->[$i], $kek)
                    : $ECB->encrypt($A . $R->[$i], $kek);
      $A = _MSB($blck, $B) ^ _N2RAW($blck, ($n*$j)+$i+1);
      $R->[$i] = _LSB($blck, $B);
    }
  }

  my $rv = $A;
  $rv .= $R->[$_] for (0..$n-1);
  return $rv;
}

sub aes_key_unwrap {
  my ($kek, $ct_data, $cipher, $padding, $inverse) = @_;
  $cipher  = 'AES' unless defined $cipher;
  $padding = $cipher eq 'AES' ? 1 : 0 unless defined $padding;

  my ($A, $B, $C, $P, $R);

  croak "aes_key_unwrap: no KEK"     unless defined $kek;
  croak "aes_key_unwrap: no CT data" unless defined $ct_data;
  my $klen = length $kek;
  croak "aes_key_unwrap: invalid KEK length" unless $klen == 16 || $klen == 24 || $klen == 32;
  croak "aes_key_unwrap: cipher must be AES or DES_EDE" unless $cipher eq 'AES' || $cipher eq 'DES_EDE';
  croak "aes_key_unwrap: padding not allowed with DES_EDE" if $padding && $cipher eq 'DES_EDE';

  my $ECB = Crypt::Mode::ECB->new($cipher, 0);
  my $blck = $cipher eq 'DES_EDE' ? 4 : 8; # semiblock size in bytes, for AES 8, for 3DES 4

  my $n = length($ct_data) / $blck - 1;
  $C->[$_] = substr($ct_data, $_*$blck, $blck) for (0..$n); # n+1 semiblocks

  if ($n==1) {
    $B = $inverse ? $ECB->encrypt($C->[0] . $C->[1], $kek)
                  : $ECB->decrypt($C->[0] . $C->[1], $kek);
    $A = _MSB($blck, $B);
    $R->[0] = _LSB($blck, $B);
  }
  else {
    $A = $C->[0];
    $R->[$_] = $C->[$_+1] for (0..$n-1);
    for(my $j=5; $j>=0; $j--) {
      for(my $i=$n-1; $i>=0; $i--) {
        $B = $inverse ? $ECB->encrypt(($A ^ _N2RAW($blck, $n*$j+$i+1)) . $R->[$i], $kek)
                      : $ECB->decrypt(($A ^ _N2RAW($blck, $n*$j+$i+1)) . $R->[$i], $kek);
        $A = _MSB($blck, $B);
        $R->[$i] = _LSB($blck, $B);
      }
    }
  }

  my $rv = '';
  $rv .= $R->[$_] for (0..$n-1);

  my $A_hex = unpack("H*", $A);
  if ($A_hex eq 'a6'x$blck) {
    return $rv;
  }
  elsif ($A_hex =~ /^a65959a6/ && $blck == 8) {
    warn "key_unwrap: unexpected padding" unless $padding;
    my $n = unpack("N", substr($A, 4, 4));
    my $z = length($rv) - $n;
    my $tail = unpack("H*", substr($rv, -$z));
    croak "aes_key_unwrap: invalid data" unless $tail eq "00"x$z;
    return substr($rv, 0, $n);
  }
  croak "aes_key_unwrap: unexpected data [$cipher/$A_hex]";
}

# AES GCM KW - https://tools.ietf.org/html/rfc7518#section-4.7

sub gcm_key_wrap {
  my ($kek, $pt_data, $aad, $cipher, $iv) = @_;
  $cipher = 'AES' unless defined $cipher;
  $iv = random_bytes(12) unless defined $iv; # 96 bits REQUIRED by RFC7518
  my ($ct_data, $tag) = gcm_encrypt_authenticate($cipher, $kek, $iv, $aad, $pt_data);
  return ($ct_data, $tag, $iv);
}

sub gcm_key_unwrap {
  my ($kek, $ct_data, $tag, $iv, $aad, $cipher) = @_;
  $cipher ||= 'AES';
  my $pt_data = gcm_decrypt_verify($cipher, $kek, $iv, $aad, $ct_data, $tag);
  return $pt_data;
}

# PBES2/PBKDF2 KW - https://tools.ietf.org/html/rfc7518#section-4.8

sub pbes2_key_wrap {
  my ($kek, $pt_data, $alg, $salt, $iter) = @_;
  my ($hash_name, $len);
  if ($alg =~ /^PBES2-HS(256|384|512)\+A(128|192|256)KW$/) {
    $hash_name = "SHA$1";
    $len = $2/8;
    my $aes_key = pbkdf2($kek, $alg."\x00".$salt, $iter, $hash_name, $len);
    my $ct_data = aes_key_wrap($aes_key, $pt_data);
    return $ct_data;
  }
  croak "pbes2_key_wrap: invalid alg '$alg'";
  return undef;
}

sub pbes2_key_unwrap {
  my ($kek, $ct_data, $alg, $salt, $iter) = @_;
  my ($hash_name, $len);
  if ($alg =~ /^PBES2-HS(256|384|512)\+A(128|192|256)KW$/) {
    $hash_name = "SHA$1";
    $len = $2/8;
    my $aes_key = pbkdf2($kek, $alg."\x00".$salt, $iter, $hash_name, $len);
    my $pt_data = aes_key_unwrap($aes_key, $ct_data);
    return $pt_data;
  }
  croak "pbes2_key_unwrap: invalid alg '$alg'";
  return undef;
}

# RSA KW
# https://tools.ietf.org/html/rfc7518#section-4.2
# https://tools.ietf.org/html/rfc7518#section-4.3

sub rsa_key_wrap {
  my ($kek_public, $pt_data, $alg) = @_;
  croak "rsa_key_wrap: no Crypt::PK::RSA" unless ref $kek_public eq 'Crypt::PK::RSA';
  my ($padding, $hash_name);
  if    ($alg eq 'RSA-OAEP')     { ($padding, $hash_name) = ('oaep', 'SHA1') }
  elsif ($alg eq 'RSA-OAEP-256') { ($padding, $hash_name) = ('oaep', 'SHA256') }
  elsif ($alg eq 'RSA1_5')       { $padding = 'v1.5' }
  croak "rsa_key_wrap: invalid algorithm '$alg'" unless $padding;
  my $ct_data = $kek_public->encrypt($pt_data, $padding, $hash_name);
  return $ct_data;
}

sub rsa_key_unwrap {
  my ($kek_private, $ct_data, $alg) = @_;
  croak "rsa_key_unwrap: no Crypt::PK::RSA" unless ref $kek_private eq 'Crypt::PK::RSA';
  croak "rsa_key_unwrap: no private key" unless $kek_private->is_private;
  my ($padding, $hash_name);
  if    ($alg eq 'RSA-OAEP')     { ($padding, $hash_name) = ('oaep', 'SHA1') }
  elsif ($alg eq 'RSA-OAEP-256') { ($padding, $hash_name) = ('oaep', 'SHA256') }
  elsif ($alg eq 'RSA1_5')       { $padding = 'v1.5' }
  croak "rsa_key_unwrap: invalid algorithm '$alg'" unless $padding;
  my $pt_data = $kek_private->decrypt($ct_data, $padding, $hash_name);
  return $pt_data;
}

# ConcatKDF - http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar2.pdf
# ECDH KW   - https://tools.ietf.org/html/rfc7518#section-4.6

sub _concat_kdf {
  my ($hash_name, $key_size, $shared_secret, $algorithm, $apu, $apv) = @_;
  $apu = '' unless defined $apu;
  $apv = '' unless defined $apv;
  my $hsize = Crypt::Digest->hashsize($hash_name);
  my $count = int($key_size / $hsize);
  $count++ if ($key_size % $hsize) > 0;
  my $data = '';
  for my $i (1..$count) {
    $data .= digest_data('SHA256', pack("N", 1) .
                                   $shared_secret .
                                   pack("N", length($algorithm)) . $algorithm .
                                   pack("N", length($apu)) . $apu .
                                   pack("N", length($apv)) . $apv .
                                   pack("N", 8 *$key_size));
  }
  return substr($data, 0, $key_size);
}

sub ecdh_key_wrap {
  my ($kek_public, $enc, $apu, $apv) = @_;
  croak "ecdh_key_wrap: no Crypt::PK::ECC" unless ref $kek_public eq 'Crypt::PK::ECC';
  my $encryption_key_size = 256;
  if ($enc =~ /^A(128|192|256)CBC-HS/) {
    $encryption_key_size = $1*2;
  }
  if ($enc =~ /^A(128|192|256)GCM/) {
    $encryption_key_size = $1;
  }
  my $ephemeral = Crypt::PK::ECC->new()->generate_key($kek_public->curve2hash);
  my $shared_secret = $ephemeral->shared_secret($kek_public);
  my $ct_data = _concat_kdf('SHA256', $encryption_key_size/8, $shared_secret, $enc, $apu, $apv);
  return ($ct_data, $ephemeral->export_key_jwk('public'));
}

sub ecdh_key_unwrap {
  my ($kek_private, $enc, $epk, $apu, $apv) = @_;
  croak "ecdh_key_unwrap: no Crypt::PK::ECC" unless ref $kek_private eq 'Crypt::PK::ECC';
  croak "ecdh_key_unwrap: no private key" unless $kek_private->is_private;
  my $encryption_key_size = 256;
  if ($enc =~ /^A(128|192|256)CBC-HS/) {
    $encryption_key_size = $1*2;
  }
  if ($enc =~ /^A(128|192|256)GCM/) {
    $encryption_key_size = $1;
  }
  my $ephemeral = ref($epk) eq 'Crypt::PK::ECC' ? $epk : Crypt::PK::ECC->new(ref $epk ? $epk : \$epk);
  my $shared_secret = $kek_private->shared_secret($ephemeral);
  my $pt_data = _concat_kdf('SHA256', $encryption_key_size/8, $shared_secret, $enc, $apu, $apv);
  return $pt_data;
}

sub ecdhaes_key_wrap {
  my ($kek_public, $pt_data, $alg, $apu, $apv) = @_;
  croak "ecdhaes_key_wrap: no Crypt::PK::(ECC|X25519)" unless ref($kek_public) =~ /^Crypt::PK::(ECC|X25519)$/;
  my $encryption_key_size = 256;
  if ($alg =~ /^ECDH-ES\+A(128|192|256)KW$/) {
    $encryption_key_size = $1;
  }
  my $ephemeral;
  if (ref($kek_public) eq 'Crypt::PK::ECC') {
    $ephemeral = Crypt::PK::ECC->new->generate_key($kek_public->curve2hash);
  }
  else {
    $ephemeral = Crypt::PK::X25519->new->generate_key();
  }
  my $shared_secret = $ephemeral->shared_secret($kek_public);
  my $kek = _concat_kdf('SHA256', $encryption_key_size/8, $shared_secret, $alg, $apu, $apv);
  return (aes_key_wrap($kek, $pt_data), $ephemeral->export_key_jwk('public'));
}

sub ecdhaes_key_unwrap {
  my ($kek_private, $ct_data, $alg, $epk, $apu, $apv) = @_;
  croak "ecdhaes_key_unwrap: no Crypt::PK::(ECC|X25519)" unless ref($kek_private) =~ /^Crypt::PK::(ECC|X25519)$/;
  croak "ecdhaes_key_unwrap: no private key" unless $kek_private->is_private;
  my $encryption_key_size = 256;
  if ($alg =~ /^ECDH-ES\+A(128|192|256)KW$/) {
    $encryption_key_size = $1;
  }
  my $ephemeral;
  if (ref($kek_private) eq 'Crypt::PK::ECC') {
    $ephemeral = ref($epk) eq 'Crypt::PK::ECC' ? $epk : Crypt::PK::ECC->new(ref $epk ? $epk : \$epk);
  }
  else {
    $ephemeral = ref($epk) eq 'Crypt::PK::X25519' ? $epk : Crypt::PK::X25519->new(ref $epk ? $epk : \$epk);
  }
  my $shared_secret = $kek_private->shared_secret($ephemeral);
  my $kek = _concat_kdf('SHA256', $encryption_key_size/8, $shared_secret, $alg, $apu, $apv);
  my $pt_data = aes_key_unwrap($kek, $ct_data);
  return $pt_data;
}

1;

=pod

=head1 NAME

Crypt::KeyWrap - Key management/wrapping algorithms defined in RFC7518 (JWA)

=head1 SYNOPSIS

   # A192KW wrapping
   use Crypt::KeyWrap qw(aes_key_wrap);
   my $kek     = pack("H*", "5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8"); # key encryption key
   my $cek     = pack("H*", "c37b7e6492584340bed12207808941155068f738"); # content encryption key
   my $enc_cek = aes_key_wrap($kek, $pt_data); # encrypted content encryption key

   # A192KW unwrapping
   use Crypt::KeyWrap qw(aes_key_unwrap);
   my $kek     = pack("H*", "5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8");
   my $enc_cek = pack("H*", "138bdeaa9b8fa7fc61f97742e72248ee5ae6ae5360d1ae6a5f54f373fa543b6a");
   my $cek     = aes_key_unwrap($kek, $pt_data);

=head1 DESCRIPTION

Implements key management algorithms defined in L<https://tools.ietf.org/html/rfc7518>

BEWARE: experimental, interface of this module might change!

Supported algorithms (all defined in RFC7518):

 A128KW                 see: aes_key_wrap() + aes_key_unwrap()
 A192KW                 see: aes_key_wrap() + aes_key_unwrap()
 A256KW                 see: aes_key_wrap() + aes_key_unwrap()
 A128GCMKW              see: gcm_key_wrap() + gcm_key_unwrap()
 A192GCMKW              see: gcm_key_wrap() + gcm_key_unwrap()
 A256GCMKW              see: gcm_key_wrap() + gcm_key_unwrap()
 PBES2-HS256+A128KW     see: pbes2_key_wrap() + pbes2_key_unwrap()
 PBES2-HS384+A192KW     see: pbes2_key_wrap() + pbes2_key_unwrap()
 PBES2-HS512+A256KW     see: pbes2_key_wrap() + pbes2_key_unwrap()
 RSA-OAEP               see: rsa_key_wrap() + rsa_key_unwrap()
 RSA-OAEP-256           see: rsa_key_wrap() + rsa_key_unwrap()
 RSA1_5                 see: rsa_key_wrap() + rsa_key_unwrap()
 ECDH-ES+A128KW         see: ecdhaes_key_wrap() + ecdhaes_key_unwrap()
 ECDH-ES+A192KW         see: ecdhaes_key_wrap() + ecdhaes_key_unwrap()
 ECDH-ES+A256KW         see: ecdhaes_key_wrap() + ecdhaes_key_unwrap()
 ECDH-ES                see: ecdh_key_wrap() + ecdh_key_unwrap()

=head1 EXPORT

Nothing is exported by default.

You can export selected functions:

  use Crypt::KeyWrap qw(aes_key_wrap gcm_key_wrap pbes2_key_wrap);

Or all of them at once:

  use Crypt::KeyWrap ':all';

=head1 FUNCTIONS

=head2 aes_key_wrap

AES key wrap algorithm as defined in L<https://tools.ietf.org/html/rfc7518#section-4.4>
(implements algorithms C<A128KW>, C<A192KW>, C<A256KW>).

Implementation follows L<https://tools.ietf.org/html/rfc5649> and L<https://tools.ietf.org/html/rfc3394>.

The implementation is also compatible with L<http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38F.pdf>
(it supports AES based KW, KWP + TDEA/DES_EDE based TKW).

AES Key Wrap algorithm.

   $enc_cek = aes_key_wrap($kek, $cek);
   # or
   $enc_cek = aes_key_wrap($kek, $cek, $cipher, $padding, $inverse);

   # params:
   #  $kek     .. key encryption key (16bytes for AES128, 24 for AES192, 32 for AES256)
   #  $cek     .. content encryption key
   # optional params:
   #  $cipher  .. 'AES' (default) or 'DES_EDE'
   #  $padding .. 1 (default) or 0 handle $cek padding (relevant for AES only)
   #  $inverse .. 0 (default) or 1 use cipher in inverse mode as defined by SP.800-38F

Values C<$enc_cek>, C<$cek> and C<$kek> are binary octets. If you disable padding you have to make sure that
C<$cek> length is multiply of 8 (for AES) or multiply of 4 (for DES_EDE);

=head2 aes_key_unwrap

AES key unwrap algorithm as defined in L<https://tools.ietf.org/html/rfc7518#section-4.4>
(implements algorithms C<A128KW>, C<A192KW>, C<A256KW>).

AES Key Unwrap algorithm.

   $cek = aes_key_unwrap($kek, $enc_cek);
   # or
   $cek = aes_key_unwrap($kek, $enc_cek, $cipher, $padding, $inverse);

   # params:
   #  $kek     .. key encryption key (16bytes for AES128, 24 for AES192, 32 for AES256)
   #  $enc_cek .. encrypted content encryption key
   # optional params:
   #  $cipher  .. 'AES' (default) or 'DES_EDE'
   #  $padding .. 1 (default) or 0 - use $cek padding (relevant for AES only)
   #  $inverse .. 0 (default) or 1 - use cipher in inverse mode as defined by SP.800-38F

Values C<$enc_cek>, C<$cek> and C<$kek> are binary octets.

=head2 gcm_key_wrap

AES GCM key wrap algorithm as defined in L<https://tools.ietf.org/html/rfc7518#section-4.7>
(implements algorithms C<A128GCMKW>, C<A192GCMKW>, C<A256GCMKW>).

   ($enc_cek, $tag, $iv) = gcm_key_wrap($kek, $cek);
   #or
   ($enc_cek, $tag, $iv) = gcm_key_wrap($kek, $cek, $aad);
   #or
   ($enc_cek, $tag, $iv) = gcm_key_wrap($kek, $cek, $aad, $cipher, $iv);

   # params:
   #  $kek     .. key encryption key (16bytes for AES128, 24 for AES192, 32 for AES256)
   #  $cek     .. content encryption key
   # optional params:
   #  $aad     .. additional authenticated data, DEFAULT is '' (empty string)
   #  $cipher  .. cipher to be used by GCM, DEFAULT is 'AES'
   #  $iv      .. initialization vector (if not defined a random IV is generated)

Values C<$enc_cek>, C<$cek>, C<$aad>, C<$iv>, C<$tag> and C<$kek> are binary octets.

=head2 gcm_key_unwrap

AES GCM key unwrap algorithm as defined in L<https://tools.ietf.org/html/rfc7518#section-4.7>
(implements algorithms C<A128GCMKW>, C<A192GCMKW>, C<A256GCMKW>).

   $cek = gcm_key_unwrap($kek, $enc_cek, $tag, $iv);
   # or
   $cek = gcm_key_unwrap($kek, $enc_cek, $tag, $iv, $aad);
   # or
   $cek = gcm_key_unwrap($kek, $enc_cek, $tag, $iv, $aad, $cipher);

   # params:
   #  $kek     .. key encryption key (16bytes for AES128, 24 for AES192, 32 for AES256)
   #  $enc_cek .. encrypted content encryption key
   #  $tag     .. GCM's tag
   #  $iv      .. initialization vector
   # optional params:
   #  $aad     .. additional authenticated data, DEFAULT is '' (empty string)
   #  $cipher  .. cipher to be used by GCM, DEFAULT is 'AES'

Values C<$enc_cek>, C<$cek>, C<$aad>, C<$iv>, C<$tag> and C<$kek> are binary octets.

=head2 pbes2_key_wrap

PBES2 key wrap algorithm as defined in L<https://tools.ietf.org/html/rfc7518#section-4.8>
(implements algorithms C<PBES2-HS256+A128KW>, C<PBES2-HS384+A192KW>, C<PBES2-HS512+A256KW>).

   $enc_cek = pbes2_key_wrap($kek, $cek, $alg, $salt, $iter);

   # params:
   #  $kek     .. key encryption key (arbitrary length)
   #  $cek     .. content encryption key
   #  $alg     .. algorithm name e.g. 'PBES2-HS256+A128KW' (see rfc7518)
   #  $salt    .. pbkdf2 salt
   #  $iter    .. pbkdf2 iteration count

Values C<$enc_cek>, C<$cek>, C<$salt> and C<$kek> are binary octets.

=head2 pbes2_key_unwrap

PBES2 key unwrap algorithm as defined in L<https://tools.ietf.org/html/rfc7518#section-4.8>
(implements algorithms C<PBES2-HS256+A128KW>, C<PBES2-HS384+A192KW>, C<PBES2-HS512+A256KW>).

   $cek = pbes2_key_unwrap($kek, $enc_cek, $alg, $salt, $iter);

   # params:
   #  $kek     .. key encryption key (arbitrary length)
   #  $enc_cek .. encrypted content encryption key
   #  $alg     .. algorithm name e.g. 'PBES2-HS256+A128KW' (see rfc7518)
   #  $salt    .. pbkdf2 salt
   #  $iter    .. pbkdf2 iteration count

Values C<$enc_cek>, C<$cek>, C<$salt> and C<$kek> are binary octets.

=head2 rsa_key_wrap

PBES2 key wrap algorithm as defined in L<https://tools.ietf.org/html/rfc7518#section-4.2> and
L<https://tools.ietf.org/html/rfc7518#section-4.3> (implements algorithms C<RSA1_5>, C<RSA-OAEP-256>, C<RSA-OAEP>).

   $enc_cek = rsa_key_wrap($kek, $cek, $alg);

   # params:
   #  $kek     .. RSA public key - Crypt::PK::RSA instance
   #  $cek     .. content encryption key
   #  $alg     .. algorithm name e.g. 'RSA-OAEP' (see rfc7518)

Values C<$enc_cek> and C<$cek> are binary octets.

=head2 rsa_key_unwrap

PBES2 key wrap algorithm as defined in L<https://tools.ietf.org/html/rfc7518#section-4.2> and
L<https://tools.ietf.org/html/rfc7518#section-4.3> (implements algorithms C<RSA1_5>, C<RSA-OAEP-256>, C<RSA-OAEP>).

   $cek = rsa_key_unwrap($kek, $enc_cek, $alg);

   # params:
   #  $kek     .. RSA private key - Crypt::PK::RSA instance
   #  $enc_cek .. encrypted content encryption key
   #  $alg     .. algorithm name e.g. 'RSA-OAEP' (see rfc7518)

Values C<$enc_cek> and C<$cek> are binary octets.

=head2 ecdhaes_key_wrap

ECDH+AESKW key agreement/wrap algorithm as defined in L<https://tools.ietf.org/html/rfc7518#section-4.6>
(implements algorithms C<ECDH-ES+A128KW>, C<ECDH-ES+A192KW>, C<ECDH-ES+A256KW>).

   ($enc_cek, $epk) = ecdhaes_key_wrap($kek, $cek, $alg, $apu, $apv);

   # params:
   #  $kek     .. ECC public key - Crypt::PK::ECC|X25519 instance
   #  $cek     .. content encryption key
   #  $alg     .. algorithm name e.g. 'ECDH-ES+A256KW' (see rfc7518)
   # optional params:
   #  $apu     .. Agreement PartyUInfo Header Parameter
   #  $apv     .. Agreement PartyVInfo Header Parameter

Values C<$enc_cek> and C<$cek> are binary octets.

=head2 ecdhaes_key_unwrap

ECDH+AESKW key agreement/unwrap algorithm as defined in L<https://tools.ietf.org/html/rfc7518#section-4.6>
(implements algorithms C<ECDH-ES+A128KW>, C<ECDH-ES+A192KW>, C<ECDH-ES+A256KW>).

   $cek = ecdhaes_key_unwrap($kek, $enc_cek, $alg, $epk, $apu, $apv);

   # params:
   #  $kek     .. ECC private key - Crypt::PK::ECC|X25519 instance
   #  $enc_cek .. encrypted content encryption key
   #  $alg     .. algorithm name e.g. 'ECDH-ES+A256KW' (see rfc7518)
   #  $epk     .. ephemeral ECC public key (JWK/JSON or Crypt::PK::ECC|X25519)
   # optional params:
   #  $apu     .. Agreement PartyUInfo Header Parameter
   #  $apv     .. Agreement PartyVInfo Header Parameter

Values C<$enc_cek> and C<$cek> are binary octets.

=head2 ecdh_key_wrap

ECDH (Ephememeral Static) key agreement/wrap algorithm as defined in L<https://tools.ietf.org/html/rfc7518#section-4.6>
(implements algorithm C<ECDH-ES>).

   ($cek, $epk) = ecdh_key_wrap($kek, $enc, $apu, $apv);

   # params:
   #  $kek     .. ECC public key - Crypt::PK::ECC|X25519 instance
   #  $enc     .. encryption algorithm name e.g. 'A256GCM' (see rfc7518)
   # optional params:
   #  $apu     .. Agreement PartyUInfo Header Parameter
   #  $apv     .. Agreement PartyVInfo Header Parameter

Value C<$cek> - binary octets, C<$epk> JWK/JSON string with ephemeral ECC public key.

=head2 ecdh_key_unwrap

ECDH (Ephememeral Static) key agreement/unwrap algorithm as defined in L<https://tools.ietf.org/html/rfc7518#section-4.6>
(implements algorithm C<ECDH-ES>).

   $cek = ecdh_key_unwrap($kek, $enc, $epk, $apu, $apv);

   # params:
   #  $kek     .. ECC private key - Crypt::PK::ECC|X25519 instance
   #  $enc     .. encryption algorithm name e.g. 'A256GCM' (see rfc7518)
   #  $epk     .. ephemeral ECC public key (JWK/JSON or Crypt::PK::ECC|X25519)
   # optional params:
   #  $apu     .. Agreement PartyUInfo Header Parameter
   #  $apv     .. Agreement PartyVInfo Header Parameter

Value C<$cek> - binary octets.

=head1 SEE ALSO

L<Crypt::Cipher::AES>, L<Crypt::AuthEnc::GCM>, L<Crypt::PK::RSA>, L<Crypt::KeyDerivation>

=head1 LICENSE

This program is free software; you can redistribute it and/or modify it under the same terms as Perl itself.

=head1 COPYRIGHT

Copyright (c) 2015-2021 DCIT, a.s. L<https://www.dcit.cz> / Karel Miko
