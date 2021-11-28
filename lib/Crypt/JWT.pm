package Crypt::JWT;

use strict;
use warnings;

our $VERSION = '0.034';

use Exporter 'import';
our %EXPORT_TAGS = ( all => [qw(decode_jwt encode_jwt)] );
our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );
our @EXPORT = qw();

use Carp;
use Crypt::Misc qw(decode_b64u encode_b64u);
use JSON qw(decode_json encode_json);
use Crypt::PK::RSA;
use Crypt::PK::ECC;
use Crypt::PK::Ed25519;
use Crypt::PK::X25519;
use Crypt::PRNG qw(random_bytes);
use Crypt::KeyWrap ':all';
use Crypt::AuthEnc::GCM qw(gcm_encrypt_authenticate gcm_decrypt_verify);
use Crypt::Mac::HMAC qw(hmac);
use Compress::Raw::Zlib;
use Scalar::Util qw(looks_like_number);

# JWS: https://tools.ietf.org/html/rfc7515
# JWE: https://tools.ietf.org/html/rfc7516
# JWK: https://tools.ietf.org/html/rfc7517
# JWA: https://tools.ietf.org/html/rfc7518
# JWT: https://tools.ietf.org/html/rfc7519
# X25519/Ed25519 https://tools.ietf.org/html/rfc8037

sub _prepare_rsa_key {
  my ($key) = @_;
  croak "JWT: undefined RSA key" unless defined $key;
  croak "JWT: invalid RSA key (cannot be scalar)" unless ref $key;
  # we need Crypt::PK::RSA object
  return $key                       if ref($key) eq 'Crypt::PK::RSA';
  return Crypt::PK::RSA->new($key)  if ref($key) eq 'HASH' || ref($key) eq 'SCALAR';
  return Crypt::PK::RSA->new(@$key) if ref($key) eq 'ARRAY';
  # handle also: Crypt::OpenSSL::RSA, Crypt::X509, Crypt::OpenSSL::X509
  my $str;
  if (ref($key) eq 'Crypt::OpenSSL::RSA') {
    # https://metacpan.org/pod/Crypt::OpenSSL::RSA
    $str = $key->is_private ? $key->get_private_key_string : $key->get_public_key_string;
  }
  elsif (ref($key) =~ /^Crypt::(X509|OpenSSL::X509)$/) {
    # https://metacpan.org/pod/Crypt::X509
    # https://metacpan.org/pod/Crypt::OpenSSL::X509
    $str = $key->pubkey;
  }
  return Crypt::PK::RSA->new(\$str) if defined $str && !ref($str);
  croak "JWT: invalid RSA key";
}

sub _prepare_ecc_key {
  my ($key) = @_;
  croak "JWT: undefined ECC key" unless defined $key;
  croak "JWT: invalid ECC key (cannot be scalar)" unless ref $key;
  # we need Crypt::PK::ECC object
  return $key                       if ref($key) eq 'Crypt::PK::ECC';
  return Crypt::PK::ECC->new($key)  if ref($key) eq 'HASH' || ref($key) eq 'SCALAR';
  return Crypt::PK::ECC->new(@$key) if ref($key) eq 'ARRAY';
  croak "JWT: invalid ECC key";
}

sub _prepare_ed25519_key {
  my ($key) = @_;
  croak "JWT: undefined Ed25519 key" unless defined $key;
  croak "JWT: invalid Ed25519 key (cannot be scalar)" unless ref $key;
  # we need Crypt::PK::Ed25519 object
  return $key                           if ref($key) eq 'Crypt::PK::Ed25519';
  return Crypt::PK::Ed25519->new($key)  if ref($key) eq 'HASH' || ref($key) eq 'SCALAR';
  return Crypt::PK::Ed25519->new(@$key) if ref($key) eq 'ARRAY';
  croak "JWT: invalid Ed25519 key";
}

sub _prepare_ecdh_key {
  my ($key) = @_;
  croak "JWT: undefined ECDH key" unless defined $key;
  croak "JWT: invalid ECDH key (cannot be scalar)" unless ref $key;

  # we need Crypt::PK::X25519 or Crypt::PK::ECC object
  return $key if ref($key) =~ /^Crypt::PK::(ECC|X25519)$/;

  if (ref($key) eq 'HASH' || ref($key) eq 'SCALAR') {
    #HACK: this is ugly
    my $rv = eval { Crypt::PK::ECC->new($key) } || eval { Crypt::PK::X25519->new($key) };
    return $rv if defined $rv;
  }
  if (ref($key) eq 'ARRAY') {
    #HACK: this is ugly
    my $rv = eval { Crypt::PK::ECC->new(@$key) } || eval { Crypt::PK::X25519->new(@$key) };
    return $rv if defined $rv;
  }
  croak "JWT: invalid ECDH key";
}

sub _prepare_oct_key {
  my ($key) = @_;
  croak "JWT: undefined oct key" unless defined $key;
  if (ref $key eq 'HASH' && $key->{k} && $key->{kty} && $key->{kty} eq 'oct') {
    return decode_b64u($key->{k});
  }
  elsif (!ref $key) {
    return $key;
  }
  croak "JWT: invalid oct key";
}

sub _kid_lookup {
  my ($kid, $kid_keys, $alg) = @_;
  return undef if !defined $kid || !defined $alg;
  $kid_keys = eval { decode_json($kid_keys) } if $kid_keys && !ref $kid_keys;
  croak "JWT: kid_keys must be a HASHREF or a valid JSON/HASH" if ref $kid_keys ne 'HASH';
  my $found;
  if (exists $kid_keys->{keys} && ref $kid_keys->{keys} eq 'ARRAY') {
    #FORMAT: { keys => [ {kid=>'A', kty=>?, ...}, {kid=>'B', kty=>?, ...} ] }
    for (@{$kid_keys->{keys}}) {
      if ($_->{kid} && $_->{kty} && $_->{kid} eq $kid) {
        $found = $_;
        last;
      }
    }
  }
  else {
    #FORMAT: { hexadec1 => "----BEGIN CERTIFICATE-----...", hexadec2 => "----BEGIN CERTIFICATE-----..." }
    #e.g. https://www.googleapis.com/oauth2/v1/certs
    return \$kid_keys->{$kid} if $kid_keys->{$kid} && !ref $kid_keys->{$kid};
  }
  return undef if !$found;
  return $found if $found->{kty} eq 'oct' && $alg =~ /^(HS|dir|PBES2-HS|A)/;
  return $found if $found->{kty} eq 'OKP' && $alg =~ /^(EdDSA|ECDH-ES)/;
  return $found if $found->{kty} eq 'EC'  && $alg =~ /^(ES|EC)/;
  return $found if $found->{kty} eq 'RSA' && $alg =~ /^(RS|PS)/;
  croak "JWT: key type '$found->{kty}' cannot be used with alg '$alg'";
}

sub _b64u_to_hash {
  my $b64url = shift;
  return undef unless $b64url;
  my $json = decode_b64u($b64url);
  return undef unless $json;
  my $hash = eval { decode_json($json) };
  return undef unless ref $hash eq 'HASH';
  return $hash;
}

sub _add_claims {
  my ($payload, %args) = @_;
  #### claims (defined for JWS only)
  # "exp"   Expiration Time
  # "nbf"   Not Before
  # "iat"   Issued At
  # "iss"   Issuer
  # "sub"   Subject
  # "aud"   Audience
  # "jti"   JWT ID
  my $now = time;
  $payload->{iat} = $now                       if $args{auto_iat};
  $payload->{exp} = $now + $args{relative_exp} if defined $args{relative_exp};
  $payload->{nbf} = $now + $args{relative_nbf} if defined $args{relative_nbf};
}

sub _verify_claims {
  my ($payload, %args) = @_;

  return if $args{ignore_claims};

  if (ref($payload) ne 'HASH') {
    # https://github.com/DCIT/perl-Crypt-JWT/issues/31
    # payload needs to be decoded into a HASH for checking any verify_XXXX
    for my $claim (qw(exp nbf iat iss sub aud jti)) {
      if (defined $args{"verify_$claim"} && $args{"verify_$claim"} != 0) {
        croak "JWT: cannot check verify_$claim (payload not decoded JSON/HASH)";
      }
    }
    return; # nothing to check
  }

  my $leeway = $args{leeway} || 0;
  my $now = time;

  ### exp
  if(defined $payload->{exp}) {
    if (!defined $args{verify_exp} || $args{verify_exp}==1) {
      croak "JWT: exp claim check failed ($payload->{exp}/$leeway vs. $now)" if $payload->{exp} + $leeway <= $now;
    }
  }
  elsif ($args{verify_exp} && $args{verify_exp}==1) {
    croak "JWT: exp claim required but missing"
  }

  ### nbf
  if(defined $payload->{nbf}) {
    if (!defined $args{verify_nbf} || $args{verify_nbf}==1) {
      croak "JWT: nbf claim check failed ($payload->{nbf}/$leeway vs. $now)" if $payload->{nbf} - $leeway > $now;
    }
  }
  elsif ($args{verify_nbf} && $args{verify_nbf}==1) {
    croak "JWT: nbf claim required but missing"
  }

  ### iat
  if (exists $args{verify_iat}) { #default (non existing verify_iat) == no iat check
    if(defined $payload->{iat}) {
      if (!defined $args{verify_iat} || $args{verify_iat}==1) {
        croak "JWT: iat claim check failed ($payload->{iat}/$leeway vs. $now)" if $payload->{iat} - $leeway > $now;
      }
    }
    elsif ($args{verify_iat} && $args{verify_iat}==1) {
      croak "JWT: iat claim required but missing"
    }
  }

  ### iss, sub, aud, jti
  foreach my $claim (qw(iss sub aud jti)) {
    my $check = $args{"verify_$claim"};
    next unless (defined $check);

    if (exists $payload->{$claim}) {
      if (ref $check eq 'Regexp') {
        my $value = $payload->{$claim};
        $value = "" if !defined $value;
        croak "JWT: $claim claim re check failed" unless $value =~ $check;
      }
      elsif (ref $check eq 'CODE') {
        croak "JWT: $claim claim code check failed" unless $check->($payload->{$claim});
      }
      elsif (!ref $check) {
        my $value = $payload->{$claim};
        croak "JWT: $claim claim scalar check failed" unless defined $value && $value eq $check;
      }
      else {
        croak "JWT: verify_$claim must be Regexp, Scalar or CODE";
      }
    }
    else {
      croak "JWT: $claim claim required but missing"
    }
  }

}

sub _payload_zip {
  my ($payload, $header, $z) = @_;
  my @zip = ref $z eq 'ARRAY' ? @$z : ($z);
  if ($zip[0] eq 'deflate') {
    my $level = defined $zip[1] ? $zip[1] : 6;
    $header->{zip} = "DEF";
    my $d = Compress::Raw::Zlib::Deflate->new(-Bufsize => 1024, -WindowBits => -&MAX_WBITS(), -AppendOutput => 1, -Level => $level );
    my $output = '';
    $d->deflate($payload, $output) == Z_OK or croak "JWT: deflate failed";
    $d->flush($output) == Z_OK             or croak "JWT: deflate/flush failed";
    croak "JWT: deflate/output failed" unless $output;
    $payload = $output;
  }
  else {
    croak "JWT: unknown zip method '$zip[0]'";
  }
  return $payload;
}

sub _payload_unzip {
  my ($payload, $z) = @_;
  if ($z eq "DEF") {
    my $d = Compress::Raw::Zlib::Inflate->new(-Bufsize => 1024, -WindowBits => -&MAX_WBITS());
    my $output = '';
    $d->inflate($payload, $output);
    croak "JWT: inflate failed" unless $output;
    $payload = $output;
  }
  else {
    croak "JWT: unknown zip method '$z'";
  }
  return $payload;
}

sub _payload_enc {
  my ($payload) = @_;
  if (ref($payload) =~ /^(HASH|ARRAY)$/) {
    $payload = JSON->new->utf8->canonical->encode($payload);
  }
  else {
    utf8::downgrade($payload, 1) or croak "JWT: payload cannot contain wide character";
  }
  return $payload;
}

sub _payload_dec {
  my ($payload, $decode_payload) = @_;
  return $payload if defined $decode_payload && $decode_payload == 0;
  my $de = $payload;
  $de = eval { decode_json($de) };
  if ($decode_payload) {
    croak "JWT: payload not a valid JSON" unless $de;
    return $de;
  }
  else {
    return defined $de ? $de : $payload;
  }
}

sub _encrypt_jwe_cek {
  my ($key, $hdr) = @_;
  my $alg = $hdr->{alg};
  my $enc = $hdr->{enc};

  if ($alg eq 'dir') {
    return (_prepare_oct_key($key), '');
  }

  my $cek;
  my $ecek;
  if ($enc =~ /^A(128|192|256)GCM/) {
    $cek = random_bytes($1/8);
  }
  elsif ($enc =~ /^A(128|192|256)CBC/) {
    $cek = random_bytes(2*$1/8);
  }

  if ($alg =~ /^A(128|192|256)KW$/) {
    $ecek = aes_key_wrap(_prepare_oct_key($key), $cek);
    return ($cek, $ecek);
  }
  elsif ($alg =~ /^A(128|192|256)GCMKW$/) {
    my ($t, $i);
    ($ecek, $t, $i) = gcm_key_wrap(_prepare_oct_key($key), $cek);
    $hdr->{tag} = encode_b64u($t);
    $hdr->{iv}  = encode_b64u($i);
    return ($cek, $ecek);
  }
  elsif ($alg =~ /^PBES2-HS(512|384|256)\+A(128|192|256)KW$/) {
    my $len = looks_like_number($hdr->{p2s}) && $hdr->{p2s} >= 8 && $hdr->{p2s} <= 9999 ? $hdr->{p2s} : 16;
    my $salt = random_bytes($len);
    my $iter = looks_like_number($hdr->{p2c}) ? $hdr->{p2c} : 5000;
    $ecek = pbes2_key_wrap(_prepare_oct_key($key), $cek, $alg, $salt, $iter);
    $hdr->{p2s} = encode_b64u($salt);
    $hdr->{p2c} = $iter;
    return ($cek, $ecek);
  }
  elsif ($alg =~ /^RSA(-OAEP|-OAEP-256|1_5)$/) {
    $key = _prepare_rsa_key($key);
    $ecek = rsa_key_wrap($key, $cek, $alg);
    return ($cek, $ecek);
  }
  elsif ($alg =~ /^ECDH-ES\+A(128|192|256)KW$/) {
    $key = _prepare_ecdh_key($key);
    ($ecek, $hdr->{epk}) = ecdhaes_key_wrap($key, $cek, $alg, $hdr->{apu}, $hdr->{apv});
    return ($cek, $ecek);
  }
  elsif ($alg eq 'ECDH-ES') {
    $key = _prepare_ecdh_key($key);
    ($cek, $hdr->{epk}) = ecdh_key_wrap($key, $enc, $hdr->{apu}, $hdr->{apv});
    return ($cek, '');
  }
  croak "JWE: unknown alg '$alg'";
}

sub _decrypt_jwe_cek {
  my ($ecek, $key, $hdr) = @_;
  my $alg = $hdr->{alg};
  my $enc = $hdr->{enc};

  if ($alg eq 'dir') {
    return _prepare_oct_key($key);
  }
  elsif ($alg =~ /^A(128|192|256)KW$/) {
    return aes_key_unwrap(_prepare_oct_key($key), $ecek);
  }
  elsif ($alg =~ /^A(128|192|256)GCMKW$/) {
    return gcm_key_unwrap(_prepare_oct_key($key), $ecek, decode_b64u($hdr->{tag}), decode_b64u($hdr->{iv}));
  }
  elsif ($alg =~ /^PBES2-HS(512|384|256)\+A(128|192|256)KW$/) {
    return pbes2_key_unwrap(_prepare_oct_key($key), $ecek, $alg, decode_b64u($hdr->{p2s}), $hdr->{p2c});
  }
  elsif ($alg =~ /^RSA(-OAEP|-OAEP-256|1_5)$/) {
    $key = _prepare_rsa_key($key);
    return rsa_key_unwrap($key, $ecek, $alg);
  }
  elsif ($alg =~ /^ECDH-ES\+A(128|192|256)KW$/) {
    $key = _prepare_ecdh_key($key);
    return ecdhaes_key_unwrap($key, $ecek, $alg, $hdr->{epk}, $hdr->{apu}, $hdr->{apv});
  }
  elsif ($alg eq 'ECDH-ES') {
    $key = _prepare_ecdh_key($key);
    return ecdh_key_unwrap($key, $enc, $hdr->{epk}, $hdr->{apu}, $hdr->{apv});
  }
  croak "JWE: unknown alg '$alg'";
}

sub _encrypt_jwe_payload {
  my ($cek, $enc, $b64u_header, $b64u_aad, $payload) = @_;
  my $aad = defined $b64u_aad ? "$b64u_header.$b64u_aad" : $b64u_header;
  if ($enc =~ /^A(128|192|256)GCM$/) {
    # https://tools.ietf.org/html/rfc7518#section-5.3
    my $len1 = $1/8;
    my $len2 = length($cek);
    croak "JWE: wrong AES key length ($len1 vs. $len2) for $enc" unless $len1 == $len2;
    my $iv = random_bytes(12); # for AESGCM always 12 (96 bits)
    my ($ct, $tag) = gcm_encrypt_authenticate('AES', $cek, $iv, $aad, $payload);
    return ($ct, $iv, $tag);
  }
  elsif ($enc =~ /^A(128|192|256)CBC-HS(256|384|512)$/) {
    # https://tools.ietf.org/html/rfc7518#section-5.2
    my ($size, $hash) = ($1/8, "SHA$2");
    my $key_len = length($cek) / 2;
    my $mac_key = substr($cek, 0, $key_len);
    my $aes_key = substr($cek, $key_len, $key_len);
    croak "JWE: wrong AES key length ($key_len vs. $size)" unless $key_len == $size;
    my $iv = random_bytes(16); # for AES always 16
    my $m = Crypt::Mode::CBC->new('AES');
    my $ct = $m->encrypt($payload, $aes_key, $iv);
    my $aad_len = length($aad);
    my $mac_input = $aad . $iv . $ct . pack('N2', ($aad_len / 2147483647)*8, ($aad_len % 2147483647)*8);
    my $mac = hmac($hash, $mac_key, $mac_input);
    my $sig_len = length($mac) / 2;
    my $sig = substr($mac, 0, $sig_len);
    return ($ct, $iv, $sig);
  }
  croak "JWE: unsupported enc '$enc'";
}

sub _decrypt_jwe_payload {
  my ($cek, $enc, $aad, $ct, $iv, $tag) = @_;
  if ($enc =~ /^A(128|192|256)GCM$/) {
    # https://tools.ietf.org/html/rfc7518#section-5.3
    my $len1 = $1/8;
    my $len2 = length($cek);
    croak "JWE: wrong AES key length ($len1 vs. $len2) for $enc" unless $len1 == $len2;
    return gcm_decrypt_verify('AES', $cek, $iv, $aad, $ct, $tag);
  }
  elsif ($enc =~ /^A(128|192|256)CBC-HS(256|384|512)$/) {
    # https://tools.ietf.org/html/rfc7518#section-5.2
    my ($size, $hash) = ($1/8, "SHA$2");
    my $key_len = length($cek) / 2;
    my $mac_key = substr($cek, 0, $key_len);
    my $aes_key = substr($cek, $key_len, $key_len);
    croak "JWE: wrong AES key length ($key_len vs. $size)" unless $key_len == $size;
    my $aad_len = length($aad); # AAD == original encoded header
    my $mac_input = $aad . $iv . $ct . pack('N2', ($aad_len / 2147483647)*8, ($aad_len % 2147483647)*8);
    my $mac = hmac($hash, $mac_key, $mac_input);
    my $sig_len = length($mac) / 2;
    my $sig = substr($mac, 0, $sig_len);
    croak "JWE: tag mismatch" unless $sig eq $tag;
    my $m = Crypt::Mode::CBC->new('AES');
    my $pt = $m->decrypt($ct, $aes_key, $iv);
    return $pt;
  }
  croak "JWE: unsupported enc '$enc'";
}

sub _encode_jwe {
  my %args = @_;
  my $payload = $args{payload};
  my $alg     = $args{alg};
  my $enc     = $args{enc};
  my $header  = $args{extra_headers} ? \%{$args{extra_headers}} : {};
  croak "JWE: missing 'enc'" if !defined $enc;
  croak "JWE: missing 'payload'" if !defined $payload;
  # add claims to payload
  _add_claims($payload, %args) if ref $payload eq 'HASH';
  # serialize payload
  $payload = _payload_enc($payload);
  # compress payload
  $payload = _payload_zip($payload, $header, $args{zip}) if $args{zip}; # may set some header items
  # prepare header
  $header->{alg} = $alg;
  $header->{enc} = $enc;
  # key
  croak "JWE: missing 'key'" if !$args{key};
  my $key = defined $args{keypass} ? [$args{key}, $args{keypass}] : $args{key};
  # prepare cek
  my ($cek, $ecek) = _encrypt_jwe_cek($key, $header); # adds some header items
  # encode header
  my $json_header = encode_json($header);
  my $b64u_header = encode_b64u($json_header);
  my $b64u_aad    = defined $args{aad} ? encode_b64u($args{aad}) : undef;
  # encrypt payload
  my ($ct, $iv, $tag) = _encrypt_jwe_payload($cek, $enc, $b64u_header, $b64u_aad, $payload);
  # return token parts
  return ( $b64u_header,
           encode_b64u($ecek),
           encode_b64u($iv),
           encode_b64u($ct),
           encode_b64u($tag),
           $b64u_aad);
}

sub _decode_jwe {
  my ($b64u_header, $b64u_ecek, $b64u_iv, $b64u_ct, $b64u_tag, $b64u_aad, $unprotected, $shared_unprotected, %args) = @_;
  my $header = _b64u_to_hash($b64u_header);
  my $ecek   = decode_b64u($b64u_ecek);
  my $ct     = decode_b64u($b64u_ct);
  my $iv     = decode_b64u($b64u_iv);
  my $tag    = decode_b64u($b64u_tag);
  croak "JWE: invalid header part" if $b64u_header && !$header;
  croak "JWE: invalid ecek part"   if $b64u_ecek   && !$ecek;
  croak "JWE: invalid ct part"     if $b64u_ct     && !$ct;
  croak "JWE: invalid iv part"     if $b64u_iv     && !$iv;
  croak "JWE: invalid tag part"    if $b64u_tag    && !$tag;

  my $key;
  if (exists $args{key}) {
    $key = defined $args{keypass} ? [$args{key}, $args{keypass}] : $args{key};
  }
  elsif (exists $args{kid_keys}) {
    # BEWARE: stricter approach since 0.023
    # when 'kid_keys' specified it croaks if header doesn't contain 'kid' value or if 'kid' wasn't found in 'kid_keys'
    my $k = _kid_lookup($header->{kid}, $args{kid_keys}, $header->{alg});
    croak "JWE: kid_keys lookup failed" if !defined $k;
    $key = $k;
  }
  croak "JWE: missing key" if !defined $key;

  my $aa = $args{accepted_alg};
  if (ref($aa) eq 'Regexp') {
    croak "JWE: alg '$header->{alg}' does not match accepted_alg" if $header->{alg} !~ $aa;
  }
  elsif ($aa && (ref($aa) eq 'ARRAY' || !ref($aa))) {
    my %acca = ref $aa ? map { $_ => 1 } @$aa : ( $aa => 1 );
    croak "JWE: alg '$header->{alg}' not in accepted_alg" if !$acca{$header->{alg}};
  }

  my $ae = $args{accepted_enc};
  if (ref($ae) eq 'Regexp') {
    croak "JWE: enc '$header->{enc}' does not match accepted_enc" if $header->{enc} !~ $ae;
  }
  elsif ($ae && (ref($ae) eq 'ARRAY' || !ref($ae))) {
    my %acce = ref $ae ? map { $_ => 1 } @$ae : ( $ae => 1 );
    croak "JWE: enc '$header->{enc}' not in accepted_enc" if !$acce{$header->{enc}};
  }

  $header = { %$shared_unprotected, %$unprotected, %$header }; # merge headers
  my $cek = _decrypt_jwe_cek($ecek, $key, $header);
  my $aad = defined $b64u_aad ? "$b64u_header.$b64u_aad" : $b64u_header;
  my $payload = _decrypt_jwe_payload($cek, $header->{enc}, $aad, $ct, $iv, $tag);
  $payload = _payload_unzip($payload, $header->{zip}) if $header->{zip};
  $payload = _payload_dec($payload, $args{decode_payload});
  _verify_claims($payload, %args); # croaks on error
  return ($header, $payload);
}

sub _sign_jws {
  my ($b64u_header, $b64u_payload, $alg, $key) = @_;
  return '' if $alg eq 'none'; # no integrity
  my $sig;
  my $data = "$b64u_header.$b64u_payload";
  if ($alg =~ /^HS(256|384|512)$/) { # HMAC integrity
    $key = _prepare_oct_key($key);
    $sig = hmac("SHA$1", $key, $data);
  }
  elsif ($alg =~ /^RS(256|384|512)/) { # RSA+PKCS1-V1_5 signatures
    my $pk = _prepare_rsa_key($key);
    $sig  = $pk->sign_message($data, "SHA$1", 'v1.5');
  }
  elsif ($alg =~ /^PS(256|384|512)/) { # RSA+PSS signatures
    my $hash = "SHA$1";
    my $hashlen = $1/8;
    my $pk = _prepare_rsa_key($key);
    $sig  = $pk->sign_message($data, $hash, 'pss', $hashlen);
  }
  elsif ($alg =~ /^ES(256|256K|384|512)$/) { # ECDSA signatures
    my $hash = {ES256 => 'SHA256', ES256K => 'SHA256', ES384 => 'SHA384', ES512 => 'SHA512'}->{$alg};
    my $pk = _prepare_ecc_key($key);
    $sig  = $pk->sign_message_rfc7518($data, $hash);
  }
  elsif ($alg eq 'EdDSA') { # Ed25519 signatures
    my $pk = _prepare_ed25519_key($key);
    $sig  = $pk->sign_message($data);
  }
  return encode_b64u($sig);
}

sub _verify_jws {
  my ($b64u_header, $b64u_payload, $b64u_sig, $alg, $key) = @_;
  my $sig = decode_b64u($b64u_sig);
  croak "JWS: invalid sig part" if $b64u_sig && !$sig;
  my $data = "$b64u_header.$b64u_payload";

  if ($alg eq 'none' ) { # no integrity
    return 1;
  }
  elsif ($alg =~ /^HS(256|384|512)$/) { # HMAC integrity
    $key = _prepare_oct_key($key);
    return 1 if $sig eq hmac("SHA$1", $key, $data);
  }
  elsif ($alg =~ /^RS(256|384|512)/) { # RSA+PKCS1-V1_5 signatures
    my $hash = "SHA$1";
    my $pk = _prepare_rsa_key($key);
    return 1 if $pk->verify_message($sig, $data, $hash, 'v1.5');
  }
  elsif ($alg =~ /^PS(256|384|512)/) { # RSA+PSS signatures
    my $hash = "SHA$1";
    my $hashlen = $1/8;
    my $pk = _prepare_rsa_key($key);
    return 1 if $pk->verify_message($sig, $data, $hash, 'pss', $hashlen);
  }
  elsif ($alg =~ /^ES(256|256K|384|512)$/) { # ECDSA signatures
    my $hash = {ES256 => 'SHA256', ES256K => 'SHA256', ES384 => 'SHA384', ES512 => 'SHA512'}->{$alg};
    my $pk = _prepare_ecc_key($key);
    return 1 if $pk->verify_message_rfc7518($sig, $data, $hash);
  }
  elsif ($alg eq 'EdDSA') { # Ed25519 signatures
    my $pk = _prepare_ed25519_key($key);
    return 1 if $pk->verify_message($sig, $data);
  }
  return 0;
}

sub _encode_jws {
  my %args = @_;
  my $payload = $args{payload};
  my $alg     = $args{alg};
  my $header  = $args{extra_headers} ? \%{$args{extra_headers}} : {};
  croak "JWS: missing 'payload'" if !defined $payload;
  croak "JWS: alg 'none' not allowed" if $alg eq 'none' && !$args{allow_none};
  # add claims to payload
  _add_claims($payload, %args) if ref $payload eq 'HASH';
  # serialize payload
  $payload = _payload_enc($payload);
  # compress payload
  $payload = _payload_zip($payload, $header, $args{zip}) if $args{zip}; # may set some header items
  # encode payload
  my $b64u_payload = encode_b64u($payload);
  # prepare header
  $header->{alg} = $alg;
  # encode header
  my $json_header = encode_json($header);
  my $b64u_header = encode_b64u($json_header);
  # key
  croak "JWS: missing 'key'" if !$args{key} && $alg ne 'none';
  my $key = defined $args{keypass} ? [$args{key}, $args{keypass}] : $args{key};
  # sign header
  my $b64u_signature = _sign_jws($b64u_header, $b64u_payload, $alg, $key);
  return ($b64u_header, $b64u_payload, $b64u_signature);
}

sub _decode_jws {
  my ($b64u_header, $b64u_payload, $b64u_sig, $unprotected_header, %args) = @_;
  my $header = _b64u_to_hash($b64u_header);
  croak "JWS: invalid header part" if $b64u_header && !$header;
  $unprotected_header = {} if ref $unprotected_header ne 'HASH';

  if (!$args{ignore_signature}) {
    my $alg = $header->{alg};
    croak "JWS: missing header 'alg'" unless $alg;
    croak "JWS: alg 'none' not allowed" if $alg eq 'none' && !$args{allow_none};
    croak "JWS: alg 'none' expects no signature" if $alg eq 'none' && defined $b64u_sig && length($b64u_sig) > 0;

    my $aa = $args{accepted_alg};
    if (ref $aa eq 'Regexp') {
      croak "JWS: alg '$alg' does not match accepted_alg" if $alg !~ $aa;
    }
    elsif (ref $aa eq 'ARRAY') {
      my %acca = map { $_ => 1 } @$aa;
      croak "JWS: alg '$alg' not in accepted_alg" if !$acca{$alg};
    }
    elsif (defined $aa) {
      croak "JWS: alg '$alg' not accepted_alg" if $aa ne $alg;
    }

    if ($alg ne 'none') {
      my $key;
      if (exists $args{key}) {
        $key = defined $args{keypass} ? [$args{key}, $args{keypass}] : $args{key};
      }
      elsif (exists $args{kid_keys}) {
        # BEWARE: stricter approach since 0.023
        # when 'kid_keys' specified it croaks if header doesn't contain 'kid' value or if 'kid' wasn't found in 'kid_keys'
        my $kid = exists $header->{kid} ? $header->{kid} : $unprotected_header->{kid};
        my $k = _kid_lookup($kid, $args{kid_keys}, $alg);
        croak "JWS: kid_keys lookup failed" if !defined $k;
        $key = $k;
      }
      elsif ($args{key_from_jwk_header}) {
        # BEWARE: stricter approach since 0.023
        # - header 'jwk' is by default ignored (unless given: key_from_jwk_header => 1)
        # - only RSA/ECDSA public keys are accepted
        my $k = $header->{jwk};
        croak "JWS: jwk header does not contain a key" if !defined $k || ref($k) ne 'HASH' || !defined $k->{kty};
        croak "JWS: jwk header allowed only for RSA/ECDSA" if $alg !~ /^(RS|PS|ES)/ || $k->{kty} !~ /^(RSA|EC)$/;
        croak "JWS: jwk header must be a public key" if $k->{d} || $k->{p} || $k->{q} || $k->{dp} || $k->{dq} || $k->{qi};
        $key = $k;
      }
      croak "JWS: missing key" if !defined $key;

      my $valid = _verify_jws($b64u_header, $b64u_payload, $b64u_sig, $alg, $key);
      croak "JWS: invalid signature" if !$valid;
    }
  }
  my $payload = decode_b64u($b64u_payload);
  croak "JWS: invalid payload part" if $b64u_payload && !$payload;
  $payload = _payload_unzip($payload, $header->{zip}) if $header->{zip};
  $payload = _payload_dec($payload, $args{decode_payload});
  _verify_claims($payload, %args); # croaks on error
  $header = { %$unprotected_header, %$header }; # merge headers
  return ($header, $payload);
}

sub encode_jwt {
  my %args = @_;

  croak "JWT: missing 'alg'" unless $args{alg};
  my $ser = $args{serialization} || 'compact';
  if ($args{alg} =~ /^(none|EdDSA|(HS|RS|PS)(256|384|512)|ES(256|256K|384|512))$/) {
    ###JWS
    my ($b64u_header, $b64u_payload, $b64u_signature) = _encode_jws(%args);
    if ($ser eq 'compact') { # https://tools.ietf.org/html/rfc7515#section-7.1
      croak "JWT: cannot use 'unprotected_headers' with compact serialization" if defined $args{unprotected_headers};
      return "$b64u_header.$b64u_payload.$b64u_signature";
    }
    elsif ($ser eq 'flattened') { # https://tools.ietf.org/html/rfc7515#section-7.2.2
      my $token = { protected => $b64u_header, payload => $b64u_payload, signature => $b64u_signature };
      $token->{header} = \%{$args{unprotected_headers}} if ref $args{unprotected_headers} eq 'HASH';
      return encode_json($token);
    }
    else {
      croak "JWT: unsupported JWS serialization '$ser'";
    }
  }
  elsif ($args{alg} =~ /^(dir|A(128|192|256)KW|A(128|192|256)GCMKW|PBES2-(HS256\+A128KW|HS384\+A192KW|HS512\+A256KW)|RSA-OAEP|RSA-OAEP-256|RSA1_5|ECDH-ES\+A(128|192|256)KW|ECDH-ES)$/) {
    ### JWE
    my ($b64u_header, $b64u_ecek, $b64u_iv, $b64u_ct, $b64u_tag, $b64u_aad) = _encode_jwe(%args);
    if ($ser eq 'compact') { # https://tools.ietf.org/html/rfc7516#section-7.1
      croak "JWT: cannot use 'aad' with compact serialization" if defined $args{aad};
      croak "JWT: cannot use 'unprotected_headers' with compact serialization" if defined $args{unprotected_headers};
      croak "JWT: cannot use 'shared_unprotected_headers' with compact serialization" if defined $args{shared_unprotected_headers};
      return "$b64u_header.$b64u_ecek.$b64u_iv.$b64u_ct.$b64u_tag";
    }
    elsif ($ser eq 'flattened') { # https://tools.ietf.org/html/rfc7516#section-7.2.2
      my $token = {
        protected     => $b64u_header,
        encrypted_key => $b64u_ecek,
        iv            => $b64u_iv,
        ciphertext    => $b64u_ct,
        tag           => $b64u_tag,
      };
      # header: JWE Per-Recipient Unprotected Header when the JWE Per-Recipient Unprotected Header
      $token->{header} = \%{$args{unprotected_headers}} if ref $args{unprotected_headers} eq 'HASH';
      # unprotected: JWE Shared Unprotected Header
      $token->{unprotected} = \%{$args{shared_unprotected_headers}} if ref $args{shared_unprotected_headers} eq 'HASH';
      # aad: Additional Authenticated Data (AAD)
      $token->{aad} = $b64u_aad if defined $b64u_aad;
      return encode_json($token);
    }
    else {
      croak "JWT: unsupported JWE serialization '$ser'";
    }
  }
  else {
      croak "JWT: unexpected alg '$args{alg}'";
  }
}

sub decode_jwt {
  my %args = @_;
  my ($header, $payload);

  if (!$args{token}) {
    croak "JWT: missing token";
  }
  elsif ($args{token} =~ /^([a-zA-Z0-9_-]+)=*\.([a-zA-Z0-9_-]*)=*\.([a-zA-Z0-9_-]+)=*\.([a-zA-Z0-9_-]+)=*\.([a-zA-Z0-9_-]+)=*$/) {
    # JWE token (5 segments)
    ($header, $payload) = _decode_jwe($1, $2, $3, $4, $5, undef, {}, {}, %args);
  }
  elsif ($args{token} =~ /^([a-zA-Z0-9_-]+)=*\.([a-zA-Z0-9_-]+)=*\.([a-zA-Z0-9_-]*)=*$/) {
    # JWS token (3 segments)
    ($header, $payload) = _decode_jws($1, $2, $3, {}, %args);
  }
  elsif ($args{token} =~ /^\s*\{.*?\}\s*$/s) {
    my $hash = decode_json($args{token});
    if (defined $hash->{payload} && $hash->{protected}) {
      # Flattened JWS JSON Serialization
      ($header, $payload) = _decode_jws($hash->{protected}, $hash->{payload}, $hash->{signature}, $hash->{header}, %args);
    }
    elsif ($hash->{ciphertext} && $hash->{protected}) {
      # Flattened JWE JSON Serialization
      ($header, $payload) = _decode_jwe($hash->{protected}, $hash->{encrypted_key}, $hash->{iv}, $hash->{ciphertext}, $hash->{tag}, $hash->{aad}, $hash->{header}, $hash->{unprotected}, %args);
    }
    else {
      croak "JWT: unsupported JWS/JWT JSON Serialization";
    }
  }
  else {
    croak "JWT: invalid token format";
  }
  return ($header, $payload) if $args{decode_header};
  return $payload;
}

1;

#### URLs
# https://metacpan.org/pod/JSON::WebToken
# https://metacpan.org/pod/Mojo::JWT
# https://bitbucket.org/b_c/jose4j/wiki/JWE%20Examples
# https://bitbucket.org/b_c/jose4j/wiki/JWS%20Examples
# https://github.com/dvsekhvalnov/jose-jwt/tree/master/JWT/jwe
# https://github.com/progrium/ruby-jwt
# https://github.com/jpadilla/pyjwt/

=pod

=head1 NAME

Crypt::JWT - JSON Web Token (JWT, JWS, JWE) as defined by RFC7519, RFC7515, RFC7516

=head1 SYNOPSIS

   # encoding
   use Crypt::JWT qw(encode_jwt);
   my $jws_token = encode_jwt(payload=>$data, alg=>'HS256', key=>'secret');
   my $jwe_token = encode_jwt(payload=>$data, alg=>'PBES2-HS256+A128KW', enc=>'A128GCM', key=>'secret');

   # decoding
   use Crypt::JWT qw(decode_jwt);
   my $data1 = decode_jwt(token=>$jws_token, key=>'secret');
   my $data2 = decode_jwt(token=>$jwe_token, key=>'secret');

=head1 DESCRIPTION

Implements B<JSON Web Token (JWT)> - L<https://tools.ietf.org/html/rfc7519>.
The implementation covers not only B<JSON Web Signature (JWS)> - L<https://tools.ietf.org/html/rfc7515>,
but also B<JSON Web Encryption (JWE)> - L<https://tools.ietf.org/html/rfc7516>.

The module implements B<all (100%) algorithms> defined in L<https://tools.ietf.org/html/rfc7518> - B<JSON Web Algorithms (JWA)>.

This module supports B<Compact JWS/JWE> and B<Flattened JWS/JWE JSON> serialization, general JSON serialization is not supported yet.

=head1 EXPORT

Nothing is exported by default.

You can export selected functions:

  use Crypt::JWT qw(decode_jwt encode_jwt);

Or all of them at once:

  use Crypt::JWT ':all';

=head1 FUNCTIONS

=head2 decode_jwt

 my $data = decode_jwt(%named_args);

Named arguments:

=over

=item token

Mandatory argument, a string with either JWS or JWE JSON Web Token.

 ### JWS token example (3 segments)
 $t = "eyJhbGciOiJIUzI1NiJ9.dGVzdA.ujBihtLSr66CEWqN74SpLUkv28lra_CeHnxLmLNp4Jo";
 my $data = decode_jwt(token=>$t, key=>$k);

 ### JWE token example (5 segments)
 $t = "eyJlbmMiOiJBMTI4R0NNIiwiYWxnIjoiQTEyOEtXIn0.UusxEbzhGkORxTRq0xkFKhvzPrXb9smw.VGfOuq0Fxt6TsdqLZUpnxw.JajIQQ.pkKZ7MHS0XjyGmRsqgom6w";
 my $data = decode_jwt(token=>$t, key=>$k);

=item key

A key used for token decryption (JWE) or token signature validation (JWS).
The value depends on the C<alg> token header value.

 JWS alg header      key value
 ------------------  ----------------------------------
 none                no key required
 HS256               string (raw octects) of any length (or perl HASH ref with JWK, kty=>'oct')
 HS384               dtto
 HS512               dtto
 RS256               public RSA key, perl HASH ref with JWK key structure,
                     a reference to SCALAR string with PEM or DER or JSON/JWK data,
                     object: Crypt::PK::RSA, Crypt::OpenSSL::RSA, Crypt::X509 or Crypt::OpenSSL::X509
 RS384               public RSA key, see RS256
 RS512               public RSA key, see RS256
 PS256               public RSA key, see RS256
 PS384               public RSA key, see RS256
 PS512               public RSA key, see RS256
 ES256               public ECC key, perl HASH ref with JWK key structure,
                     a reference to SCALAR string with PEM or DER or JSON/JWK data,
                     an instance of Crypt::PK::ECC
 ES256K              public ECC key, see ES256
 ES384               public ECC key, see ES256
 ES512               public ECC key, see ES256
 EdDSA               public Ed25519 key

 JWE alg header      key value
 ------------------  ----------------------------------
 dir                 string (raw octects) or perl HASH ref with JWK, kty=>'oct', length depends on 'enc' algorithm
 A128KW              string (raw octects) 16 bytes (or perl HASH ref with JWK, kty=>'oct')
 A192KW              string (raw octects) 24 bytes (or perl HASH ref with JWK, kty=>'oct')
 A256KW              string (raw octects) 32 bytes (or perl HASH ref with JWK, kty=>'oct')
 A128GCMKW           string (raw octects) 16 bytes (or perl HASH ref with JWK, kty=>'oct')
 A192GCMKW           string (raw octects) 24 bytes (or perl HASH ref with JWK, kty=>'oct')
 A256GCMKW           string (raw octects) 32 bytes (or perl HASH ref with JWK, kty=>'oct')
 PBES2-HS256+A128KW  string (raw octects) of any length (or perl HASH ref with JWK, kty=>'oct')
 PBES2-HS384+A192KW  string (raw octects) of any length (or perl HASH ref with JWK, kty=>'oct')
 PBES2-HS512+A256KW  string (raw octects) of any length (or perl HASH ref with JWK, kty=>'oct')
 RSA-OAEP            private RSA key, perl HASH ref with JWK key structure,
                     a reference to SCALAR string with PEM or DER or JSON/JWK data,
                     an instance of Crypt::PK::RSA or Crypt::OpenSSL::RSA
 RSA-OAEP-256        private RSA key, see RSA-OAEP
 RSA1_5              private RSA key, see RSA-OAEP
 ECDH-ES             private ECC or X25519 key, perl HASH ref with JWK key structure,
                     a reference to SCALAR string with PEM or DER or JSON/JWK data,
                     an instance of Crypt::PK::ECC
 ECDH-ES+A128KW      private ECC or X25519 key, see ECDH-ES
 ECDH-ES+A192KW      private ECC or X25519 key, see ECDH-ES
 ECDH-ES+A256KW      private ECC or X25519 key, see ECDH-ES

Example using the key from C<jwk> token header:

 my $data = decode_jwt(token=>$t, key_from_jwk_header=>1);
 my ($header, $data) = decode_jwt(token=>$t, decode_header=>1, key_from_jwk_header=>1);

Examples with raw octet keys:

 #string
 my $data = decode_jwt(token=>$t, key=>'secretkey');
 #binary key
 my $data = decode_jwt(token=>$t, key=>pack("H*", "788A6E38F36B7596EF6A669E94"));
 #perl HASH ref with JWK structure (key type 'oct')
 my $data = decode_jwt(token=>$t, key=>{kty=>'oct', k=>"GawgguFyGrWKav7AX4VKUg"});

Examples with RSA keys:

 my $pem_key_string = <<'EOF';
 -----BEGIN PRIVATE KEY-----
 MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCoVm/Sl5r+Ofky
 jioRSZK26GW6WyjyfWKddsSi13/NOtCn0rRErSF/u3QrgGMpWFqKohqbi1VVC+SZ
 ...
 8c1vm2YFafgdkSk9Qd1oU2Fv1aOQy4VovOFzJ3CcR+2r7cbRfcpLGnintHtp9yek
 02p+d5g4OChfFNDhDtnIqjvY
 -----END PRIVATE KEY-----
 EOF

 my $jwk_key_json_string = '{"kty":"RSA","n":"0vx7agoebG...L6tSoc_BJECP","e":"AQAB"}';

 #a reference to SCALAR string with PEM or DER or JSON/JWK data,
 my $data = decode_jwt(token=>$t, key=>\$pem_key_string);
 my $data = decode_jwt(token=>$t, key=>\$der_key_string);
 my $data = decode_jwt(token=>$t, key=>\$jwk_key_json_string);

 #instance of Crypt::PK::RSA
 my $data = decode_jwt(token=>$t, key=>Crypt::PK::RSA->new('keyfile.pem'));
 my $data = decode_jwt(token=>$t, key=>Crypt::PK::RSA->new(\$pem_key_string));

 #instance of Crypt::OpenSSL::RSA
 my $data = decode_jwt(token=>$t, key=>Crypt::OpenSSL::RSA->new_private_key($pem_key_string));

 #instance of Crypt::X509 (public key only)
 my $data = decode_jwt(token=>$t, key=>Crypt::X509->new(cert=>$cert));

 #instance of Crypt::OpenSSL::X509 (public key only)
 my $data = decode_jwt(token=>$t, key=>Crypt::OpenSSL::X509->new_from_file('cert.pem'));
 my $data = decode_jwt(token=>$t, key=>Crypt::OpenSSL::X509->new_from_string($cert));

 #perl HASH ref with JWK structure (key type 'RSA')
 my $rsa_priv = {
   kty => "RSA",
   n   => "0vx7agoebGcQSuuPiLJXZpt...eZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
   e   => "AQAB",
   d   => "X4cTteJY_gn4FYPsXB8rdXi...FLN5EEaG6RoVH-HLKD9Mdx5ooGURknhnrRwUkC7h5fJLMWbFAKLWY2v7B6NqSzUvx0_YSf",
   p   => "83i-7IvMGXoMXCskv73TKr8...Z27zvoj6pbUQyLPBQxtPnwD20-60eTmD2ujMt5PoMrm8RmNhVWtjjMmMjOpSicFHjXOuVI",
   q   => "3dfOR9cuYq-0S-mkFLzgItg...q3hWeMuG0ouqnb3obLyuqjVZQ1dIrdgTnCdYzBcOW5r37AFXjift_NGiovonzhKpoVVS78",
   dp  => "G4sPXkc6Ya9y8oJW9_ILj4...zi_H7TkS8x5SdX3oE0oiYwxIiemTAu0UOa5pgFGyJ4c8t2VF40XRugKTP8akhFo5tA77Qe",
   dq  => "s9lAH9fggBsoFR8Oac2R_E...T2kGOhvIllTE1efA6huUvMfBcpn8lqW6vzzYY5SSF7pMd_agI3G8IbpBUb0JiraRNUfLhc",
   qi  => "GyM_p6JrXySiz1toFgKbWV...4ypu9bMWx3QJBfm0FoYzUIZEVEcOqwmRN81oDAaaBk0KWGDjJHDdDmFW3AN7I-pux_mHZG",
 };
 my $data = decode_jwt(token=>$t, key=>$rsa_priv});

Examples with ECC keys:

 my $pem_key_string = <<'EOF';
 -----BEGIN EC PRIVATE KEY-----
 MHcCAQEEIBG1c3z52T8XwMsahGVdOZWgKCQJfv+l7djuJjgetdbDoAoGCCqGSM49
 AwEHoUQDQgAEoBUyo8CQAFPeYPvv78ylh5MwFZjTCLQeb042TjiMJxG+9DLFmRSM
 lBQ9T/RsLLc+PmpB1+7yPAR+oR5gZn3kJQ==
 -----END EC PRIVATE KEY-----
 EOF

 my $jwk_key_json_string = '{"kty":"EC","crv":"P-256","x":"MKB..7D4","y":"4Et..FyM"}';

 #a reference to SCALAR string with PEM or DER or JSON/JWK data,
 my $data = decode_jwt(token=>$t, key=>\$pem_key_string);
 my $data = decode_jwt(token=>$t, key=>\$der_key_string);
 my $data = decode_jwt(token=>$t, key=>\$jwk_key_json_string);

 #instance of Crypt::PK::ECC
 my $data = decode_jwt(token=>$t, key=>Crypt::PK::ECC->new('keyfile.pem'));
 my $data = decode_jwt(token=>$t, key=>Crypt::PK::ECC->new(\$pem_key_string));

 #perl HASH ref with JWK structure (key type 'EC')
 my $ecc_priv = {
   kty => "EC",
   crv => "P-256",
   x   => "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
   y   => "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
   d   => "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE",
 };
 my $data = decode_jwt(token=>$t, key=>$ecc_priv});

=item keypass

When 'key' parameter is an encrypted private RSA or ECC key this optional parameter may contain a password for private key decryption.

=item kid_keys

This parametes can be either a JWK Set JSON string (see RFC7517) or a perl HASH ref with JWK Set structure like this:

  my $keylist = {
    keys => [
      { kid=>"key1", kty=>"oct", k=>"GawgguFyGrWKav7AX4VKUg" },
      { kid=>"key2", kty=>"oct", k=>"ulxLGy4XqhbpkR5ObGh1gX" },
    ]
  };
  my $payload = decode_jwt(token=>$t, kid_keys=>$keylist);

The structure described above is used e.g. by L<https://www.googleapis.com/oauth2/v2/certs>

  use Mojo::UserAgent;
  my $ua = Mojo::UserAgent->new;
  my $google_keys => $ua->get('https://www.googleapis.com/oauth2/v2/certs')->result->json;
  my $payload = decode_jwt(token => $t, kid_keys => $google_keys);

B<SINCE 0.019> we also support alternative structure used e.g. by L<https://www.googleapis.com/oauth2/v1/certs>:

  use LWP::Simple;
  my $google_certs = get('https://www.googleapis.com/oauth2/v1/certs');
  my $payload = decode_jwt(token => $t, kid_keys => $google_certs);

When the token header contains C<kid> item the corresponding key is looked up in C<kid_keys> list and used for token
decoding (you do not need to pass the explicit key via C<key> parameter).

B<INCOMPATIBLE CHANGE in 0.023:> When C<kid_keys> is specified it croaks if token header does not contain C<kid> value or
if C<kid> was not found in C<kid_keys>.

=item key_from_jwk_header

B<SINCE 0.023>

C<1> - use C<jwk> header value for validating JWS signature if neither C<key> nor C<kid_keys> specified, B<BEWARE: DANGEROUS, UNSECURE!!!>

C<0> (default) - ignore C<jwk> header value when validating JWS signature

Keep in mind that enabling C<key_from_jwk_header> requires C<jwk> header to exist and be an valid RSA/ECDSA public key (otherwise it croaks).

=item allow_none

C<1> - accept JWS tokens with C<none> 'alg' header value (which means that token has no signature), B<BEWARE: DANGEROUS, UNSECURE!!!>

C<0> (default) - do not allow JWS with C<none> 'alg' header value

=item ignore_signature

C<1> - do not check signature on JWS tokens, B<BEWARE: DANGEROUS, UNSECURE!!!>

C<0> (default) - check signature on JWS tokens

=item accepted_alg

C<undef> (default) means accept all 'alg' algorithms except 'none' (for accepting 'none' use C<allow_none>)

C<string> name of accepted 'alg' algorithm (only one)

C<ARRAY ref> a list of accepted 'alg' algorithms

C<Regexp> that has to match 'alg' algorithm name

 my $payload = decode_jwt(token=>$t, key=>$k, accepted_alg=>'HS256');
 #or
 my $payload = decode_jwt(token=>$t, key=>$k, accepted_alg=>['HS256','HS384']);
 #or
 my $payload = decode_jwt(token=>$t, key=>$k, accepted_alg=>qr/^HS(256|384|512)$/);

=item accepted_enc

C<undef> (default) means accept all 'enc' algorithms

C<string> name of accepted 'enc' algorithm (only one)

C<ARRAY ref> a list of accepted 'enc' algorithms

C<Regexp> that has to match 'enc' algorithm name

 my $payload = decode_jwt(token=>$t, key=>$k, accepted_enc=>'A192GCM');
 #or
 my $payload = decode_jwt(token=>$t, key=>$k, accepted_enc=>['A192GCM','A256GCM']);
 #or
 my $payload = decode_jwt(token=>$t, key=>$k, accepted_enc=>qr/^A(128|192|256)GCM$/);

=item decode_payload

C<0> - do not decode payload, return it as a raw string (octects).

C<1> - decode payload from JSON string, return it as perl hash ref (or array ref) - decode_json failure means fatal error (croak).

C<undef> (default) - if possible decode payload from JSON string, if decode_json fails return payload as a raw string (octets).

=item decode_header

C<0> (default) - do not return decoded header as a return value of decode_jwt()

C<1> - return decoded header as a return value of decode_jwt()

 my $payload = decode_jwt(token=>$t, key=>$k);
 #or
 my ($header, $payload) = decode_jwt(token=>$t, key=>$k, decode_header=>1);

=item verify_iss

B<INCOMPATIBLE CHANGE in 0.024:> If C<verify_iss> is specified and
claim C<iss> (Issuer) is completely missing it is a failure since 0.024

C<CODE ref> - subroutine (with 'iss' claim value passed as argument) should return C<true> otherwise verification fails

C<Regexp ref> - 'iss' claim value has to match given regexp otherwise verification fails

C<Scalar> - 'iss' claim value has to be equal to given string (since 0.029)

C<undef> (default) - do not verify 'iss' claim

=item verify_aud

B<INCOMPATIBLE CHANGE in 0.024:> If C<verify_aud> is specified and
claim C<aud> (Audience) is completely missing it is a failure since 0.024

C<CODE ref> - subroutine (with 'aud' claim value passed as argument) should return C<true> otherwise verification fails

C<Regexp ref> - 'aud' claim value has to match given regexp otherwise verification fails

C<Scalar> - 'aud' claim value has to be equal to given string (since 0.029)

C<undef> (default) - do not verify 'aud' claim

=item verify_sub

B<INCOMPATIBLE CHANGE in 0.024:> If C<verify_sub> is specified and
claim C<sub> (Subject) is completely missing it is a failure since 0.024

C<CODE ref> - subroutine (with 'sub' claim value passed as argument) should return C<true> otherwise verification fails

C<Regexp ref> - 'sub' claim value has to match given regexp otherwise verification fails

C<Scalar> - 'sub' claim value has to be equal to given string (since 0.029)

C<undef> (default) - do not verify 'sub' claim

=item verify_jti

B<INCOMPATIBLE CHANGE in 0.024:> If C<verify_jti> is specified and
claim C<jti> (JWT ID) is completely missing it is a failure since 0.024

C<CODE ref> - subroutine (with 'jti' claim value passed as argument) should return C<true> otherwise verification fails

C<Regexp ref> - 'jti' claim value has to match given regexp otherwise verification fails

C<Scalar> - 'jti' claim value has to be equal to given string (since 0.029)

C<undef> (default) - do not verify 'jti' claim

=item verify_iat

C<undef> - Issued At 'iat' claim must be valid (not in the future) if present

C<0> (default) - ignore 'iat' claim

C<1> - require valid 'iat' claim

=item verify_nbf

C<undef> (default) - Not Before 'nbf' claim must be valid if present

C<0> - ignore 'nbf' claim

C<1> - require valid 'nbf' claim

=item verify_exp

C<undef> (default) - Expiration Time 'exp' claim must be valid if present

C<0> - ignore 'exp' claim

C<1> - require valid 'exp' claim

=item leeway

Tolerance in seconds related to C<verify_exp>, C<verify_nbf> and C<verify_iat>. Default is C<0>.

=item ignore_claims

C<1> - do not check claims (iat, exp, nbf, iss, aud, sub, jti), B<BEWARE: DANGEROUS, UNSECURE!!!>

C<0> (default) - check claims

=back

=head2 encode_jwt

 my $token = encode_jwt(%named_args);

Named arguments:

=over

=item payload

Value of this mandatory parameter can be a string/buffer or HASH ref or ARRAY ref

 my $token = encode_jwt(payload=>"any raw data", key=>$k, alg=>'HS256');
 #or
 my $token = encode_jwt(payload=>{a=>1,b=>2}, key=>$k, alg=>'HS256');
 #or
 my $token = encode_jwt(payload=>[11,22,33,44], key=>$k, alg=>'HS256');

HASH refs and ARRAY refs payloads are serialized as JSON strings

=item alg

The 'alg' header value is mandatory for both JWE and JWS tokens.

Supported JWE 'alg' algorithms:

 dir
 A128KW
 A192KW
 A256KW
 A128GCMKW
 A192GCMKW
 A256GCMKW
 PBES2-HS256+A128KW
 PBES2-HS384+A192KW
 PBES2-HS512+A256KW
 RSA-OAEP
 RSA-OAEP-256
 RSA1_5
 ECDH-ES+A128KW
 ECDH-ES+A192KW
 ECDH-ES+A256KW
 ECDH-ES

Supported JWS algorithms:

 none   ...  no integrity (NOTE: disabled by default)
 HS256  ...  HMAC+SHA256 integrity
 HS384  ...  HMAC+SHA384 integrity
 HS512  ...  HMAC+SHA512 integrity
 RS256  ...  RSA+PKCS1-V1_5 + SHA256 signature
 RS384  ...  RSA+PKCS1-V1_5 + SHA384 signature
 RS512  ...  RSA+PKCS1-V1_5 + SHA512 signature
 PS256  ...  RSA+PSS + SHA256 signature
 PS384  ...  RSA+PSS + SHA384 signature
 PS512  ...  RSA+PSS + SHA512 signature
 ES256  ...  ECDSA + SHA256 signature
 ES256K ...  ECDSA + SHA256 signature
 ES384  ...  ECDSA + SHA384 signature
 ES512  ...  ECDSA + SHA512 signature
 EdDSA  ...  Ed25519 signature

=item enc

The 'enc' header is mandatory for JWE tokens.

Supported 'enc' algorithms:

 A128GCM
 A192GCM
 A256GCM
 A128CBC-HS256
 A192CBC-HS384
 A256CBC-HS512

=item key

A key used for token encryption (JWE) or token signing (JWS). The value depends on C<alg> token header value.

 JWS alg header      key value
 ------------------  ----------------------------------
 none                no key required
 HS256               string (raw octects) of any length (or perl HASH ref with JWK, kty=>'oct')
 HS384               dtto
 HS512               dtto
 RS256               private RSA key, perl HASH ref with JWK key structure,
                     a reference to SCALAR string with PEM or DER or JSON/JWK data,
                     object: Crypt::PK::RSA, Crypt::OpenSSL::RSA, Crypt::X509 or Crypt::OpenSSL::X509
 RS384               private RSA key, see RS256
 RS512               private RSA key, see RS256
 PS256               private RSA key, see RS256
 PS384               private RSA key, see RS256
 PS512               private RSA key, see RS256
 ES256               private ECC key, perl HASH ref with JWK key structure,
                     a reference to SCALAR string with PEM or DER or JSON/JWK data,
                     an instance of Crypt::PK::ECC
 ES256K              private ECC key, see ES256
 ES384               private ECC key, see ES256
 ES512               private ECC key, see ES256
 EdDSA               private Ed25519 key

 JWE alg header      key value
 ------------------  ----------------------------------
 dir                 string (raw octects) or perl HASH ref with JWK, kty=>'oct', length depends on 'enc' algorithm
 A128KW              string (raw octects) 16 bytes (or perl HASH ref with JWK, kty=>'oct')
 A192KW              string (raw octects) 24 bytes (or perl HASH ref with JWK, kty=>'oct')
 A256KW              string (raw octects) 32 bytes (or perl HASH ref with JWK, kty=>'oct')
 A128GCMKW           string (raw octects) 16 bytes (or perl HASH ref with JWK, kty=>'oct')
 A192GCMKW           string (raw octects) 24 bytes (or perl HASH ref with JWK, kty=>'oct')
 A256GCMKW           string (raw octects) 32 bytes (or perl HASH ref with JWK, kty=>'oct')
 PBES2-HS256+A128KW  string (raw octects) of any length (or perl HASH ref with JWK, kty=>'oct')
 PBES2-HS384+A192KW  string (raw octects) of any length (or perl HASH ref with JWK, kty=>'oct')
 PBES2-HS512+A256KW  string (raw octects) of any length (or perl HASH ref with JWK, kty=>'oct')
 RSA-OAEP            public RSA key, perl HASH ref with JWK key structure,
                     a reference to SCALAR string with PEM or DER or JSON/JWK data,
                     an instance of Crypt::PK::RSA or Crypt::OpenSSL::RSA
 RSA-OAEP-256        public RSA key, see RSA-OAEP
 RSA1_5              public RSA key, see RSA-OAEP
 ECDH-ES             public ECC or X25519 key, perl HASH ref with JWK key structure,
                     a reference to SCALAR string with PEM or DER or JSON/JWK data,
                     an instance of Crypt::PK::ECC
 ECDH-ES+A128KW      public ECC or X25519 key, see ECDH-ES
 ECDH-ES+A192KW      public ECC or X25519 key, see ECDH-ES
 ECDH-ES+A256KW      public ECC or X25519 key, see ECDH-ES

=item keypass

When 'key' parameter is an encrypted private RSA or ECC key this optional parameter may contain a password for private key decryption.

=item allow_none

C<1> - allow JWS with C<none> 'alg' header value (which means that token has no signature), B<BEWARE: DANGEROUS, UNSECURE!!!>

C<0> (default) - do not allow JWS with C<none> 'alg' header value

=item extra_headers

This optional parameter may contain a HASH ref with items that will be added to JWT header.

If you want to use PBES2-based 'alg' like C<PBES2-HS512+A256KW> you can set PBES2 salt len (p2s) in bytes and
iteration count (p2c) via C<extra_headers> like this:

 my $token = encode_jwt(payload=>$p, key=>$k, alg=>'PBES2-HS512+A256KW', extra_headers=>{p2c=8000, p2s=>32});
 #NOTE: handling of p2s header is a special case, in the end it is replaced with the generated salt

=item unprotected_headers

A hash with additional integrity unprotected headers - JWS and JWE (not available for C<compact> serialization);

=item shared_unprotected_headers

A hash with additional integrity unprotected headers - JWE only (not available for C<compact> serialization);

=item aad

Additional Authenticated Data - scalar value with any (even raw octects) data - JWE only (not available for C<compact> serialization);

=item serialization

Specify serialization method: C<compat> (= default) for Compact JWS/JWE serialization or C<flattened> for Flattened JWS/JWE JSON serialization.

General JSON serialization is not supported yet.

=item zip

Compression method, currently 'deflate' is the only one supported. C<undef> (default) means no compression.

 my $token = encode_jwt(payload=>$p, key=>$k, alg=>'HS256', zip=>'deflate');
 #or define compression level
 my $token = encode_jwt(payload=>$p, key=>$k, alg=>'HS256', zip=>['deflate', 9]);

=item auto_iat

C<1> - set 'iat' (Issued At) claim to current time (epoch seconds since 1970) at the moment of token encoding

C<0> (default) - do not set 'iat' claim

NOTE: claims are part of the payload and can be used only if the payload is a HASH ref!

=item relative_exp

Set 'exp' claim (Expiration Time) to current time + C<relative_exp> value (in seconds).

NOTE: claims are part of the payload and can be used only if the payload is a HASH ref!

=item relative_nbf

Set 'nbf' claim (Not Before) to current time + C<relative_nbf> value (in seconds).

NOTE: claims are part of the payload and can be used only if the payload is a HASH ref!

=back

=head1 SEE ALSO

L<Crypt::Cipher::AES>, L<Crypt::AuthEnc::GCM>, L<Crypt::PK::RSA>, L<Crypt::PK::ECC>, L<Crypt::KeyDerivation>, L<Crypt::KeyWrap>

=head1 LICENSE

This program is free software; you can redistribute it and/or modify it under the same terms as Perl itself.

=head1 COPYRIGHT

Copyright (c) 2015-2021 DCIT, a.s. L<https://www.dcit.cz> / Karel Miko
