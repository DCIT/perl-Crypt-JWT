use strict;
use warnings;

use Test::More;

my $TV_DIR = 't/wycheproof-repo/testvectors_v1';
my $AUTHOR_MODE = defined $ENV{AUTHOR_MODE} ? $ENV{AUTHOR_MODE} : '';

plan skip_all => 'set AUTHOR_MODE=1 to run Project Wycheproof tests' unless $AUTHOR_MODE eq '1';
plan skip_all => "Project Wycheproof checkout not found at $TV_DIR" unless -d $TV_DIR;

require Crypt::JWT;     Crypt::JWT->import('decode_jwt');
require Crypt::KeyWrap; Crypt::KeyWrap->import('aes_key_unwrap');
require JSON;           JSON->import('decode_json');

# Residual gaps grouped by root cause. A line moves out of TODO only when
# the underlying check or behaviour change has actually landed in the lib.
my %TODO = (
  # ---- Wycheproof internal inconsistency: tcId 332-336 vs 338-340 want
  # 'reject when JWK alg differs from token alg', but tcId 346/347/350/351
  # (RFC 7520 examples) want 'accept when JWK alg differs from token alg'
  # within the same family. Library matches the second policy (family-based
  # alg check), satisfying the larger group.
  'json_web_signature_test:338' => 'Wycheproof: PS512-key vs PS256-token, conflicts with RFC 7520 cases',
  'json_web_signature_test:340' => 'Wycheproof: PS512-key vs PS384-token, conflicts with RFC 7520 cases',

  # ---- Wycheproof's tcId 349 carries a malformed key_ops where the array
  # has a single string "sign, verify" (one element with an embedded
  # comma) rather than two elements ["sign","verify"]. We enforce key_ops
  # strictly per RFC 7517 sec 4.3 and reject; Wycheproof labels valid.
  'json_web_signature_test:349' => 'Wycheproof: malformed key_ops single-string entry',

  # ---- Wycheproof bug: tcId 367 and 370 are byte-identical strings to the
  # valid tcId 357 in the same group, but labelled 'invalid'. No implementation
  # can distinguish identical bytes.
  'json_web_signature_test:367' => 'WYCHEPROOF BUG: byte-identical to valid tcId 357',
  'json_web_signature_test:370' => 'WYCHEPROOF BUG: byte-identical to valid tcId 357',

  # ---- Spec-strict reject: tcId 372/373 contain a literal '?' character
  # (not in the base64url alphabet). RFC 7515 mandates strict base64url; we
  # reject, Wycheproof labels valid. We side with the spec.
  'json_web_signature_test:372' => 'spec-strict: non-base64url char (?) in header',
  'json_web_signature_test:373' => 'spec-strict: non-base64url char (?) in payload',

  # ---- MAC computed over a non-canonical Base64 encoding; detecting this
  # would require re-MAC-ing under each acceptable encoding variant. Out of
  # scope.
  'json_web_signature_test:375' => 'MAC over non-canonical b64 encoding',

  # ---- Judgment call: tcId 22 is a well-formed flattened JWE with extra
  # unprotected fields. Wycheproof wants any JSON-serialised JWE rejected by
  # libraries that don't fully support general serialization; this lib
  # supports flattened, so it accepts.
  'json_web_encryption_test:22' => 'flattened JSON serialization is supported here',

  # ---- Weak-key / malformed-key detection that the library does NOT do:
  #   tcId  7  ROCA-vulnerable RSA modulus (belongs in Crypt::PK::RSA)
  #   tcId  9  RSA public exponent = 1 (degenerate; check belongs in Crypt::PK::RSA)
  #   tcId 10  HS256 key shorter than 32 bytes (lib accepts >= 6 bytes by default;
  #            see SECURITY CONSIDERATIONS in POD)
  #   tcId 11  HS384 key shorter than 48 bytes (same; lib accepts >= 6 bytes)
  #   tcId 12  HS512 key shorter than 64 bytes (same; lib accepts >= 6 bytes)
  #   tcId 22  Modified EC key value (curve-membership check belongs in Crypt::PK::ECC)
  # (tcId  8, 1024-bit RSA, now closed by $MIN_RSA_BITS = 2048.)
  # (tcId 19, 20, EC alg/crv mismatch, now closed by JWK self-consistency check.)
  (map { ("json_web_key_test:$_" => 'weak/malformed-key check beyond what Crypt::JWT enforces') }
    7, 9, 10, 11, 12, 22),

  # ---- ROCA vulnerability detection: same reasoning - belongs in
  # Crypt::PK::RSA.
  'json_web_crypto_test:46' => 'ROCA detection belongs in Crypt::PK::RSA',
);

sub _load {
  my ($filename) = @_;
  my $path = "$TV_DIR/$filename.json";
  open my $fh, '<', $path or die "open $path: $!";
  my $tv = decode_json(do { local $/; <$fh> });
  close $fh;
  return $tv;
}

# Driver for the JOSE-token files (jws/jwe/jwk/jwc). Routes a JWK Set as
# 'kid_keys' and a single JWK as 'key'; for JWE compares the decoded payload
# against the expected hex 'pt'.
sub run_jwt_file {
  my ($filename) = @_;
  my $tv = _load($filename);

  for my $g (@{ $tv->{testGroups} }) {
    my $key = $g->{private};
    for my $t (@{ $g->{tests} }) {
      my $expect = $t->{result};
      my $token  = $t->{jws} // $t->{jwe};
      my $tag    = "$filename:$t->{tcId}";

      # A 'private' that looks like a JWK Set (has a 'keys' array) is a
      # multi-key directory; route it through kid_keys so the library can
      # match by 'kid' header. A bare JWK goes through 'key' as before.
      my $payload = eval {
        local $SIG{__WARN__} = sub {};   # corrupt vectors trip warnings on uninit values
        if (ref $key eq 'HASH' && ref $key->{keys} eq 'ARRAY') {
          decode_jwt(token => $token, kid_keys => $key, decode_payload => 0);
        } else {
          decode_jwt(token => $token, key => $key, decode_payload => 0);
        }
      };

      my $ok;
      if    ($expect eq 'valid')      { $ok = defined $payload
                                          && (!$t->{pt} || lc(unpack 'H*', $payload) eq lc($t->{pt})) }
      elsif ($expect eq 'invalid')    { $ok = !defined $payload }
      elsif ($expect eq 'acceptable') { $ok = 1 }
      else                            { $ok = 0 }

      local $TODO = $TODO{$tag} if exists $TODO{$tag};
      ok($ok, "$tag $t->{comment} (expect $expect)");
    }
  }
}

# Driver for the AES key-wrap primitive files. Each test has hex-encoded
# {key, msg, ct}; we run aes_key_unwrap and check it produces msg.
# $padding=0 -> RFC 3394 (KW), $padding=1 -> RFC 5649 (KWP).
sub run_keywrap_file {
  my ($filename, $padding) = @_;
  my $tv = _load($filename);

  for my $g (@{ $tv->{testGroups} }) {
    for my $t (@{ $g->{tests} }) {
      my $expect = $t->{result};
      my $tag    = "$filename:$t->{tcId}";
      my $key    = pack 'H*', $t->{key};
      my $ct     = pack 'H*', $t->{ct};
      my $msg    = pack 'H*', $t->{msg};

      my $got = eval {
        local $SIG{__WARN__} = sub {};
        aes_key_unwrap($key, $ct, 'AES', $padding);
      };

      my $ok;
      if    ($expect eq 'valid')      { $ok = defined $got && $got eq $msg }
      elsif ($expect eq 'invalid')    { $ok = !defined $got }
      elsif ($expect eq 'acceptable') { $ok = 1 }
      else                            { $ok = 0 }

      local $TODO = $TODO{$tag} if exists $TODO{$tag};
      ok($ok, "$tag $t->{comment} (expect $expect)");
    }
  }
}

run_jwt_file('json_web_signature_test');
run_jwt_file('json_web_encryption_test');
run_jwt_file('json_web_key_test');
run_jwt_file('json_web_crypto_test');
run_keywrap_file('aes_wrap_test', 0);   # RFC 3394 - no padding
run_keywrap_file('aes_kwp_test',  1);   # RFC 5649 - with padding

done_testing;
