use strict;
use warnings;

use Test::More;

my $TV_DIR = 't/wycheproof-repo/testvectors_v1';
my $AUTHOR_MODE = defined $ENV{AUTHOR_MODE} ? $ENV{AUTHOR_MODE} : '';

plan skip_all => 'set AUTHOR_MODE=1 to run Project Wycheproof tests' unless $AUTHOR_MODE eq '1';
plan skip_all => "Project Wycheproof checkout not found at $TV_DIR" unless -d $TV_DIR;

require Crypt::JWT; Crypt::JWT->import('decode_jwt');
require JSON;       JSON->import('decode_json');

# Known gaps in this library (not in the vectors). Each entry maps
# "<file>:<tcId>" to a short reason; matching cases run as TODO so the suite
# stays green until the underlying gap is closed. Grouped by root cause.
my %TODO = (
  # ---- JWK 'alg' / 'use' / 'key_ops' constraints not enforced on the
  # bare-`key` path. RFC 7517 §4.2/4.3 say these fields constrain how the key
  # may be used; the kid_keys path enforces 'kty' but no path enforces 'alg',
  # 'use', or 'key_ops'. Closing this is a single check after key selection.
  (map { ("json_web_signature_test:$_" => 'JWK alg/kid mismatch not enforced') }
    332, 334, 336, 338, 340),
  (map { ("json_web_signature_test:$_" => 'JWK use=enc not enforced for sig')   } 353, 354),
  (map { ("json_web_signature_test:$_" => 'JWK key_ops not enforced')           } 355, 356),
  (map { ("json_web_encryption_test:$_" => 'JWK alg-family confusion (e.g. RSA-OAEP key used with RSA1_5)') }
    106, 107, 108, 109, 110, 111),

  # ---- tolerate_padding=>0 strips '=' from segments rather than rejecting
  # tokens that carry padding; Wycheproof considers the latter the spec-strict
  # behavior. Design choice today; revisit if v1.0 tightens this.
  (map { ("json_web_signature_test:$_" => 'padding tolerance default strips, does not reject') }
    367, 370),

  # ---- Tokens with non-canonical Base64 input that decode to the same bytes.
  # Wycheproof marks these "valid" (output unchanged); this lib's strict regex
  # rejects the surface form. Could be relaxed by accepting any segment that
  # decodes the same after canonicalisation.
  'json_web_signature_test:372' => 'non-canonical b64 char inserted in header',
  'json_web_signature_test:373' => 'non-canonical b64 char inserted in payload',
  'json_web_signature_test:375' => 'MAC of non-canonical encoding',

  # ---- JWE: generic JSON serialization is not supported but should be
  # actively rejected, not mis-detected as flattened.
  'json_web_encryption_test:22'  => 'general JSON serialization mis-detected',

  # ---- JWK file: 5 keysets we reject that Wycheproof says are valid.
  # Mostly long-key / multi-key edge cases; needs JWK-set parsing review.
  (map { ("json_web_key_test:$_" => 'JWK set/long-key edge case rejected') } 2, 5, 13, 14, 15),

  # ---- Crypto file: ROCA-vulnerable key acceptance + one valid edge case.
  'json_web_crypto_test:46' => 'ROCA-vulnerable RSA modulus not detected',
  'json_web_crypto_test:48' => 'valid edge case rejected',
);

sub run_file {
  my ($filename) = @_;
  my $path = "$TV_DIR/$filename.json";
  open my $fh, '<', $path or die "open $path: $!";
  my $tv = decode_json(do { local $/; <$fh> });
  close $fh;

  for my $g (@{ $tv->{testGroups} }) {
    my $key = $g->{private};
    for my $t (@{ $g->{tests} }) {
      my $expect = $t->{result};
      my $token  = $t->{jws} // $t->{jwe};
      my $tag    = "$filename:$t->{tcId}";

      my $payload = eval {
        local $SIG{__WARN__} = sub {};   # corrupt vectors trip warnings on uninit values
        decode_jwt(token => $token, key => $key, decode_payload => 0);
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

run_file('json_web_signature_test');
run_file('json_web_encryption_test');
run_file('json_web_key_test');
run_file('json_web_crypto_test');

done_testing;
