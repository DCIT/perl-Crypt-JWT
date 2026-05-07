use strict;
use warnings;
use Test::More;

use Crypt::JWT qw(decode_jwt);

# Regression vectors for the ConcatKDF fix (counter-per-iteration + honour the
# requested hash). The bug only manifested when key_size > hash_size, i.e.
# ECDH-ES (direct) paired with A192CBC-HS384 (48-byte key) or A256CBC-HS512
# (64-byte key). Round-trip tests in this repo could not catch it because both
# encode and decode were equally wrong.
#
# These two tokens were produced by jwcrypto 1.5.7 (an independent, spec-
# compliant JOSE implementation) and encrypt the payload {"hello":"world"} to
# the static EC P-256 keypair below. A regression in _concat_kdf would derive
# the wrong CEK and decryption would fail.

my $ec_priv_pem = <<'EOF';
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg26+F/ifLwUlXYaEF
iUMpiTEljnxJVBLXOUMnmoF8pO6hRANCAAQtJcfPtxnqrdBNe2R2gqTlHOgnfnmz
TEh6MynIJ44MiITSmLZhlFP8GdX+A0lcKPzS6tN2W6Zu9gZjtpwR65ab
-----END PRIVATE KEY-----
EOF

my %vectors = (
  'ECDH-ES + A192CBC-HS384' =>
    'eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTE5MkNCQy1IUzM4NCIsImVwayI6eyJjcnYi'
  . 'OiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImZiNkpNTXdlQlpHc0xPeVdwUVZHSUNRUm0w'
  . 'LVIzRElMUkdxYzNIZDJPVDgiLCJ5IjoiVE9hUUpOSVNkWFlad3ByOTRpT2tSTi1mSHZO'
  . 'S2t0WDlROTVHbGJpN1pjQSJ9fQ..QqoyONjUURBsmQswE1-3gw.BXnr518x06QecAi9'
  . '_9Baz5ytVeLt1MBRRrFijlxrpRs.Qx7Artlj1MNZcGjqeVWPVVrJpciQoKyJ',
  'ECDH-ES + A256CBC-HS512' =>
    'eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTI1NkNCQy1IUzUxMiIsImVwayI6eyJjcnYi'
  . 'OiJQLTI1NiIsImt0eSI6IkVDIiwieCI6IjlJRTI3b0hrTjJ0LWpVaGZnbjA3aGtqc1hV'
  . 'VG8tV3hLclNxVjJXMTNuZ3ciLCJ5IjoiRUVybE1kNGtVdDU5VnRQUUhRMUtvaE85MUxT'
  . 'UzJqOTZnUTdMVC1hb1FTTSJ9fQ..JQE5msVIbA-4Fq5W6fhwRA.VdZ9WfNwCEVaQunX'
  . 'pwTTz58LQl6u1ASV6_gwJzSHg0Y.EOAirtbVgDnIRcwDHKBuF777pnT8lYPrGAgPdo14Eho',
);

my $expected = '{"hello":"world"}';

for my $label (sort keys %vectors) {
  my $payload = eval { decode_jwt(token => $vectors{$label}, key => \$ec_priv_pem, decode_payload => 0) };
  is($payload, $expected, "$label: decode third-party (jwcrypto) vector");
}

done_testing;
