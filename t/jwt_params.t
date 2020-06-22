use strict;
use warnings;
use Test::More;

use Crypt::JWT qw(encode_jwt decode_jwt);
use Crypt::PK::ECC;
use Crypt::PK::RSA;
use Crypt::Misc qw(encode_b64u);
use JSON qw(encode_json);

# key password is 'secret'
my $rsaPriv = <<'EOF';
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,2823DCBA91F7DBA2ED920CAEE40F0BB4

KAADjca5SzbAbdz2cF567ZO9WjZz+lA1C40gsOBvHB6LjWU32YGW6Hz9a7pwUjOh
E/gGSFkKv6pTJgXfLs/l+pIDGSohhzChw7hkmN1IgVXqDQZw3koW5Yn7bg6xeJoI
JFwIIQhnft6BHG2o/5MzUTRwHpIxRuIaz2FnZtBNbVtQInHtP8LJIAVoyoO4c0ET
IQBDj7dwOAPdxOsrKCRkjI8IBMwWtKBq7XunkE15dZFFZrZOfIaXUqNYF9DlCHBk
eGV2lZoL99pOtJzHTBzv3rtyPYqCNotTNnui2Z0Jzcq8K97XAlzKhL7BFMw5TSUF
Tf9ECgumaRELXDdlUtEiZ7uACBXAW+qTUxOCrp+EeyfUBYPLuiy9KQvJd4C+8QIs
OIYekzfqZfhbhOdb0U7ZRN3KXfuNS70vKfoMyuW4UVx75QZt3CnJL8M6dn+eijjw
mEVCT/a8SLgTgMKtl2AzFiJK4WqvnUs9iOswlaAWCIpvrMQmxltoL34aim55EZKd
gDlEW5zCcjYe8A5d5abd4cX8vVrN57j2O3Dk9Dgyr4ZHPjBMF8b6LnWqBGrgFrbQ
LpjDZRNm4W7JuROL5VtSBEwP5VAMdl56UPlgGmM6K2MgAvkZ99ycffu0vsKOxd1T
5wpY2y5SBOyoex0XPa9woz0GOLjf9ydpVlVikPHk4XX2ts0+L5VttkQ7wO9GLUj0
OltsrOxscHq3xPYsJgxmmHGmhrlTKIv1YHjzZsteqZLokH3kr1sCEX+vS3lqaQP8
rmIjf2vAWi3inteZifZ2v48V8XPTOUky/YQvTEGDstHWVd74hhrCVfx+Jk7vjipr
-----END RSA PRIVATE KEY-----
EOF

my $k = '68yYPz1F17s4VWIIbEOB';
my $p = 'testik RANDOM=kDSIHckuMyz1JmCyKhhx Blexx!';
my $h = { body=>"hash", number=>123456, text=>"Hello" };
my $l = [ 11, 22, 33, 44, 55 ];
my ($alg, $enc);
my ($token, $decoded, $decoded_h);

for ([qw/PBES2-HS256+A128KW A128GCM/], ['HS512', '']) {
  ($alg, $enc) = @$_;

  $token = encode_jwt(key=>$k, payload=>$p, alg=>$alg, enc=>$enc, zip=>'deflate');
  ok($token, "deflate: enc=>'$enc' alg=>'$alg'");
  $decoded = decode_jwt(key=>$k, token=>$token);
  is($decoded, $p, "decoded - deflate: enc=>'$enc' alg=>'$alg'");

  $decoded = decode_jwt(key=>$k, token=>$token, accepted_alg=>$alg);
  is($decoded, $p, "decoded - accepted_alg/1: enc=>'$enc' alg=>qr/.+/");
  $decoded = decode_jwt(key=>$k, token=>$token, accepted_alg=>$alg);
  is($decoded, $p, "decoded - accepted_alg/2: enc=>'$enc' alg=>'$alg'");
  $decoded = decode_jwt(key=>$k, token=>$token, accepted_alg=>["XX", $alg, "YY"]);
  is($decoded, $p, "decoded - accepted_alg/3: enc=>'$enc' alg=>'$alg'");
  $decoded = eval { decode_jwt(key=>$k, token=>$token, accepted_alg=>["XX", "YY"]) };
  is($decoded, undef, "decoded - accepted_alg/4: enc=>'$enc' alg=>'$alg'");
  $decoded = eval { decode_jwt(key=>$k, token=>$token, accepted_alg=>"YY") };
  is($decoded, undef, "decoded - accepted_alg/5: enc=>'$enc' alg=>'$alg'");
  $decoded = eval { decode_jwt(key=>$k, token=>$token, accepted_alg=>qr/NOTFOUND/) };
  is($decoded, undef, "decoded - accepted_alg/6: enc=>'$enc' alg=>'$alg'");

  if ($enc) {
    # JWE only
    $decoded = decode_jwt(key=>$k, token=>$token, accepted_enc=>$enc);
    is($decoded, $p, "decoded - accepted_enc/1: enc=>'$enc' alg=>qr/.+/");
    $decoded = decode_jwt(key=>$k, token=>$token, accepted_enc=>$enc);
    is($decoded, $p, "decoded - accepted_enc/2: enc=>'$enc' alg=>'$alg'");
    $decoded = decode_jwt(key=>$k, token=>$token, accepted_enc=>["XX", $enc, "YY"]);
    is($decoded, $p, "decoded - accepted_enc/3: enc=>'$enc' alg=>'$alg'");
    $decoded = eval { decode_jwt(key=>$k, token=>$token, accepted_enc=>["XX", "YY"]) };
    is($decoded, undef, "decoded - accepted_enc/4: enc=>'$enc' alg=>'$alg'");
    $decoded = eval { decode_jwt(key=>$k, token=>$token, accepted_enc=>"YY") };
    is($decoded, undef, "decoded - accepted_enc/5: enc=>'$enc' alg=>'$alg'");
    $decoded = eval { decode_jwt(key=>$k, token=>$token, accepted_enc=>qr/NOTFOUND/) };
    is($decoded, undef, "decoded - accepted_enc/6: enc=>'$enc' alg=>'$alg'");
  }

  $token = encode_jwt(key=>$k, payload=>$p, alg=>$alg, enc=>$enc, zip=>['deflate', 1]);
  ok($token, "deflate+1: enc=>'$enc' alg=>'$alg'");
  $decoded = decode_jwt(key=>$k, token=>$token);
  is($decoded, $p, "decoded - deflate+1: enc=>'$enc' alg=>'$alg'");

  $token = encode_jwt(key=>$k, payload=>$h, alg=>$alg, enc=>$enc);
  ok($token, "hash: enc=>'$enc' alg=>'$alg'");
  $decoded = decode_jwt(key=>$k, token=>$token, decode_payload=>0);
  like($decoded, qr/"text":"Hello"/, "decoded - hash/1: enc=>'$enc' alg=>'$alg'");
  $decoded = decode_jwt(key=>$k, token=>$token, decode_payload=>1);
  is($decoded->{text}, "Hello", "decoded - hash/2: enc=>'$enc' alg=>'$alg'");
  $decoded = decode_jwt(key=>$k, token=>$token);
  is($decoded->{text}, "Hello", "decoded - hash/3: enc=>'$enc' alg=>'$alg'");

  $token = encode_jwt(key=>$k, payload=>$l, alg=>$alg, enc=>$enc);
  ok($token, "array: enc=>'$enc' alg=>'$alg'");
  $decoded = decode_jwt(key=>$k, token=>$token, decode_payload=>0);
  like($decoded, qr/\[11,22,33,44,55\]/, "decoded - array/1: enc=>'$enc' alg=>'$alg'");
  $decoded = decode_jwt(key=>$k, token=>$token, decode_payload=>1);
  is($decoded->[0], 11, "decoded - array/2: enc=>'$enc' alg=>'$alg'");
  $decoded = decode_jwt(key=>$k, token=>$token);
  is($decoded->[0], 11, "decoded - array/3: enc=>'$enc' alg=>'$alg'");

  my $keylist = {
    keys => [
      { kid=>"key1", kty=>"oct", k=>"GawgguFyGrWKav7AX4VKUg" },
      { kid=>"key2", kty=>"oct", k=>"ulxLGy4XqhbpkR5ObGh1gX" },
    ]
  };
  my $keylist_json = encode_json($keylist);
  $token = encode_jwt(key=>$keylist->{keys}->[1], extra_headers=>{kid=>"key2"}, payload=>$p, alg=>$alg, enc=>$enc);
  ok($token, "kid_keys: enc=>'$enc' alg=>'$alg'");
  $decoded = decode_jwt(kid_keys=>$keylist, token=>$token);
  is($decoded, $p, "decoded - kid_keys/1: enc=>'$enc' alg=>'$alg'");
  $decoded = decode_jwt(kid_keys=>$keylist_json, token=>$token);
  is($decoded, $p, "decoded - kid_keys/2: enc=>'$enc' alg=>'$alg'");

  $token = encode_jwt(key=>$k, payload=>$p, alg=>$alg, enc=>$enc, extra_headers=>{extra1=>11, extra2=>22});
  ($decoded_h, $decoded) = decode_jwt(key=>$k, token=>$token, decode_header=>1);
  is($decoded, $p, "decoded - decode_header/1: enc=>'$enc' alg=>'$alg'");
  is($decoded_h->{extra1}, 11, "decoded - decode_header/2: enc=>'$enc' alg=>'$alg'");

  if (!$enc) {
    #JWS only
    $token = encode_jwt(key=>$k, payload=>$p, alg=>$alg);
    ok($token, "ignore_signature: alg=>'$alg'");
    $decoded = decode_jwt(token=>$token, ignore_signature=>1);
    is($decoded, $p, "decoded - ignore_signature: alg=>'$alg'");

    my $claims = {
      iss => 'iss-string',
      aud => 'aud-string',
      sub => 'sub-string',
      jti => 'jti-string',
      iat => time,
      nbf => time,
      exp => time + 10,
      data => 'Hello',
    };
    $token = encode_jwt(key=>$k, payload=>$claims, alg=>$alg);
    ok($token, "claims: alg=>'$alg'");
    $decoded = decode_jwt(key=>$k, token=>$token);
    is($decoded->{data}, 'Hello', "decoded - claims/1: alg=>'$alg'");

    $decoded = decode_jwt(key=>$k, token=>$token, verify_iss=>sub { return 1 }, verify_aud=>sub { return 1 }, verify_sub=>sub { return 1 }, verify_jti=>sub { return 1 });
    is($decoded->{data}, 'Hello', "decoded - claims/2: alg=>'$alg'");
    $decoded = eval { decode_jwt(key=>$k, token=>$token, verify_iss=>sub { return 0 }, verify_aud=>sub { return 1 }, verify_sub=>sub { return 1 }, verify_jti=>sub { return 1 }) };
    is($decoded, undef, "decoded - claims/3: alg=>'$alg'");
    $decoded = eval { decode_jwt(key=>$k, token=>$token, verify_iss=>sub { return 1 }, verify_aud=>sub { return 0 }, verify_sub=>sub { return 1 }, verify_jti=>sub { return 1 }) };
    is($decoded, undef, "decoded - claims/4: alg=>'$alg'");
    $decoded = eval { decode_jwt(key=>$k, token=>$token, verify_iss=>sub { return 1 }, verify_aud=>sub { return 1 }, verify_sub=>sub { return 0 }, verify_jti=>sub { return 1 }) };
    is($decoded, undef, "decoded - claims/5: alg=>'$alg'");
    $decoded = eval { decode_jwt(key=>$k, token=>$token, verify_iss=>sub { return 1 }, verify_aud=>sub { return 1 }, verify_sub=>sub { return 1 }, verify_jti=>sub { return 0 }) };
    is($decoded, undef, "decoded - claims/6: alg=>'$alg'");

    $decoded = decode_jwt(key=>$k, token=>$token, verify_iss=>qr/string/, verify_aud=>qr/string/, verify_sub=>qr/string/, verify_jti=>qr/string/);
    is($decoded->{data}, 'Hello', "decoded - claims/7: alg=>'$alg'");
    $decoded = eval { decode_jwt(key=>$k, token=>$token, verify_iss=>qr/BADVAL/, verify_aud=>qr/string/, verify_sub=>qr/string/, verify_jti=>qr/string/) };
    is($decoded, undef, "decoded - claims/8: alg=>'$alg'");
    $decoded = eval { decode_jwt(key=>$k, token=>$token, verify_iss=>qr/string/, verify_aud=>qr/BADVAL/, verify_sub=>qr/string/, verify_jti=>qr/string/) };
    is($decoded, undef, "decoded - claims/9: alg=>'$alg'");
    $decoded = eval { decode_jwt(key=>$k, token=>$token, verify_iss=>qr/string/, verify_aud=>qr/string/, verify_sub=>qr/BADVAL/, verify_jti=>qr/string/) };
    is($decoded, undef, "decoded - claims/10: alg=>'$alg'");
    $decoded = eval { decode_jwt(key=>$k, token=>$token, verify_iss=>qr/string/, verify_aud=>qr/string/, verify_sub=>qr/string/, verify_jti=>qr/BADVAL/) };
    is($decoded, undef, "decoded - claims/11: alg=>'$alg'");

    $decoded = decode_jwt(key=>$k, token=>$token, verify_iss=>'iss-string', verify_aud=>'aud-string', verify_sub=>'sub-string', verify_jti=>'jti-string');
    is($decoded->{data}, 'Hello', "decoded - claims/12: alg=>'$alg'");
    $decoded = eval { decode_jwt(key=>$k, token=>$token, verify_iss=>'BADVAL', verify_aud=>'aud-string', verify_sub=>'sub-string', verify_jti=>'jti-string') };
    is($decoded, undef, "decoded - claims/13: alg=>'$alg'");
    $decoded = eval { decode_jwt(key=>$k, token=>$token, verify_iss=>'iss-string', verify_aud=>'BADVAL', verify_sub=>'sub-string', verify_jti=>'jti-string') };
    is($decoded, undef, "decoded - claims/14: alg=>'$alg'");
    $decoded = eval { decode_jwt(key=>$k, token=>$token, verify_iss=>'iss-string', verify_aud=>'aud-string', verify_sub=>'BADVAL', verify_jti=>'jti-string') };
    is($decoded, undef, "decoded - claims/15: alg=>'$alg'");
    $decoded = eval { decode_jwt(key=>$k, token=>$token, verify_iss=>'iss-string', verify_aud=>'aud-string', verify_sub=>'sub-string', verify_jti=>'BADVAL') };
    is($decoded, undef, "decoded - claims/16: alg=>'$alg'");

    # check for undef payload values or undef verify args
    $token = encode_jwt(key=>$k, payload=>{iat=>time, nbf=>time, exp=>time+10, iss=>undef, aud=>undef, sub=>undef, jti=>undef, data=>'Hello'}, alg=>$alg);
    $decoded = eval { decode_jwt(key=>$k, token=>$token, verify_iss=>qr/string/, verify_aud=>qr/string/, verify_sub=>qr/string/, verify_jti=>qr/BADVAL/) };
    is($decoded, undef, "decoded - claims_undef/1: alg=>'$alg'");
    $decoded = decode_jwt(key=>$k, token=>$token, verify_iss=>undef, verify_aud=>undef, verify_sub=>undef, verify_jti=>undef);
    is($decoded->{data}, 'Hello', "decoded - claims_undef/2: alg=>'$alg'");

    # iat
    $token = encode_jwt(key=>$k, payload=>{iat=>time+10, nbf=>time, exp=>time+10, data=>'Hello'}, alg=>$alg);
    $decoded = eval { decode_jwt(key=>$k, token=>$token) };
    is($decoded->{data}, 'Hello', "decoded - iat/1: alg=>'$alg'");
    $decoded = eval { decode_jwt(key=>$k, token=>$token, verify_iat=>undef) };
    is($decoded, undef, "decoded - iat/2: alg=>'$alg'");
    $decoded = eval { decode_jwt(key=>$k, token=>$token, verify_iat=>1) };
    is($decoded, undef, "decoded - iat/3: alg=>'$alg'");
    $decoded = eval { decode_jwt(key=>$k, token=>$token, verify_iat=>0) };
    is($decoded->{data}, 'Hello', "decoded - iat/4: alg=>'$alg'");
    $decoded = eval { decode_jwt(key=>$k, token=>$token, verify_iat=>1, leeway=>20) };
    is($decoded->{data}, 'Hello', "decoded - iat/5: alg=>'$alg'");

    # nbf
    $token = encode_jwt(key=>$k, payload=>{nbf=>time+10, exp=>time+20, data=>'Hello'}, alg=>$alg);
    $decoded = eval { decode_jwt(key=>$k, token=>$token) };
    is($decoded, undef, "decoded - nbf/1: alg=>'$alg'");
    $decoded = eval { decode_jwt(key=>$k, token=>$token, verify_nbf=>undef) };
    is($decoded, undef, "decoded - nbf/2: alg=>'$alg'");
    $decoded = eval { decode_jwt(key=>$k, token=>$token, verify_nbf=>1) };
    is($decoded, undef, "decoded - nbf/3: alg=>'$alg'");
    $decoded = eval { decode_jwt(key=>$k, token=>$token, verify_nbf=>0) };
    is($decoded->{data}, 'Hello', "decoded - nbf/4: alg=>'$alg'");
    $decoded = eval { decode_jwt(key=>$k, token=>$token, leeway=>20) };
    is($decoded->{data}, 'Hello', "decoded - nbf/5: alg=>'$alg'");

    # exp
    $token = encode_jwt(key=>$k, payload=>{exp=>time-5, data=>'Hello'}, alg=>$alg);
    $decoded = eval { decode_jwt(key=>$k, token=>$token) };
    is($decoded, undef, "decoded - exp/1: alg=>'$alg'");
    $decoded = eval { decode_jwt(key=>$k, token=>$token, verify_exp=>undef) };
    is($decoded, undef, "decoded - exp/2: alg=>'$alg'");
    $decoded = eval { decode_jwt(key=>$k, token=>$token, verify_exp=>1) };
    is($decoded, undef, "decoded - exp/3: alg=>'$alg'");
    $decoded = eval { decode_jwt(key=>$k, token=>$token, verify_exp=>0) };
    is($decoded->{data}, 'Hello', "decoded - exp/4: alg=>'$alg'");
    $decoded = eval { decode_jwt(key=>$k, token=>$token, leeway=>20) };
    is($decoded->{data}, 'Hello', "decoded - exp/5: alg=>'$alg'");

    $token = encode_jwt(key=>$k, payload=>{nbf=>time+10, iat=>time+10, exp=>time-10, data=>'Hello'}, alg=>$alg);
    $decoded = eval { decode_jwt(key=>$k, token=>$token) };
    is($decoded, undef, "ignore_claims/1: alg=>'$alg'");
    $decoded = eval { decode_jwt(key=>$k, token=>$token, ignore_claims=>1) };
    is($decoded->{data}, 'Hello', "ignore_claims/2: alg=>'$alg'");

    $token = encode_jwt(key=>$k, auto_iat=>1, relative_exp=>14, relative_nbf=>3, payload=>{data=>'Hello'}, alg=>$alg);
    ($decoded_h, $decoded) = decode_jwt(key=>$k, token=>$token, decode_header=>1, leeway=>4);
    my $iat = $decoded->{iat};
    ok(time - $iat < 2, "auto_iat/1");
    is($decoded->{nbf}, $iat+3,  "relative_nbf/1: alg=>'$alg'");
    is($decoded->{exp}, $iat+14, "relative_exp/1: alg=>'$alg'");

    $token = encode_jwt(key=>$k, auto_iat=>1, relative_exp=>-4, relative_nbf=>-13, payload=>{data=>'Hello'}, alg=>$alg);
    ($decoded_h, $decoded) = decode_jwt(key=>$k, token=>$token, decode_header=>1, leeway=>14);
    $iat = $decoded->{iat};
    ok(time - $iat < 2, "auto_iat/2");
    is($decoded->{nbf}, $iat-13,  "relative_nbf/2: alg=>'$alg'");
    is($decoded->{exp}, $iat-4, "relative_exp/2: alg=>'$alg'");

    $token = encode_jwt(key=>$k, payload=>{}, alg=>$alg);
    $decoded = eval { decode_jwt(key=>$k, token=>$token, verify_iss=>sub { return 1 }) };
    is($decoded, undef, "decoded - missing_claims/1: alg=>'$alg'");
    $decoded = eval { decode_jwt(key=>$k, token=>$token, verify_sub=>sub { return 1 }) };
    is($decoded, undef, "decoded - missing_claims/2: alg=>'$alg'");
    $decoded = eval { decode_jwt(key=>$k, token=>$token, verify_aud=>sub { return 1 }) };
    is($decoded, undef, "decoded - missing_claims/3: alg=>'$alg'");
    $decoded = eval { decode_jwt(key=>$k, token=>$token, verify_jti=>sub { return 1 }) };
    is($decoded, undef, "decoded - missing_claims/4: alg=>'$alg'");
  }
}

{
  $token = eval { encode_jwt(payload=>$p, alg=>'none') };
  ok(!defined $token, "allow_none/1: alg=>'$alg'");
  $token = encode_jwt(payload=>$p, alg=>'none', allow_none=>1);
  ok($token, "allow_none/2: alg=>'$alg'");
  $decoded = eval { decode_jwt(token=>$token) };
  is($decoded, undef, "decoded - allow_none/1: alg=>'$alg'");
  $decoded = decode_jwt(token=>$token, allow_none=>1);
  is($decoded, $p, "decoded - allow_none/2: alg=>'$alg'");
}

done_testing;
