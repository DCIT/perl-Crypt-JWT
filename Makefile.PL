use 5.006;
use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME         => 'Crypt::JWT',
    AUTHOR       => 'Karel Miko',
    VERSION_FROM => 'lib/Crypt/JWT.pm',
    ABSTRACT     => 'JSON Web Token',
    LICENSE      => 'perl',
    PREREQ_PM    => {
      'MIME::Base64'        => '3.11',     # (en|de)code_base64url
      'JSON::MaybeXS'       => '1.003005', # (en|de)code_json
      'Exporter'            => '5.59',     # we need: use Exporter 'import';
      'Compress::Raw::Zlib' => 0,
      'CryptX'              => '0.024',
    },
    MIN_PERL_VERSION => '5.006',
    META_MERGE       => {
      resources => {
        repository => 'https://github.com/DCIT/perl-Crypt-JWT',
      },
    },
    dist => {
      PREOP    => 'pod2text lib/Crypt/JWT.pm > README',
      TAR      => 'ptar',
      TARFLAGS => '-c -C -f'
      #TARFLAGS => '--owner=0 --group=0 -cvf',
    },
);
