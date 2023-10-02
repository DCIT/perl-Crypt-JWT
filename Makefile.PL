use 5.006;
use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME             => 'Crypt::JWT',
    VERSION_FROM     => 'lib/Crypt/JWT.pm',
    AUTHOR           => 'Karel Miko',
    ABSTRACT         => 'JSON Web Token',
    MIN_PERL_VERSION => '5.006',
    LICENSE          => 'perl',
    PREREQ_PM => {
      'JSON'                => 0,
      'Exporter'            => '5.57',     # we need: use Exporter 'import';
      'Compress::Raw::Zlib' => 0,
      'CryptX'              => '0.067',    # we need: Ed25519+X25519
      'Scalar::Util'        => 0,
      'Test::More'          => '0.88',     # we need: done_testing
    },
    META_MERGE => {
      resources => {
        repository => 'https://github.com/DCIT/perl-Crypt-JWT',
        bugtracker => 'https://github.com/DCIT/perl-Crypt-JWT/issues',
      },
    },
    dist => {
      PREOP => 'perldoc -u lib/Crypt/JWT.pm | pod2markdown > README.md',
      TARFLAGS => '--owner=0 --group=0 -cvf'
    },
);
