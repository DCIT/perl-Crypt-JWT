@echo off
call :%*
goto :eof

rem cygwin setup.exe params
rem -q --quiet-mode     Unattended setup mode
rem -g --upgrade-also   also upgrade installed packages

:perl_setup

if "%perl_type%" == "cygwin32" (
  start /wait c:\cygwin\setup-x86.exe -q -g -P perl -P make -P gcc -P gcc-g++ -P libcrypt-devel -P libnsl-devel
  set "PATH=C:\cygwin\usr\local\bin;C:\cygwin\bin;%PATH%"
) else if "%perl_type%" == "cygwin64" (
  start /wait c:\cygwin64\setup-x86_64.exe -q -g -P perl -P make -P gcc -P gcc-g++ -P libcrypt-devel -P libnsl-devel
  set "PATH=C:\cygwin64\usr\local\bin;C:\cygwin64\bin;%PATH%"
) else if "%perl_type%" == "strawberry_gh" (
  if "%perl_version%" == "5.40" (
    echo Going to download "%download_url%"
    wget -nv https://github.com/StrawberryPerl/Perl-Dist-Strawberry/releases/download/SP_54001_64bit_UCRT/strawberry-perl-5.40.0.1-64bit-portable.zip -O downloaded-strawberry.zip
  ) else if "%perl_version%" == "5.38" (
    echo Going to download "%perl_version%"
    wget -nv https://github.com/StrawberryPerl/Perl-Dist-Strawberry/releases/download/SP_53822_64bit/strawberry-perl-5.38.2.2-64bit-portable.zip -O downloaded-strawberry.zip
  ) else if "%perl_version%" == "5.36" (
    echo Going to download "%perl_version%"
    wget -nv https://github.com/StrawberryPerl/Perl-Dist-Strawberry/releases/download/SP_53631_64bit/strawberry-perl-5.36.3.1-64bit-portable.zip -O downloaded-strawberry.zip
  ) else (
    echo FATAL unexpected value "%perl_version%"
  )
  7z x downloaded-strawberry.zip -oc:\spperl\
  set "PATH=c:\spperl\perl\site\bin;c:\spperl\perl\bin;c:\spperl\c\bin;%PATH%"
) else if "%perl_type%" == "strawberry" (
  wget -q http://strawberryperl.com/download/%perl_version%/strawberry-perl-%perl_version%-%perl_bits%bit-portable.zip -O downloaded-strawberry.zip
  7z x downloaded-strawberry.zip -oc:\spperl\
  set "PATH=c:\spperl\perl\site\bin;c:\spperl\perl\bin;c:\spperl\c\bin;%PATH%"
) else if "%perl_type%" == "strawberry_old" (
  wget -q http://strawberryperl.com/download/%perl_version%/strawberry-perl-%perl_version%-portable.zip -O downloaded-strawberry.zip
  7z x downloaded-strawberry.zip -oc:\spperl\
  set "PATH=c:\spperl\perl\site\bin;c:\spperl\perl\bin;c:\spperl\c\bin;%PATH%"
) else (
  echo.Unknown perl type "%perl_type%"! 1>&2
  exit /b 1
)

wget -q --no-check-certificate https://cpanmin.us/ -O downloaded-cpanm
set cpanm=perl downloaded-cpanm
set perl=perl

for /f "usebackq delims=" %%d in (`perl -MConfig -e"print $Config{make}"`) do set make=%%d

:eof
