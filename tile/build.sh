#!/bin/bash
echo Running configure
LIBS="-lgxio -ltmc" ./configure --host=tile --disable-gccmarch-native \
  --without-libpcap \
  --with-libyaml-includes=/home/decanio/work/TileGX/github/yaml/include \
  --with-libyaml-libraries=/home/decanio/work/TileGX/github/yaml/src/.libs \
  --with-libmagic-includes=/home/decanio/work/TileGX/github/libmagic/src \
  --with-libmagic-libraries=/home/decanio/work/TileGX/github/libmagic/src/.libs
echo Patching results
patch config.h tile/config.h.diff
# MDE4.0alpha11 messes up CFLAGS in src/Makefile and add -static to LDFLAGS
patch src/Makefile tile/Makefile.static.diff
echo building Suricata
make clean
make
