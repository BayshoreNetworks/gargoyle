#!/bin/sh

set -e
set -x

if [ -z "$DESTDIR" ];
then
DESTDIR=/
fi

if [ -z "$DEPLOY_TO" ];
then
DEPLOY_TO=/opt/gargoyle_pscand
fi

./autogen.sh

# do not pass in LDFLAGS or CXXFLAGS as this can spoil the autoconf checks
# TODO: perhaps we should decouple autoconf from make by splitting up the build.sh script
./configure --prefix=$DEPLOY_TO --bindir=$DEPLOY_TO \
    --build=i686-pc-linux-gnu --host=$CROSS_COMPILE DESTDIR=$DESTDIR \
    LDFLAGS= CXXFLAGS= 


mkdir -p ${DESTDIR}${DEPLOY_TO}/db/

if [ ! -f ${DESTDIR}${DEPLOY_TO}/db/gargoyle_attack_detect.db ]; then
   cp db/gargoyle_attack_detect.db ${DESTDIR}${DEPLOY_TO}/db/
fi

if [ ! -f ${DESTDIR}${DEPLOY_TO}/.gargoyle_config ]; then
   cp .gargoyle_config ${DESTDIR}${DEPLOY_TO}
fi

if [ ! -f ${DESTDIR}${DEPLOY_TO}/.gargoyle_internal_port_config ]; then
   cp .gargoyle_internal_port_config ${DESTDIR}${DEPLOY_TO}
fi

#if [ ! -f ${DESTDIR}${DEPLOY_TO}/sshd_regexes ]; then
#   cp lib/sshd_regexes ${DESTDIR}${DEPLOY_TO}
#fi

sed -e "s,APPDIR,$DEPLOY_TO,g" etc-init.d-gargoyle>${DESTDIR}/etc/init.d/gargoyle_pscand
chmod 770 ${DESTDIR}/etc/init.d/gargoyle_pscand

# If we are cross-compiling, we may not be ready to start gargoyle_pscand, so
# commenting this out.
#systemctl enable gargoyle_pscand
#systemctl daemon-reload

make clean
make LDFLAGS="$LDFLAGS" CXXFLAGS="$CXXFLAGS"
