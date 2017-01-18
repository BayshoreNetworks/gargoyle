#!/bin/sh

MYPREFIX=/opt/gargoyle_pscand
./autogen.sh
./configure --prefix=$MYPREFIX --bindir=$MYPREFIX

mkdir -p $MYPREFIX/db/

if [ ! -f $MYPREFIX/db/port_scan_detect.db ]; then
   cp db/port_scan_detect.db $MYPREFIX/db/
fi

if [ ! -f $MYPREFIX/.gargoyle_config ]; then
   cp .gargoyle_config $MYPREFIX
fi

cp etc-init.d-gargoyle /etc/init.d/gargoyle_pscand
chmod 770 /etc/init.d/gargoyle_pscand
systemctl enable gargoyle_pscand
systemctl daemon-reload

make clean
make
