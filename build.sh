#!/bin/sh

DEPLOY_TO=/opt/gargoyle_pscand
./autogen.sh
./configure --prefix=$DEPLOY_TO --bindir=$DEPLOY_TO

mkdir -p $DEPLOY_TO/db/

if [ ! -f $DEPLOY_TO/db/port_scan_detect.db ]; then
   cp db/port_scan_detect.db $DEPLOY_TO/db/
fi

if [ ! -f $DEPLOY_TO/.gargoyle_config ]; then
   cp .gargoyle_config $DEPLOY_TO
fi

sed -e "s,APPDIR,$DEPLOY_TO,g" etc-init.d-gargoyle>/etc/init.d/gargoyle_pscand
chmod 770 /etc/init.d/gargoyle_pscand
systemctl enable gargoyle_pscand
systemctl daemon-reload

make clean
make
