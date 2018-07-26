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

# Converts string to integer
int_version()
  {
    echo "$@" | awk -F. '{ printf("%03d%03d%03d\n", $1,$2,$3); }'; 
  }

# Check for journalctl and use it.
# If we're building on an older distro and it's missing, tell bruteforce to use auth.log
journalctl_exists()
  {
  set +e
  if [ ! $(which journalctl) ];then
    sed -i '/journal/ d' .gargoyle_ssh_bruteforce_config
    echo "log_entity:/var/log/auth.log">>.gargoyle_ssh_bruteforce_config
  fi
  set -e
  }

# Stop all gargoyle progs before updating
echo "Stopping running gargoyle processes"

for p in $(ps -ef |grep -v grep|grep gargoyle_ |awk {'print $2'})
    do kill -2 $p
done

mkdir -p ${DESTDIR}${DEPLOY_TO}/db/

if [ ! -f ${DESTDIR}${DEPLOY_TO}/db/gargoyle_attack_detect.db ]; then
   cp db/gargoyle_attack_detect.db ${DESTDIR}${DEPLOY_TO}/db/
else

# Schema update required for black_ip_list table

  if [ ! -f ${DESTDIR}${DEPLOY_TO}/gargoyle_pscand ]; then 
    echo "gargoyle_pscand binary not present, skipping sqlite update"
  else 
    current_version=$(${DESTDIR}${DEPLOY_TO}/gargoyle_pscand -v | awk {'print $3'} | tr -d '\n')
    new_version=1.5
    if [ "$(int_version "$current_version")" -lt "$(int_version "$new_version")" ]; then
      echo -e "Installed gargoyle version is $current_version, running sql schema update\n"
      /usr/bin/sqlite3 ${DESTDIR}${DEPLOY_TO}/db/gargoyle_attack_detect.db < utils/alter_black_list_table.sql 
    else
      echo -e "no need to update sqlite table\n"

    fi
  fi
fi

if [ ! -f ${DESTDIR}${DEPLOY_TO}/.gargoyle_config ]; then
   cp .gargoyle_config ${DESTDIR}${DEPLOY_TO}
fi

if [ ! -f ${DESTDIR}${DEPLOY_TO}/.gargoyle_internal_port_config ]; then
   cp .gargoyle_internal_port_config ${DESTDIR}${DEPLOY_TO}
fi

if [ ! -f ${DESTDIR}${DEPLOY_TO}/sshd_regexes ]; then
   cp lib/sshd_regexes ${DESTDIR}${DEPLOY_TO}
fi

if [ ! -f ${DESTDIR}${DEPLOY_TO}/.gargoyle_ssh_bruteforce_config ]; then
    journalctl_exists
    cp .gargoyle_ssh_bruteforce_config ${DESTDIR}${DEPLOY_TO}
fi

# Disable tornado lscan if package doesn't exist
if [ ! -d /usr/local/lib/python*/dist-packages/tornado ]  &&  [ ! -d /usr/lib/python*/dist-packages/tornado ] ; then
   sed -i s/'enabled:1/enabled:0'/g conf.d/tornado.conf
fi

if [ ! -d ${DESTDIR}${DEPLOY_TO}/conf.d ]; then
   cp -r conf.d ${DESTDIR}${DEPLOY_TO}
fi

sed -e "s,APPDIR,$DEPLOY_TO,g" etc-init.d-gargoyle>${DESTDIR}/etc/init.d/gargoyle_pscand
chmod 770 ${DESTDIR}/etc/init.d/gargoyle_pscand

# If we are cross-compiling, we may not be ready to start gargoyle_pscand, so
# commenting this out.
#systemctl enable gargoyle_pscand
#systemctl daemon-reload

# initscript enablement is now conditional
if [ $(which systemctl) ] && [ ! -f /.dockerenv ] ;then
   echo "Enabling init daemon via systemctl"
   systemctl enable gargoyle_pscand
   systemctl daemon-reload
else
   echo "systemctl not present, skipping script enable"
fi

make clean
make LDFLAGS="$LDFLAGS" CXXFLAGS="$CXXFLAGS"
