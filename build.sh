#!/bin/sh

MYPREFIX=/opt/gargoyle_pscand
./autogen.sh
./configure --prefix=$MYPREFIX --bindir=$MYPREFIX
make clean
