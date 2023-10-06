#!/bin/bash

echo "Building ucentral-client..."

if [ ! -f /.dockerenv ] ; then
	echo "Not inside docker container - err";
	exit 1;
fi

# restore envs
export HOME="/root"
export EXTERNAL_LIBS="$HOME/ucentral-external-libs"

rm -rf $HOME/deliverables 2>/dev/null;
rm -rf $HOME/ucentral 2>/dev/null;
mkdir $HOME/deliverables 2>/dev/null;
mkdir $HOME/ucentral;
cp -rf $HOME/ols-nos/src/ucentral-client/* $HOME/ucentral/

echo "Copying external deps libraries to /root/deliverables..."
# cJSON/websockers are part of build env, hence should be prebuilt already;
# but we still should copy deliverables (.so) to the target;
# explicit copy:
cp $EXTERNAL_LIBS/cJSON/build/lib* /root/deliverables || exit 1;
cp $EXTERNAL_LIBS/libwebsockets/build/lib/lib* /root/deliverables || exit 1;

# rtty is part of build env; copy rtty to target;
cp $EXTERNAL_LIBS/rtty/build/src/rtty /root/deliverables || exit 1;

ldconfig

echo "Making ucentral-client application..."
cd $HOME/ucentral/
{ make clean && make test && make UCENTRAL_PLATFORM=$UCENTRAL_PLATFORM -j4; } || exit 1;

echo "Installing ucentral-client to /root/deliverables"
cp ucentral-client /root/deliverables/

exit 0;
