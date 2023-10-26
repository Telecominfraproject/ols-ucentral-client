#!/bin/bash
UCENTRAL_DIR=${PWD}
EC_BUILD_DIR=${PWD}/src/ec-private
OUT_DIR=${UCENTRAL_DIR}/output
BIN_DIR=${OUT_DIR}/usr/sbin
LIB_DIR=${OUT_DIR}/lib

LIB_OPENSSL=openssl-1.1.1q
LIB_WEBSOCKETS=libwebsockets-4.1.4
LIB_CURL=curl-7.83.1
LIB_CJSON=cJSON-1.7.15

echo "+++++++++++++++++ check EC build environment +++++++++++++++++"
if [ ! "${PROJECT_NAME}" ] || [ ! "${SOURCE_PATH}" ]; then
  echo "Error! Please source 'build_env_init' for your build environment."
  exit
fi

cp -af ${UCENTRAL_DIR}/src/ucentral-client/* ${EC_BUILD_DIR}/ucentral-client

rm -rf ${OUT_DIR}

if [ ! -d output ]; then
  mkdir -p ${BIN_DIR}
  mkdir -p ${LIB_DIR}
fi

C_COMPILER="${TOOLCHAIN_PATH}/${CROSS_COMPILE}gcc ."

echo "+++++++++++++++++ openssl +++++++++++++++++"
cd ${EC_BUILD_DIR}
if [ ! -d openssl ]; then
  tar -xf ./archive/${LIB_OPENSSL}.tar.gz
  mv ${LIB_OPENSSL} openssl
fi

model_name=${D_MODEL_NAME}

if [ "$model_name" == 'ECS4130_AC5' ]; then
  platform=linux-aarch64
elif [ "$model_name" == 'ECS4125_10P' ]; then
  platform=linux-mips32
else
  echo "Error! The model ${model_name} is not in the support lists, please check."
  exit 1
fi

cd openssl
./Configure ${platform} --cross-compile-prefix=${CROSS_COMPILE} no-idea no-mdc2 no-rc5 no-ssl2 no-ssl3
make -j${nproc}

if [ "$?" -eq "0" ]; then
  cp -af libssl.so.1.1 libcrypto.so.1.1 ${LIB_DIR}
fi

echo "+++++++++++++++++ libwebsockets +++++++++++++++++"
cd ${EC_BUILD_DIR}
if [ ! -d libwebsockets ]; then
  tar -xf ./archive/${LIB_WEBSOCKETS}.tar.gz
  mv ${LIB_WEBSOCKETS} libwebsockets
  patch -s -N -p1 -d libwebsockets/lib < ./patch/libwebsockets/${LIB_WEBSOCKETS}.patch
fi

cd libwebsockets
cmake \
   -DOPENSSL_ROOT_DIR=${EC_BUILD_DIR}/openssl \
   -DCMAKE_C_COMPILER=${C_COMPILER}
make -j${nproc}

if [ "$?" -eq "0" ]; then
  cp -af lib/libwebsockets.so.17 ${LIB_DIR}
fi

echo "+++++++++++++++++ curl +++++++++++++++++"
cd ${EC_BUILD_DIR}

if [ ! -d curl ]; then
  tar -xf ./archive/${LIB_CURL}.tar.xz
  mv ${LIB_CURL} curl
  patch -s -N -p1 -d curl < ./patch/curl/${LIB_CURL}.patch
fi

cd curl
cmake -DCMAKE_C_COMPILER=${C_COMPILER} -DCMAKE_SHARED_LINKER_FLAGS=-L${EC_BUILD_DIR}/openssl
make

if [ "$?" -eq "0" ]; then
  cp -af ./lib/libcurl.so ${LIB_DIR}
  cp -af ./src/curl ${BIN_DIR}
fi

echo "+++++++++++++++++ cjson +++++++++++++++++"
cd ${EC_BUILD_DIR}

if [ ! -d cjson ]; then
  tar -xf ./archive/${LIB_CJSON}.tar.gz
  mv ${LIB_CJSON} cjson
fi

cd cjson
cmake -DCMAKE_C_COMPILER=${C_COMPILER}
make

if [ "$?" -eq "0" ]; then
  cp -af ./libcjson.so.1.7.15 ${LIB_DIR}
  cd ${LIB_DIR}
  mv libcjson.so.1.7.15 libcjson.so.1
fi

echo "+++++++++++++++++ ecapi +++++++++++++++++"
cd ${EC_BUILD_DIR}/ecapi
mkdir ${EC_BUILD_DIR}/ecapi/build
cd ${EC_BUILD_DIR}/ecapi/build

cmake -DCMAKE_C_COMPILER=${C_COMPILER} ..
make

if [ "$?" -eq "0" ]; then
  cp -af libecapi.so ${LIB_DIR}
fi

echo "+++++++++++++++++ ucentral-client +++++++++++++++++"
if [ ! -d ucentral ]; then
  mkdir -p ${EC_BUILD_DIR}/ucentral
fi

cp -af ${UCENTRAL_DIR}/src/ucentral-client ${EC_BUILD_DIR}/ucentral/ucentral-client
cp -af ${EC_BUILD_DIR}/patch/ucentral/* ${EC_BUILD_DIR}/ucentral
mkdir -p ${EC_BUILD_DIR}/ucentral/build
cd ${EC_BUILD_DIR}/ucentral/build

cmake -DCMAKE_C_COMPILER=${C_COMPILER} ..
make

if [ "$?" -eq "0" ]; then
  cp -af ucentral-client ${BIN_DIR}
fi

echo "+++++++++++++++++ Strip target binaries +++++++++++++++++"
${TOOLCHAIN_PATH}/${CROSS_COMPILE}strip ${BIN_DIR}/*
${TOOLCHAIN_PATH}/${CROSS_COMPILE}strip ${LIB_DIR}/*
