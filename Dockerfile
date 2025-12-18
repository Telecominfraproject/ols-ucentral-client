FROM debian:bullseye
LABEL Description="Ucentral client (Build) environment"

ARG HOME /root
ARG SCHEMA="4.1.0-rc1"
ARG SCHEMA_VERSION="v${SCHEMA}"
ARG SCHEMA_ZIP_FILE="${SCHEMA_VERSION}.zip"
ARG SCHEMA_UNZIPPED="ols-ucentral-schema-${SCHEMA}"
ARG OLS_SCHEMA_SRC="https://github.com/Telecominfraproject/ols-ucentral-schema/archive/refs/tags/${SCHEMA_ZIP_FILE}"
SHELL ["/bin/bash", "-c"]

RUN apt-get update -q -y  && apt-get -q -y --no-install-recommends install \
	build-essential \
	g++ \
	gcc \
	cmake \
	curl \
	libcurl4-openssl-dev \
	libev-dev \
	libssl-dev \
	libnl-route-3-dev \
	libnl-3-dev \
	apt-utils \
	git \
	wget \
	autoconf \
	libtool \
	pkg-config \
	libjsoncpp-dev \
        unzip \
        python3 \
        python3-jsonschema

RUN git config --global http.sslverify false
RUN git clone https://github.com/DaveGamble/cJSON.git ${HOME}/ucentral-external-libs/cJSON/
RUN git clone https://libwebsockets.org/repo/libwebsockets ${HOME}/ucentral-external-libs/libwebsockets/
RUN git clone --recurse-submodules -b v1.50.0 --depth 1 --shallow-submodules https://github.com/grpc/grpc ${HOME}/ucentral-external-libs/grpc/
RUN git clone --recursive --branch v7.1.4 https://github.com/zhaojh329/rtty.git ${HOME}/ucentral-external-libs/rtty/
ADD ${OLS_SCHEMA_SRC} /tmp/


# The following libs should be prebuilt in docker-build-env img to speed-up
# recompilation of only the ucentral-client itself
RUN cd ${HOME}/ucentral-external-libs/cJSON/ && \
	mkdir build && \
	cd build && \
	cmake .. && \
	make -j 4 && \
	make install

RUN cd ${HOME}/ucentral-external-libs/libwebsockets/ && \
        git branch --all && \
        git checkout a9b8fe7ebf61b8c0e7891e06e70d558412933a33 && \
	mkdir build && \
	cd build && \
	cmake .. && \
	make -j 4 && \
	make install

RUN cd ${HOME}/ucentral-external-libs/grpc/ && \
	mkdir cbuild && \
	cd cbuild && \
	cmake -DgRPC_INSTALL=ON \
	      -DgRPC_BUILD_TESTS=OFF \
	      -DCMAKE_INSTALL_PREFIX=/usr/local \
		.. && \
	make -j4 && \
	make install

RUN cd ${HOME}/ucentral-external-libs/rtty/ && \
	mkdir build && \
	cd build && \
	cmake .. && \
	make -j4

RUN unzip /tmp/${SCHEMA_ZIP_FILE} -d ${HOME}/ucentral-external-libs/

RUN cd ${HOME}/ucentral-external-libs/ && \
    mv ${SCHEMA_UNZIPPED} ols-ucentral-schema
