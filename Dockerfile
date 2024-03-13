FROM debian:buster
LABEL Description="Ucentral client (Build) environment"

ARG HOME /root
ARG EXTERNAL_LIBS ${HOME}/ucentral-external-libs

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
	libjsoncpp-dev

RUN git config --global http.sslverify false
RUN git clone https://github.com/DaveGamble/cJSON.git ${HOME}/ucentral-external-libs/cJSON/
RUN git clone https://libwebsockets.org/repo/libwebsockets ${HOME}/ucentral-external-libs/libwebsockets/
RUN git clone --recurse-submodules -b v1.50.0 --depth 1 --shallow-submodules https://github.com/grpc/grpc ${HOME}/ucentral-external-libs/grpc/
RUN git clone --recursive --branch v7.1.4 https://github.com/zhaojh329/rtty.git ${HOME}/ucentral-external-libs/rtty/

# The following libs should be prebuilt in docker-build-env img to speed-up
# recompilation of only the ucentral-client itself
RUN cd ${HOME}/ucentral-external-libs/cJSON/ && \
	mkdir build && \
	cd build && \
	cmake .. && \
	make -j 4 && \
	make install

RUN cd ${HOME}/ucentral-external-libs/libwebsockets/ && \
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
