FROM arm64v8/debian:buster

RUN apt-get update -q -y && apt-get -q -y --no-install-recommends install \
    build-essential \
    fakeroot \
    dpkg-dev \
    dh-exec \
    debhelper
