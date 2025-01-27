FROM debian:buster

RUN echo "uCentral client support"
RUN apt-get update && apt-get install --no-install-recommends -y \
  libev4 \
  openssh-client \
  ca-certificates \
  procps \
  curl \
  libjsoncpp-dev \
  busybox \
  && rm -rf /var/lib/apt/lists/*

RUN ln -s /bin/busybox /usr/local/bin/nslookup
RUN ln -s /bin/busybox /usr/local/bin/traceroute

RUN useradd -ms /bin/bash admin
RUN echo 'admin:broadcom' | chpasswd

COPY /ucentral-client /usr/local/bin/ucentral-client
COPY /rtty /usr/local/bin/
COPY /lib* /usr/local/lib/

COPY /version.jso[n] /etc/
COPY /schema.jso[n] /etc/
RUN ldconfig
RUN ls -l /usr/local/bin/ucentral-client

ENTRYPOINT ["/usr/local/bin/ucentral-client"]
