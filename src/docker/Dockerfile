FROM arm64v8/debian:buster

RUN echo "uCentral client support"
RUN apt-get update && apt-get install --no-install-recommends -y \
  libev4 \
  openssh-client \
  ca-certificates \
  procps \
  curl \
  libjsoncpp-dev \
  busybox \
  libhiredis0.14 \
  && rm -rf /var/lib/apt/lists/*

RUN ln -s /bin/busybox /usr/local/bin/nslookup
RUN ln -s /bin/busybox /usr/local/bin/traceroute

RUN useradd -ms /bin/bash admin
RUN echo 'admin:broadcom' | chpasswd

COPY /ucentral-client /usr/local/bin/ucentral-client
COPY /rtty /usr/local/bin/
COPY /lib* /usr/local/lib/

# Install root CA certificate for development purposes
COPY /ca-cert.pem /usr/local/share/ca-certificates/ca-cert.crt
COPY /tip-cert.pem /usr/local/share/ca-certificates/tip-cert.crt
RUN update-ca-certificates

RUN ldconfig
RUN ls -l /usr/local/bin/ucentral-client

ENTRYPOINT ["/usr/local/bin/ucentral-client"]
