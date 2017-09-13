# How To
#
# Build image
#  docker build -t bned_mme .
#  docker save bned_mme | gzip > bned_mme.tar.gz
# Import image:
#  gunzip -c bned_mme.tar.gz | docker load
#  docker create --name bned_mme --network host --hostname bned-mme bned_mme

FROM ubuntu:16.04
MAINTAINER blackned

CMD ["/usr/local/bin/mme","-c","/usr/local/etc/oai/mme.conf"]
WORKDIR /tmp/

RUN apt update \
 && apt install -y sudo psmisc \
 && apt install -y build-essential autoconf libtool check cmake nettle-bin nettle-dev libgnutls-dev libssl-dev libxml2-dev libconfig8-dev libgcrypt11-dev \
 && apt install -y python mscgen libsctp-dev libmnl-dev bison flex

COPY asn1c/  /root/openair-cn/asn1c/
COPY libgtpnl/  /root/openair-cn/libgtpnl/
COPY freeDiameter/  /root/openair-cn/freeDiameter/
COPY src/ /root/openair-cn/src/
COPY build/ /root/openair-cn/build/
COPY scripts/ /root/openair-cn/scripts/
COPY etc/ /root/openair-cn/etc/

# Install libgtpnl
RUN cd /root/openair-cn/libgtpnl \
 && autoreconf -fi \
 && ./configure \
 && make -j`nproc` \
 && make install \
 && cd / \
 && rm -rf /root/openair-cn/libgtpnl \
 && ldconfig

# Install asn1c
RUN cd /root/openair-cn/asn1c \
 && ./configure \
 && make -j`nproc` \
 && make install \
 && cd / \
 && rm -rf /root/openair-cn/asn1c

# Install freeDiameter
RUN cd /root/openair-cn/freeDiameter \
 && mkdir build && cd build \
 && cmake -DCMAKE_BUILD_TYPE:STRING=Release -DCMAKE_INSTALL_PREFIX:PATH=/usr/local ../ \
 && make -j`nproc` \
 && make install \
 && cd / \
 && rm -rf /root/openair-cn/freeDiameter \
 && ldconfig

# Install MME
RUN cd /root/openair-cn/scripts/ \
 && ./build_mme -c \
 && cd /root/openair-cn/scripts/ \
 && ./check_mme_s6a_certificate /usr/local/etc/oai/freeDiameter bned-mme.ridux.local
