ARG VERSION
FROM ubuntu:$VERSION

RUN mkdir -p output/
COPY scripts/ /
RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y libboost-all-dev libssl-dev libpcre2-dev libxml2-dev libgtest-dev libgmock-dev libcurl4-gnutls-dev 
RUN apt-get install -y cmake build-essential
RUN chmod +x build_artifacts.sh
ENTRYPOINT /build_artifacts.sh

