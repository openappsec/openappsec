FROM alpine

RUN apk add --no-cache -u busybox
RUN apk add --no-cache -u zlib
RUN apk add --no-cache bash
RUN apk add --no-cache libstdc++
RUN apk add --no-cache boost
RUN apk add --no-cache icu-libs
RUN apk add --no-cache curl
RUN apk add --no-cache libunwind
RUN apk add --no-cache gdb
RUN apk add --no-cache libxml2
RUN apk add --no-cache pcre2
RUN apk add --update coreutils

COPY install*.sh /nano-service-installers/
COPY entry.sh /entry.sh

RUN chmod +x entry.sh /nano-service-installers/*
RUN ln -s entry.sh cp-nano-agent

CMD [ "/cp-nano-agent" ]
