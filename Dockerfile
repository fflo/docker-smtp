FROM debian:stretch-slim

# smtp-tor
MAINTAINER Florian Fuessl "flo@degnet.de"

# forked from docker-smtp
# MAINTAINER Oluwaseun Obajobi "oluwaseun.obajobi@namshi.com"

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive \
       apt-get install --no-install-recommends -y exim4-daemon-light tor iptables iproute2 && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* && \
    find /var/log -type f | while read f; do echo -ne '' > $f; done;

COPY entrypoint.sh /bin/
COPY set-exim4-update-conf /bin/

RUN chmod a+x /bin/entrypoint.sh && \
    chmod a+x /bin/set-exim4-update-conf

EXPOSE 25
ENTRYPOINT ["/bin/entrypoint.sh"]
CMD ["exim", "-bd", "-q15m", "-v"]
