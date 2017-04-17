#!/bin/bash
set -e

### setup exim4 ###
if [ "$MAILNAME" ]; then
	echo "MAIN_HARDCODE_PRIMARY_HOSTNAME = $MAILNAME" > /etc/exim4/exim4.conf.localmacros
	echo $MAILNAME > /etc/mailname
fi

if [ "$KEY_PATH" -a "$CERTIFICATE_PATH" ]; then
	if [ "$MAILNAME" ]; then
	  echo "MAIN_TLS_ENABLE = yes" >>  /etc/exim4/exim4.conf.localmacros
	else
	  echo "MAIN_TLS_ENABLE = yes" >>  /etc/exim4/exim4.conf.localmacros
	fi
	cp $KEY_PATH /etc/exim4/exim.key
	cp $CERTIFICATE_PATH /etc/exim4/exim.crt
	chgrp Debian-exim /etc/exim4/exim.key
	chgrp Debian-exim /etc/exim4/exim.crt
	chmod 640 /etc/exim4/exim.key
	chmod 640 /etc/exim4/exim.crt
fi

opts=(
	dc_local_interfaces "[0.0.0.0]:${PORT:-25} ; [::0]:${PORT:-25}"
	dc_other_hostnames ''
	dc_relay_nets "$(ip addr show dev eth0 | awk '$1 == "inet" { print $2 }')${RELAY_NETWORKS}"
)

if [ "$DISABLE_IPV6" ]; then 
        echo 'disable_ipv6=true' >> /etc/exim4/exim4.conf.localmacros
fi

if [ "$GMAIL_USER" -a "$GMAIL_PASSWORD" ]; then
	opts+=(
		dc_eximconfig_configtype 'smarthost'
		dc_smarthost 'smtp.gmail.com::587'
	)
	echo "*.google.com:$GMAIL_USER:$GMAIL_PASSWORD" > /etc/exim4/passwd.client
elif [ "$SES_USER" -a "$SES_PASSWORD" ]; then
	opts+=(
		dc_eximconfig_configtype 'smarthost'
		dc_smarthost "email-smtp.${SES_REGION:=us-east-1}.amazonaws.com::587"
	)
	echo "*.amazonaws.com:$SES_USER:$SES_PASSWORD" > /etc/exim4/passwd.client
# Allow to specify an arbitrary smarthost.
# Parameters: SMARTHOST_USER, SMARTHOST_PASSWORD: authentication parameters
# SMARTHOST_ALIASES: list of aliases to puth auth data for (semicolon separated)
# SMARTHOST_ADDRESS, SMARTHOST_PORT: connection parameters.
elif [ "$SMARTHOST_USER" -a "$SMARTHOST_PASSWORD" ] && [ "$SMARTHOST_ALIASES" -a "$SMARTHOST_ADDRESS" ] ; then
	opts+=(
		dc_eximconfig_configtype 'smarthost'
		dc_smarthost "${SMARTHOST_ADDRESS}::${SMARTHOST_PORT-25}"
	)
	rm -f /etc/exim4/passwd.client
	echo "$SMARTHOST_ALIASES;" | while read -d ";" alias; do
	  echo "${alias}:$SMARTHOST_USER:$SMARTHOST_PASSWORD" >> /etc/exim4/passwd.client
	done
elif [ "$RELAY_DOMAINS" ]; then
	opts+=(
		dc_relay_domains "${RELAY_DOMAINS}"
		dc_eximconfig_configtype 'internet'
	)
else
	opts+=(
		dc_eximconfig_configtype 'internet'
	)
fi

# allow to add additional macros by bind-mounting a file
if [ -f /etc/exim4/_docker_additional_macros ]; then
	cat /etc/exim4/_docker_additional_macros >> /etc/exim4/exim4.conf.localmacros
fi

echo "Update Exim4 configuration"
/bin/set-exim4-update-conf "${opts[@]}"

### setup and start tor service ###
# setup torrc
cat <<-EOF > /etc/tor/torrc 
VirtualAddrNetworkIPv4 100.64.0.0/10
AutomapHostsOnResolve 1
TransPort 9040
DNSPort 5353
EOF

# start tor service
echo "Starting the tor daemon"
service tor start

# modify resolv.conf
echo "nameserver 127.0.0.1" > /etc/resolv.conf

# setup tor iptables rules 
# Note: take care that you run this docker image with the capability NET_ADMIN, like i.e.
#       docker run --cap-add=NET_ADMIN ...

#set iptables variables
#your outgoing interface
_out_if="eth0"

#the UID that Tor runs as (varies from system to system)
_tor_uid="debian-tor"

#Tor's TransPort
_trans_port="9040"

#Tor's DNSPort
_dns_port="5353"

#Tor's VirtualAddrNetworkIPv4
_virt_addr="100.64.0.0/10"

#LAN destinations that shouldn't be routed through Tor
#Check reserved block.
_non_tor="127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16"

#Other IANA reserved blocks (These are not processed by tor and dropped by default)
_resv_iana="0.0.0.0/8 100.64.0.0/10 169.254.0.0/16 192.0.0.0/24 192.0.2.0/24 192.88.99.0/24 198.18.0.0/15 198.51.100.0/24 203.0.113.0/24 224.0.0.0/3"

### Don't lock yourself out after the flush
#iptables -P INPUT ACCEPT
#iptables -P OUTPUT ACCEPT

### flush iptables
iptables -F
iptables -t nat -F

### set iptables *nat
#nat .onion addresses
iptables -t nat -A OUTPUT -d $_virt_addr -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -j REDIRECT --to-ports $_trans_port

#nat dns requests to Tor
iptables -t nat -A OUTPUT -d 127.0.0.1/32 -p udp -m udp --dport 53 -j REDIRECT --to-ports $_dns_port

#don't nat the Tor process, the loopback, or the local network
iptables -t nat -A OUTPUT -m owner --uid-owner $_tor_uid -j RETURN
iptables -t nat -A OUTPUT -o lo -j RETURN

for _lan in $_non_tor; do
 iptables -t nat -A OUTPUT -d $_lan -j RETURN
done

for _iana in $_resv_iana; do
 if [ $_iana == "100.64.0.0/10" ]
 then
   ip ro add $_iana dev lo
 else
   ip ro add blackhole $_iana
 fi
 iptables -t nat -A OUTPUT -d $_iana -j RETURN
done

#redirect whatever fell thru to Tor's TransPort
iptables -t nat -A OUTPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -j REDIRECT --to-ports $_trans_port

### set iptables *filter
#*filter INPUT
iptables -A INPUT -m state --state ESTABLISHED -j ACCEPT
iptables -A INPUT -i lo -j ACCEPT

#grant ssh access for remote machines
#iptables -A INPUT -i $_out_if -p tcp --dport 22 -m state --state NEW -j ACCEPT

#grant smtp access for remote machines
iptables -A INPUT -i $_out_if -p tcp --dport 25 -m state --state NEW -j ACCEPT

iptables -A INPUT -j DROP

#*filter FORWARD
iptables -A FORWARD -j DROP

#*filter OUTPUT
#possible leak fix. See warning.
iptables -A OUTPUT -m state --state INVALID -j DROP

iptables -A OUTPUT -m state --state ESTABLISHED -j ACCEPT

#allow Tor process output
iptables -A OUTPUT -o $_out_if -m owner --uid-owner $_tor_uid -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -m state --state NEW -j ACCEPT

#allow loopback output
iptables -A OUTPUT -d 127.0.0.1/32 -o lo -j ACCEPT

#tor transproxy magic
iptables -A OUTPUT -d 127.0.0.1/32 -p tcp -m tcp --dport $_trans_port --tcp-flags FIN,SYN,RST,ACK SYN -j ACCEPT

#allow access to lan hosts in $_non_tor
#these 3 lines can be ommited
for _lan in $_non_tor; do
 iptables -A OUTPUT -d $_lan -j ACCEPT
done

#Log & Drop everything else.
iptables -A OUTPUT -j LOG --log-prefix "Dropped OUTPUT packet: " --log-level 7 --log-uid
iptables -A OUTPUT -j DROP

#Set default policies to DROP
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP

### run docker CMD ###
exec "$@"
