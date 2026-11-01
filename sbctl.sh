#!/bin/sh
# Transparent proxy for LAN devices with sing-box on iptables-only firmware (e.g. Xiaomi stock):
# LAN traffic goes to the redirect or tproxy inbound (see MODE) and LAN DNS to the dns-in inbound,
# except reserved destinations, China IPs, IPs in $DIRECT_IP and blacklisted devices.
#
# Usage: sbctl.sh start|stop|restart|status|watchdog|fw_start|fw_stop|update_cnip
#   watchdog     restart sing-box if it died, e.g. from cron: * * * * * /data/sing-box/sbctl.sh watchdog
#   fw_start     only (re)apply firewall rules, e.g. after a firewall reload; needs sing-box running
#   fw_stop      only remove firewall rules
#   update_cnip  download the China IP rule-set and reapply the rules

SB_DIR=/data/sing-box
# The binary runs from RAM; start extracts it from $SB_XZ when missing or when $SB_XZ is newer.
SB_BIN=/tmp/bin/sing-box
SB_XZ=$SB_DIR/sing-box.xz
# All .json files in $CONF_DIR (base.json, outbounds.json) are loaded and merged in filename order.
# Keep only config files there; a stray .json would be merged in and likely break startup.
CONF_DIR=$SB_DIR/conf
SB_LOG=/dev/null
PID_FILE=/var/run/sing-box.pid

LAN_IF=br-lan
# IPv4 source subnets proxied besides $LAN_IF's own subnet.
EXTRA_LAN_IPV4="192.168.68.0/24 192.168.69.0/24"
# 1 also proxies IPv6 from $LAN_IF; needs the same ip6tables support as IPv4.
IPV6=1

# redir   TCP via REDIRECT; UDP other than DNS is not proxied
# tproxy  TCP and UDP via TPROXY
# mixed   TCP via REDIRECT, UDP via TPROXY
MODE=tproxy

# Must match config.json.
REDIR_PORT=7892
TPROXY_PORT=7893
DNS_PORT=1053
MIXED_PORT=7890
FAKEIP_IPV4=198.18.0.0/15

# TPROXY-marked packets are routed to the local machine through this table. The mark must
# differ from route.default_mark in config.json (7894).
TPROXY_MARK=$REDIR_PORT
ROUTE_TABLE=100

# Only these destination ports are proxied (multiport allows at most 15); fake IPs are
# proxied on every port. Empty proxies every port.
PROXY_PORTS=22,53,80,123,143,194,443,465,587,853,993,995,5222,8080,8443

# One MAC per line, # starts a comment; these devices bypass the proxy and DNS hijack.
MAC_BLACKLIST=$SB_DIR/mac_blacklist
# One IPv4/IPv6 address or CIDR per line, # starts a comment; these destinations bypass sing-box.
DIRECT_IP=$SB_DIR/direct_ip
# Destinations in this rule-set bypass sing-box entirely. Same data as config.json's geoip-cn,
# so the firewall and the DNS rules agree on what a China IP is.
CN_SRS=$SB_DIR/geoip-cn.srs
CN_SRS_URL=https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs

RESERVED_IPV4="0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.168.0.0/16 224.0.0.0/4 240.0.0.0/4"
RESERVED_IPV6="::/128 ::1/128 ::ffff:0:0/96 64:ff9b::/96 100::/64 2001::/32 2001:20::/28 2001:db8::/32 2002::/16 fc00::/7 fe80::/10 ff00::/8"

CHAIN_TCP=SINGBOX_TCP
CHAIN_DNS=SINGBOX_DNS
CHAIN_TPROXY=SINGBOX_TPROXY
SET_BYPASS4=singbox_bypass4
SET_BYPASS6=singbox_bypass6

log() {
	echo "sbctl: $*" >&2
	logger -t sbctl "$*" 2>/dev/null
}

running() {
	[ -s "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null
}

case "$MODE" in
redir) REDIR_PROTOCOLS=tcp TPROXY_PROTOCOLS= ;;
tproxy) REDIR_PROTOCOLS= TPROXY_PROTOCOLS="tcp udp" ;;
mixed) REDIR_PROTOCOLS=tcp TPROXY_PROTOCOLS=udp ;;
*)
	echo "sbctl: MODE must be redir, tproxy or mixed, not '$MODE'" >&2
	exit 2
	;;
esac
[ -n "$REDIR_PROTOCOLS" ] && LISTEN_PORT=$REDIR_PORT || LISTEN_PORT=$TPROXY_PORT

listening() {
	netstat -lnt 2>/dev/null | grep -q ":$LISTEN_PORT "
}

list_file() {
	[ -f "$1" ] && sed 's/#.*//' "$1" | awk 'NF { print $1 }'
}

# Prints one iptables source match per line.
lan_matches() {
	if [ "$1" = iptables ]; then
		for net in $(ip -4 -o addr show dev "$LAN_IF" | awk '{ print $4 }') $EXTRA_LAN_IPV4; do
			echo "-s $net"
		done
	else
		echo "-i $LAN_IF"
	fi
}

cn_list() {
	if [ ! -s "$CN_SRS" ]; then
		log "$CN_SRS not found, China IPs go through sing-box; run: $0 update_cnip"
		return
	fi
	json=/tmp/sbctl-geoip-cn.json
	"$SB_BIN" rule-set decompile -o "$json" "$CN_SRS" && grep -oE '"[0-9a-fA-F:.]+/[0-9]+"' "$json" | tr -d '"'
	rm -f "$json"
}

load_bypass_sets() {
	{
		echo "create $SET_BYPASS4 hash:net family inet"
		echo "create $SET_BYPASS6 hash:net family inet6"
		{
			cn_list
			list_file "$DIRECT_IP"
		} | awk -v v4="$SET_BYPASS4" -v v6="$SET_BYPASS6" '{ print "add", (index($0, ":") ? v6 : v4), $0 }'
	} | ipset -! restore || log "ipset restore failed, check $DIRECT_IP for invalid entries"
}

# Adds RETURN rules for traffic that must not reach sing-box: $1 iptables/ip6tables, $2 table, $3 chain.
add_bypass() {
	if [ "$1" = iptables ]; then
		reserved=$RESERVED_IPV4 bypass_set=$SET_BYPASS4
	else
		reserved=$RESERVED_IPV6 bypass_set=$SET_BYPASS6
	fi
	for net in $reserved; do
		$1 -t $2 -A $3 -d "$net" -j RETURN
	done
	ipset list -n $bypass_set >/dev/null 2>&1 && $1 -t $2 -A $3 -m set --match-set $bypass_set dst -j RETURN
	for mac in $(list_file "$MAC_BLACKLIST"); do
		$1 -t $2 -A $3 -m mac --mac-source "$mac" -j RETURN
	done
}

# Sends $4 (tcp/udp) traffic in PREROUTING of table $2 to chain $3.
add_hook() {
	if [ -n "$PROXY_PORTS" ]; then
		$1 -t $2 -I PREROUTING -p $4 -m multiport --dports $PROXY_PORTS -j $3
		[ "$1" = iptables ] && $1 -t $2 -I PREROUTING -p $4 -d $FAKEIP_IPV4 -j $3
	else
		$1 -t $2 -I PREROUTING -p $4 -j $3
	fi
}

fw_family() {
	ipt=$1
	if [ -n "$REDIR_PROTOCOLS" ]; then
		$ipt -t nat -N $CHAIN_TCP
		add_bypass $ipt nat $CHAIN_TCP
		lan_matches $ipt | while read -r match; do
			$ipt -t nat -A $CHAIN_TCP -p tcp $match -j REDIRECT --to-ports $REDIR_PORT
		done
		add_hook $ipt nat $CHAIN_TCP tcp
	fi
	if [ -n "$TPROXY_PROTOCOLS" ]; then
		$ipt -t mangle -N $CHAIN_TPROXY
		# DNS is redirected to dns-in in the nat table instead.
		$ipt -t mangle -A $CHAIN_TPROXY -p udp --dport 53 -j RETURN
		$ipt -t mangle -A $CHAIN_TPROXY -p tcp --dport 53 -j RETURN
		add_bypass $ipt mangle $CHAIN_TPROXY
		lan_matches $ipt | while read -r match; do
			for protocol in $TPROXY_PROTOCOLS; do
				$ipt -t mangle -A $CHAIN_TPROXY -p $protocol $match -j TPROXY --on-port $TPROXY_PORT --tproxy-mark $TPROXY_MARK
			done
		done
		for protocol in $TPROXY_PROTOCOLS; do
			add_hook $ipt mangle $CHAIN_TPROXY $protocol
		done
		[ "$ipt" = iptables ] && ip=ip || ip="ip -6"
		$ip rule add fwmark $TPROXY_MARK table $ROUTE_TABLE
		$ip route add local default dev lo table $ROUTE_TABLE
	fi
	$ipt -t nat -N $CHAIN_DNS
	for mac in $(list_file "$MAC_BLACKLIST"); do
		$ipt -t nat -A $CHAIN_DNS -m mac --mac-source "$mac" -j RETURN
	done
	lan_matches $ipt | while read -r match; do
		$ipt -t nat -A $CHAIN_DNS -p udp $match -j REDIRECT --to-ports $DNS_PORT
		$ipt -t nat -A $CHAIN_DNS -p tcp $match -j REDIRECT --to-ports $DNS_PORT
	done
	# Inserted last so DNS is matched before the TCP chain, which also covers port 53.
	$ipt -t nat -I PREROUTING -p udp --dport 53 -j $CHAIN_DNS
	$ipt -t nat -I PREROUTING -p tcp --dport 53 -j $CHAIN_DNS
}

fw_stop() {
	for ipt in iptables ip6tables; do
		command -v $ipt >/dev/null || continue
		for table in nat mangle; do
			$ipt -t $table -S PREROUTING 2>/dev/null | grep -E -- "-j ($CHAIN_TCP|$CHAIN_DNS|$CHAIN_TPROXY)\$" | sed 's/^-A /-D /' |
				while read -r rule; do
					$ipt -t $table $rule
				done
		done
		for chain in $CHAIN_TCP $CHAIN_DNS; do
			$ipt -t nat -F $chain 2>/dev/null
			$ipt -t nat -X $chain 2>/dev/null
		done
		$ipt -t mangle -F $CHAIN_TPROXY 2>/dev/null
		$ipt -t mangle -X $CHAIN_TPROXY 2>/dev/null
	done
	for ip in "ip" "ip -6"; do
		while $ip rule del fwmark $TPROXY_MARK table $ROUTE_TABLE 2>/dev/null; do :; done
		$ip route flush table $ROUTE_TABLE 2>/dev/null
	done
	ipset destroy $SET_BYPASS4 2>/dev/null
	ipset destroy $SET_BYPASS6 2>/dev/null
}

ipv6_supported() {
	ip6tables -t nat -L PREROUTING -n >/dev/null 2>&1 &&
		ip6tables -j REDIRECT -h 2>/dev/null | grep -q -- '--to-ports' || return 1
	[ -z "$TPROXY_PROTOCOLS" ] || ip6tables -j TPROXY -h 2>/dev/null | grep -q -- '--on-port'
}

fw_start() {
	fw_stop
	load_bypass_sets
	fw_family iptables
	[ "$IPV6" = 1 ] || return 0
	if ipv6_supported; then
		fw_family ip6tables
	else
		log "ip6tables lacks nat, REDIRECT or TPROXY support, IPv6 is not proxied"
	fi
}

extract_bin() {
	if [ ! -f "$SB_XZ" ]; then
		[ -x "$SB_BIN" ] && return 0
		log "sing-box binary not found: neither $SB_BIN nor $SB_XZ exists"
		return 1
	fi
	[ -x "$SB_BIN" ] && [ ! "$SB_XZ" -nt "$SB_BIN" ] && return 0
	mkdir -p "${SB_BIN%/*}"
	if ! xz -dc "$SB_XZ" >"$SB_BIN.tmp" || ! chmod +x "$SB_BIN.tmp"; then
		rm -f "$SB_BIN.tmp"
		log "failed to extract $SB_XZ"
		return 1
	fi
	mv -f "$SB_BIN.tmp" "$SB_BIN"
	log "extracted $SB_XZ to $SB_BIN"
}

start() {
	if running; then
		log "already running"
		return 0
	fi
	extract_bin || return 1
	fw_stop
	command -v nohup >/dev/null && nohup=nohup || nohup=
	$nohup "$SB_BIN" run -D "$SB_DIR" -C "$CONF_DIR" >>"$SB_LOG" 2>&1 &
	echo $! >"$PID_FILE"
	i=0
	until listening; do
		i=$((i + 1))
		if ! running || [ $i -gt 30 ]; then
			log "sing-box failed to start, see: $SB_BIN check -D $SB_DIR -C $CONF_DIR"
			stop
			return 1
		fi
		sleep 1
	done
	fw_start
	log "started"
}

stop() {
	fw_stop
	if running; then
		pid=$(cat "$PID_FILE")
		kill "$pid"
		i=0
		while kill -0 "$pid" 2>/dev/null && [ $i -lt 10 ]; do
			sleep 1
			i=$((i + 1))
		done
		kill -9 "$pid" 2>/dev/null
	fi
	rm -f "$PID_FILE"
}

mib() {
	awk -v kb="$1" 'BEGIN { printf "%.1f MiB", kb / 1024 }'
}

# Prints the kB value of field $1 in a /proc file like status or meminfo.
proc_kb() {
	awk -v key="$1:" '$1 == key { print $2 }' "$2"
}

show_status() {
	pid=$(cat "$PID_FILE")
	hz=$(getconf CLK_TCK 2>/dev/null || echo 100)
	stat=$(cat /proc/$pid/stat)
	# Fields after "pid (comm) " start at field 3, so starttime (field 22) is the 20th.
	start=$(echo "${stat##*) }" | awk '{ print $20 }')
	elapsed=$(awk -v start="$start" -v hz="$hz" '{ print int($1 - start / hz) }' /proc/uptime)
	uptime=$(awk -v s="$elapsed" 'BEGIN { printf "%dd %02d:%02d", s / 86400, s % 86400 / 3600, s % 3600 / 60 }')
	echo "running, pid $pid, uptime $uptime"
	echo "memory: rss $(mib "$(proc_kb VmRSS /proc/$pid/status)")," \
		"peak $(mib "$(proc_kb VmHWM /proc/$pid/status)")" \
		"(system available $(mib "$(proc_kb MemAvailable /proc/meminfo)") of $(mib "$(proc_kb MemTotal /proc/meminfo)"))"
}

update_cnip() {
	proxy=
	running && proxy="-x http://127.0.0.1:$MIXED_PORT"
	if ! curl -fsSL $proxy -o "$CN_SRS.tmp" "$CN_SRS_URL" || ! "$SB_BIN" rule-set decompile -o /dev/null "$CN_SRS.tmp"; then
		rm -f "$CN_SRS.tmp"
		log "failed to download $CN_SRS_URL"
		return 1
	fi
	mv -f "$CN_SRS.tmp" "$CN_SRS"
	log "updated $CN_SRS"
	if listening; then
		fw_start
	fi
}

case "$1" in
start) start ;;
stop) stop ;;
restart)
	stop
	start
	;;
status)
	if running; then
		show_status
	else
		echo "stopped"
		exit 1
	fi
	;;
watchdog)
	if ! running; then
		log "sing-box is not running, restarting"
		start
	fi
	;;
fw_start)
	if ! listening; then
		log "nothing listens on port $LISTEN_PORT, rules not applied"
		exit 1
	fi
	fw_start
	;;
fw_stop) fw_stop ;;
update_cnip) update_cnip ;;
*)
	echo "usage: $0 start|stop|restart|status|watchdog|fw_start|fw_stop|update_cnip" >&2
	exit 2
	;;
esac
