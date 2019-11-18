#!/bin/bash -e
#
# Ladders, a security level based firewall script for iptables
#  -- pallair at magex.hu
#
# = Licence =
# CC BY-SA 3.0
# * http://creativecommons.org/licenses/by-sa/3.0/
#

IPT='iptables'
POLICY_DROP=1
#cd ${0%/*}

function net2matcher () {
	direction=$1
	net=$2
	case $net in
		d:*)
			net=${net/d:}
			direction=${direction/d/o}
			direction=${direction/s/i}
			;;
	esac
	case `echo $net | grep -o '\^' | wc -l` in
		0)
			echo "-$direction $net"
			;;
		1)
			echo "-$direction ${net%^*} -p ${net#*^}"
			;;
		2)
			echo "-$direction ${net%%^*} -p `expr match $net '.*^\(.*\)^.*'`"\
				 "-m multiport --${direction}port ${net##*^}"
		;;
	esac
}

function is_local_address () {
	localipaddrs="`ip ro sh ta local | cut -d' ' -f2`"
	which gethostip >/dev/null || return 0
	ipaddr=`gethostip -d $1`
	for localipaddr in $localipaddrs; do
		case $localipaddr in
			($ipaddr)
				return 0
		esac
	done
	return 1
}

function mark_src_sl () {
	org=$1 sl=$2; shift; shift
	for net in $*; do
		$IPT -A ${org}_mark_src_sl `net2matcher s $net` -j MARK --set-mark 0x$sl
	done
}

function match_dst () {
	org=$1 sl=$2; shift; shift
	for net in $*; do
		#
		# Az INPUT chainbe csak azt kell betenni aminek ertelme van ott.
		# Az IP tartomanyokat egyelore valogatas nelkul betesszuk, talan lefed helyi IP cimet is;
		# ezt nem vizsgaljuk, bar lehetne.
		#
		if [ $_PROTECT_LOCALHOST -ge 1 ]; then
			if echo ${net%%^*} | grep -vq :; then
				if echo ${net%%^*} | grep -q / || is_local_address ${net%%^*}; then
					$IPT -A INPUT `net2matcher d $net` -j ${ORG}_as_target
				fi
			fi
		fi
		$IPT -A FORWARD `net2matcher d $net` -j ${ORG}_as_target
		$IPT -A ${ORG}_as_target `net2matcher d $net` -m mark --mark 0x${sl}/0x${sl} -j ACCEPT
	done
}

function match_brk () {
	org=$1; shift
	for net in $*; do
		$IPT -I ${ORG}_as_target `net2matcher d $net` -j RETURN
	done
}

function set_env_if_labeled () {
	if [ ${1:0:1} == '.' ]; then
		NAME=${1:1}
		shift
		eval "$ORG[$NAME]='$*'"
		return 0
	fi
	return 1
}

function src () {
	SL=$1; shift
	[ "$DEBUG" ] && printf "<= %-8s %2x %s\n" $ORG 0x$SL $*
	set_env_if_labeled $* && shift
	mark_src_sl $ORG $SL $*
}
function dst () {
	SL=$1; shift
	[ "$DEBUG" ] && printf "=> %-8s %2x %s\n" $ORG 0x$SL $*
	set_env_if_labeled $* && shift
	match_dst $ORG $SL $*
}
function net () {
	SL=$1; shift
	[ "$DEBUG" ] && printf "<> %-8s %2x %s\n" $ORG 0x$SL $*
	set_env_if_labeled $* && shift
	mark_src_sl $ORG $SL $*
	match_dst $ORG $SL $*
}
function brk () {
	[ "$DEBUG" ] && printf "!! %-8s %s\n" $ORG $*
	set_env_if_labeled $* && shift
	match_brk $ORG $*
}
function erroff () { set +e; }
function erron () { set -e; }

function org () {
	export ORG=$1
	# http://stackoverflow.com/questions/10806357/associative-arrays-are-local-by-default
	#declare -gA NET_$ORG
	[ "$DEBUG" ] && echo "** $ORG **"
	$IPT -N ${ORG}_mark_src_sl
	# eloszor is kinullazzuk a hozott mark-ot
	$IPT -A ${ORG}_mark_src_sl -j MARK --set-mark 0x0
	$IPT -N ${ORG}_as_target
	$IPT -A ${ORG}_as_target -j ${ORG}_mark_src_sl
}

OP=${1:-restart}
_PROTECT_LOCALHOST=0
grep -Eqi '^PROTECT_LOCALHOST=(1|on|yes)$' /etc/fw/ladders.sh && _PROTECT_LOCALHOST=1
case $OP in
	start)
		[ $_PROTECT_LOCALHOST -ge 1 ] && $IPT -A INPUT -i lo -j ACCEPT
		[ $_PROTECT_LOCALHOST -ge 1 ] && $IPT -A INPUT -m state --state ESTABLISHED,RELATED,INVALID -j ACCEPT
		$IPT -A FORWARD -m state --state ESTABLISHED,RELATED,INVALID -j ACCEPT
		. /etc/fw/ladders.sh
		[ $_PROTECT_LOCALHOST -ge 1 ] && $IPT -A INPUT -j ULOG --ulog-prefix "INPUT DROP:"
		[ $_PROTECT_LOCALHOST -ge 1 -a $POLICY_DROP -ge 1 ] && $IPT -A INPUT -j DROP
		$IPT -A FORWARD -j ULOG --ulog-prefix "FORWARD DROP:"
		[ $POLICY_DROP -ge 1 ] && $IPT -A FORWARD -j DROP
		;;
	restart)
		$0 stop
		$0 start
		;;
	stop)
		$IPT -F
		$IPT -X
		;;
	*)
		echo "Usage: $0 {start|stop|restart}"
		;;
esac

exit 0
