divert(-1)
#
# Copyright (c) 1983 Eric P. Allman
# Copyright (c) 1988, 1993
#       The Regents of the University of California.  All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. All advertising materials mentioning features or use of this software
#    must display the following acknowledgement:
#       This product includes software developed by the University of
#       California, Berkeley and its contributors.
# 4. Neither the name of the University nor the names of its contributors
#    may be used to endorse or promote products derived from this software
#    without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#

#
#  This is a generic configuration file for 4.4 BSD-based systems.
#  If you want to customize it, copy it to a name appropriate for your
#  environment and do the modifications there.
#
#  The best documentation for this .mc file is:
#  /usr/src/contrib/sendmail/cf/README
#
divert(0)dnl
VERSIONID(`$FreeBSD: src/etc/sendmail/freebsd.mc,v 1.10.2.2 2000/10/19 21:17:28 gshapiro Exp $')
OSTYPE(freebsd6)dnl
DOMAIN(generic)dnl
FEATURE(mailertable, `hash -o /etc/mail/mailertable')dnl
FEATURE(access_db)dnl
FEATURE(`greet_pause',1000)dnl
define(`confCONNECTION_RATE_THROTTLE',`4')
define(`confCONNECTION_RATE_WINDOW_SIZE',`10')
FEATURE(virtusertable, `hash -o /etc/mail/virtusertable')dnl
FEATURE(local_lmtp)dnl
FEATURE(compat_check)dnl
define(`confLOG_LEVEL',`32')dnl
define(`LOCAL_MAILER_FLAGS', LOCAL_MAILER_FLAGS`+S'P)dnl
define(`confCW_FILE', `-o /etc/mail/local-host-names')dnl
define(`confNO_RCPT_ACTION', `add-to-undisclosed')dnl
dnl define(`confMAX_MIME_HEADER_LENGTH', `256/128')dnl
define(`confPRIVACY_FLAGS', `authwarnings,noexpn,novrfy')dnl
FEATURE(`dnsbl', `dnsbl.dmz', `"Messages from you Blocked. Please visit http://antispam.domain.my/?ip="$&{client_addr} ""')dnl
FEATURE(badmx)dnl
MAILER(local)dnl
MAILER(smtp)dnl
define(`confMAX_MESSAGE_SIZE',`10500000')dnl
define(`confDELIVERY_MODE',`background')
define(`confMAX_HOP',`20')
define(`confMAX_RCPTS_PER_MESSAGE',`10')
define(`confPRIVACY_FLAGS',`authwarnings,needmailhelo,needexpnhelo,needvrfyhelo,noexpn,restrictmailq,restrictqrun')
define(`confQUEUE_LA',`10')
define(`confREFUSE_LA',`20')
define(`confMAX_DAEMON_CHILDREN',`30')
define(`confDEF_CHAR_SET',`koi8-r')
define(`confNO_RCPT_ACTION',`add-apparently-to')
define(`confDONT_BLAME_SENDMAIL',`forwardfileingroupwritabledirpath')
define(`confSMTP_LOGIN_MSG',`$j Sendmail $v/$Z; $b\n"Use of this system for the delivery of UCE (a.k.a. SPAM), or any other"\n"message without the express permission of the system owner is prohibited."\n"Use of this system for third party relaying is prohibited." ')
define(`LUSER_RELAY',`local:postmaster')dnl
define(`VIRTUSER_CLASS', `T')
define(`VIRTUSER_ERR_NOUSER', 1)
define(`confTO_ICONNECT', `15s')dnl
define(`confTO_ACONNECT', `1m')dnl
define(`confTO_CONNECT', `30s')dnl
define(`confTO_INITIAL', `30s')dnl
define(`confTO_HELO', `30s')dnl
define(`confTO_MAIL', `30s')dnl
define(`confTO_RCPT', `30s')dnl
define(`confTO_DATAINIT', `1m')dnl
define(`confTO_DATABLOCK', `1m')dnl
define(`confTO_DATAFINAL', `1m')dnl
define(`confTO_RSET', `30s')dnl
define(`confTO_QUIT', `30s')dnl
define(`confTO_MISC', `30s')dnl
define(`confTO_COMMAND', `30s')dnl
define(`confTO_CONTROL', `30s')dnl
define(`confTO_STARTTLS', `2m')dnl
INPUT_MAIL_FILTER(`spamassassin', `S=local:/var/run/spamass-milter.sock, F=T, T=C:1m;S:2m;R:2m;E:5m')
dnl INPUT_MAIL_FILTER(`clmilter', `S=local:/var/run/clamav/clmilter.sock, F=, T=S:4m;R:4m')
define(`_FFR_MILTER',1)
dnl define(`confINPUT_MAIL_FILTERS', `spamassassin,clmilter')
define(`confINPUT_MAIL_FILTERS', `spamassassin')
define(`confMILTER_LOG_LEVEL',`2')

LOCAL_CONFIG
Ksyslog		syslog
#Khs		socket -T<TMPF> inet:532@10.6.204.218
Ksave macro
Kfindmx		bestmx -z: -T<TEMP>
#KdnsAmx	dns -R A -T<TEMP>
Kdnslook	dns -R A -T<TMP>
D{nullfrom}"undefined@undefined.domain"


#C{RejectHelo}	foo.bar.com localhost.localdomain
#Khelolook	dns -RA

LOCAL_RULESETS
SLocal_check_mail
R<>		$: <$&{nullfrom}>
R<$*>		$: $1 $(syslog local_check_mail:$1::$&{hname}::$&s $)
R$+ @ $*	$: <:$(findmx $2 $):><:>
R<:$+:$*><:$*>	<:$2><:$3 $(dnslook $1 $) :>
R<:><:$+:$*>	$: $1 $(dnslook $&i:$&{haddr}:MX:$1:$2.upd.dmz $)

R$*		$: <:$(findmx $&s $):><:>
R<:$+:$*><:$*>	<:$2><:$3 $(dnslook $1 $) :>
R<:><:$+:$*>	$: $1 $(dnslook $&i:$&{haddr}:HL:$&s:$1:$2.upd.dmz $)

R$*		$: $&f
R$@		$: $&{nullfrom}
#R$*		$: $1 $(syslog CheckFrom:$1 $)
R$+ @ $*	$: $(dnslook $&i:$&{haddr}:$1:$2.helobl.dmz. $: OK $)
R$*		$: $1 $(syslog CHECK_FROM: $1 $)
ROK		$@ OK
R127.0.0.12		$#error $@ 5.7.1 $: "550 Your HELO contains illegal chars combinations. Message blocked. http://antispam.domain.my/"
R127.0.0.208		$#error $@ 5.7.1 $: "550 Messages from your domain is blocked."
R127.0.0.209		$#error $@ 5.7.1 $: "550 Messages from your address is blocked."
R127.0.0.255		$#error $@ 4.7.1 $: "421 Remote host IP address is null. Connection Dropped."
R$+		$#error $@ 4.2.1 $: "421 Delivery Error. Please visit http://antispam.domain.my/?ip="$&{client_addr}"+"$&s""

SLocal_check_relay
R$*		$: $&_
# split incoming hostname[ipaddr]
R$*[$*]		$: $(save {haddr} $@ $2 $) $1
# $2 -> Hostaddr
# Saving $1
R$*		$: $(save {tmp} $@ $1 $)
# if $1 null -> Hostaddr -> Hostname
R$@		$: $(save {hname} $@ [$&{haddr}] $)
# restore $1
R$*		$: $&{tmp}
# if $1 is not null -> tmpvar -> Hostname
R$+		$: $(save {hname} $@ $&{tmp} $)
# Syslog to log
#R$*			$: $1 $(syslog RelayCheck:$&{client_addr}:$&{client_name}:$&_ $)

#R$*			$: $1 $(syslog RelayCheck:$&{haddr}:$&{hname} $)
R$*			$: <?> $(dnslook $&{haddr}:$&{hname}.fastbl.dmz. $: OK $)
R$*			$: $1 $(syslog CHECK_RELAY: $1 $)
R<?>OK			$: OKSOFAR
R<?>$+<TMP>		$: TMPOK

R<?>127.0.0.10		$#error $@ 5.7.1 $: "421 Too many connections from your host. Try again later."
R<?>127.0.0.13		$#error $@ 5.7.1 $: "550 Your Hostname contains illegal chars combinations. Message blocked. http://antispam.domain.my/"
R<?>127.0.0.210		$#error $@ 5.7.1 $: "550 Messages from your GeoZone is blocked. http://antispam.domain.my/"
R<?>127.0.0.211		$#error $@ 5.7.1 $: "550 Messages from your host is blocked."
R<?>127.0.0.255		$#error $@ 4.7.1 $: "421 Remote host IP address is null. Connection Dropped."

#R<?>127.0.0.10		$#error $@ 4.7.1 $: "421 Too many connections from your host. Message defered."
#R<?>127.0.0.13		$#error $@ 4.7.1 $: "421 Your Hostname contains illegal chars combinations. Message blocked. http://antispam.domain.my/"
#R<?>127.0.0.211		$#error $@ 4.7.1 $: "421 Messages from your host is blocked. http://antispam.domain.my/"
#R<?>127.0.0.255		$#error $@ 4.7.1 $: "421 Remote host IP address is null. Connection Dropped. http://antispam.domain.my/"
R<?>$+			$#error $@ 4.7.1 $: "421 Probably spam host or too many connections. Please visit http://antispam.domain.my/?ip="$&{client_addr}" or resend mail later"

# Connection Rate Block 
#R$*			$: <?> $(dnslook $&{client_addr}.fastbl.dmz. $: OK $)
#R$-.$-.$-.$-		$: <?> $(dnslook $4.$3.$2.$1.fastbl.dmz. $: OK $)
#R<?>OK			$: OKSOFAR
#R<?>$+<TMP>		$: TMPOK
#R<?>$+			$#error $@ 4.7.1 $: "421 Too many connections from your ip "$&{client_addr} ". Please resend mail later."

# DNS based IP address spam list dnslook.dmz, learned from spamassassin
R$*			$: $&{client_addr}
R$-.$-.$-.$-		$: <?> $(dnslook $4.$3.$2.$1.dnsbl.dmz. $: OK $)
R<?>OK			$: OKSOFAR
R<?>$+<TMP>		$: TMPOK
R<?>$+			$#error $@ 5.7.1 $: "550 Messages from you Blocked. Please visit http://antispam.domain.my/?ip="$&{client_addr}"&error="$1""

SLocal_check_rcpt
# DNS based black user list userbl.dmz
R<$+ @ $*>		$: <?> $(dnslook $&i:$1:$2:$&{msgid}.rcptbl.dmz. $: OK $)
#R<$+ @ $*>		$: <?> $(dnslook $1.$2.userbl.dmz. $: OK $)
R$*			$: $1 $(syslog CHECK_RCPT: $1 $)
R<?>OK			$: OKSOFAR
R<?>$+<TMP>		$: TMPOK
R<?>$*			$: <?>$1 $(save {error} $@ $1 $)
#R<?>$*			$: <?>$1 $(syslog CHRCPT: $1 $)

R<?>127.0.0.208		$#error $@ 5.7.1 $: "550 Messages from your domain is blocked. http://antispam.domain.my/?ip="$&{client_addr}"&error="$&{error}""
R<?>127.0.0.209		$#error $@ 5.7.1 $: "550 Messages from your address is blocked. http://antispam.domain.my/?ip="$&{client_addr}"&error="$&{error}""
R<?>127.0.0.210		$#error $@ 5.7.1 $: "550 Messages from your GeoZone is blocked. http://antispam.domain.my/?ip="$&{client_addr}"&error="$&{error}""
R<?>127.0.0.211		$#error $@ 5.7.1 $: "550 Messages from your host is blocked. http://antispam.domain.my/?ip="$&{client_addr}"&error="$&{error}""
R<?>127.0.0.212		$#error $@ 5.7.1 $: "550 Messages to this domain is blocked."
R<?>127.0.0.213		$#error $@ 5.7.1 $: "550 User account is disabled."
R<?>127.0.0.214		$#error $@ 5.7.1 $: "550 User not found."

R<?>127.0.0.224		$#error $@ 4.7.1 $: "421 Null From Received. Message defered."
R<?>127.0.0.225		$#error $@ 5.7.1 $: "550 Your Host is not trusted for send as our domain. Message blocked."
R<?>127.0.0.226		$#error $@ 5.7.1 $: "550 Your HELO contains illegal chars combinations. Message blocked. http://antispam.domain.my/"
R<?>127.0.0.227		$#error $@ 5.7.1 $: "550 Your Hostname contains illegal chars combinations. Message blocked. http://antispam.domain.my/"
R<?>127.0.0.228		$#error $@ 4.7.1 $: "421 Your HELO cannot be resolved. Message defered."
R<?>127.0.0.229		$#error $@ 4.7.1 $: "421 Your IP address Geozone not equal MX Geozone. Message blocked. http://antispam.domain.my/"
R<?>127.0.0.230		$#error $@ 4.7.1 $: "421 Your HELO Geozone not equal your MX Geozone. Message blocked. http://antispam.domain.my/"
R<?>127.0.0.231		$#error $@ 4.7.1 $: "421 Your host ip address not equal resolved HELO address. Message blocked. http://antispam.domain.my/"
R<?>127.0.0.232		$#error $@ 5.7.1 $: "555 Illegal From:. Message blocked."
R<?>127.0.0.233		$#error $@ 5.7.1 $: "555 Illegal To:. Message blocked."
R<?>127.0.0.234		$#error $@ 5.7.1 $: "555 Numeric From:. Message blocked."
R<?>127.0.0.235		$#error $@ 5.7.1 $: "555 Numeric To:. Message blocked."

R<?>127.0.0.247		$#error $@ 4.7.1 $: "421 Greylist activated. See ya later."
R<?>127.0.0.240		$#error $@ 4.7.1 $: "421 Greylist for rcpt user is active."
R<?>127.0.0.241		$#error $@ 4.7.1 $: "421 Greylist for sender user is active."
R<?>127.0.0.242		$#error $@ 4.7.1 $: "421 Greylist for rcpt domain is active."
R<?>127.0.0.243		$#error $@ 4.7.1 $: "421 Greylist for sender domain is active."
R<?>127.0.0.244		$#error $@ 4.7.1 $: "421 Greylist for your Geozone is active."
R<?>127.0.0.245		$#error $@ 4.7.1 $: "421 Greylist for your host is active."

R<?>127.0.0.253		$#error $@ 4.7.1 $: "421 You come is too early. Try again some time later."
R<?>127.0.0.255		$#error $@ 4.7.1 $: "421 Remote host IP address is null. Connection Dropped."

R<?>$+			$#error $@ 5.7.1 $: "421 Message not accepted by policy. http://antispam.domain.my/?ip="$&{client_addr}"&error="$1""

HMessage-ID:		$>CheckMessageId

SCheckMessageId
R<$*@$+>		$: $(save {msgid} $@ $2 $)
R$*			$: <?> $(dnslook $&i:$&{haddr}:MSGID:$&{msgid}:.upd.dmz $: OK $)
R$*			$: $1 $(syslog MSGID $&{msgid} $)
R<?>OK			$: OKSOFAR
R<?>$+<TMP>		$: TMPOK
R<?>$*			$: <?>$1 $(save {error} $@ $1 $)

R<?>127.0.0.223		$#error $@ 5.7.1 $: "550 Illegal Messageid detected. Message dropped."
R<?>$+			$#error $@ 5.7.1 $: "421 Message not accepted by policy. http://antispam.domain.my/?ip="$&{client_addr}"&error="$1""

divert(-1)
