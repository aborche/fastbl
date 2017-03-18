#!/usr/bin/perl -w
# udpmsg - send a message to the udpquotd server

use IO::Socket;
use Digest::HMAC_SHA1 qw(hmac_sha1);
#use strict;

my($sock, $server_host, $msg, $port, $ipaddr, $hishost, 
   $MAXLEN, $PORTNO, $TIMEOUT);

$MAXLEN  = 1024;
#$PORTNO  = 56789;
$TIMEOUT = 5;
$PFTBLVERSION = 2;
$PFTBLCOMMAND = 2; # 0x01 - add, 0x02 - del, 0x03 -flush
$PFTBLMASK = 32;
$PFTBLNAME = "spamzone";
$PFTBLPORT = 56789;

@servers = ('10.6.204.219','10.6.204.218','10.6.204.225');

foreach my $server_host (@servers)
{
#$msg         = "@ARGV";
$sock = IO::Socket::INET->new(Proto     => 'udp',
                              PeerPort  => $PFTBLPORT,
                              PeerAddr  => $server_host)
    or die "Creating socket: $!\n";

$key = "fb359303098f2f921f0b";
#$/ = "\n";
my $addr = $ARGV[0];
$addr =~ s/[^0-9.]//g;
#print $addr,"\n";
#undef $/;
#$addr = inet_aton($addr);
#$time = time();
my $block = pack("C1 S1 C1",$PFTBLVERSION,$PFTBLCOMMAND,$PFTBLMASK).inet_aton($addr).pack("a32 N*",$PFTBLNAME,time());
$digest = hmac_sha1($block, $key);
$block .= $digest;
$sock->send($block) or die "send: $!";
}
