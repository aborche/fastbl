#!/usr/local/bin/perl
# 
# !!!!!!!!!!!!!!!!!!!!!!!!!!! Unstable !!!!!!!!!!!!!!!!!!!!!!!!!!!!

# Kaltashkin Eugene (C) 2008. Email: zhecka@gmail.com
# Modified by Alexander Demin. Email: support@spectrum.ru
#
# !!!!!!!! reject_null_from is deprecated. use greylist_null_from
#
# 25.02.2010
# version 0.6.6 devel
# changed codes of blacklists
# added real users list
#
# 04.03.2009
# version 0.6.4 devel
# added greylisting for null from senders
# 
# 18.12.2008
# version 0.6.2 devel
# added some new filters
#
# 05.07.2008
# version 0.6.0 devel
# added greylisting, whitelisting, heuristic
#
#
# version 0.5.0 devel
# Added Patricia support for whitelists
#
#
# version 0.4.6
# Added delimiter define string
# Fully rewrited listener, now used IO::Multiplex
# Added autoreload for white-list
# Removed memory leaks 
#
# version 0.4.5
# Changed white-list format : "white-list": IP\thost_name
# Changed function check_fastbl() : changed host detection type
#=====================


#use POSIX ":sys_wait_h";
#use diagnostics;
use IO::Multiplex;
use Net::Patricia;
use strict;
use IO::Socket;
use Cache::FastMmap;
use Data::Dumper;
use Digest::HMAC_SHA1 qw(hmac_sha1);
use Sys::Syslog;

use vars qw/
  $config $sock $sockres $PORTNO $PORTNOres
  $HEADERLEN $PACKETSZ $MAXLEN $QR_MASK $OP_MASK $AA_MASK $TC_MASK $NOTIMP $NOERROR $FORMERR $NOSUCHNAME $RCODE
  $errorcode $countrec %ttlh %count $white $black $zonemap $delim $wlmtime %hr_types %conf
  $sessionmap $greylistmap $statusmap $commonmap $loopcount %pfban %pfsock $banip %banaction $domaincontrol
  $PFTBLVERSION $PFTBLCOMMAND $PFTBLMASK $PFTBLNAME $PFTBLPORT $banned $sesslog $lastqueue $queuelist
/;
#  %Kid_Status %white %trust $timelimit $countlimit $wlmtime 

$config = "/usr/local/etc/fastbl/fastbl.conf";
$sesslog = "/var/log/fastbl.log";
&read_conf;
#
#
$delim = ':';
$loopcount = 0;
openlog("fastbl","ndelay");

#$SIG{INT} = $SIG{QUIT} = $SIG{TERM} = $SIG{STOP} = \&quit;

$SIG{HUP} = sub {
  close SESSLOG;
  open SESSLOG,">$sesslog" or die "cannot open logfine $!";
  SESSLOG->autoflush(1);
};

$zonemap = new Net::Patricia;	# hosts and networks geoip map
$banned = new Net::Patricia;

# info about sessions
$sessionmap = Cache::FastMmap->new(
                                    share_file => $conf{sessionmapfile},
                                    expire_time => "2h",
#                                    cache_size => "30m",
                                    unlink_on_exit => 0
                                  );
# greylist sessions list
$greylistmap = Cache::FastMmap->new(
                                    share_file => $conf{greylistmapfile},
                                    expire_time => "1h",
#                                    cache_size => "10m",
                                    unlink_on_exit => 0
                                  );
# stat info for hosts
$statusmap = Cache::FastMmap->new(
                                    share_file => $conf{statusmapfile},
                                    expire_time => "120h",
#                                    cache_size => "30m",
                                    unlink_on_exit => 0
                                  );
$queuelist = Cache::FastMmap->new(
                                    share_file => $conf{queuemapfile},
                                    expire_time => "10m",
#                                    cache_size => "30m",
                                    unlink_on_exit => 0
                                  );

$domaincontrol = Cache::FastMmap->new(
                                    share_file => $conf{domaincontrol},
#                                    expire_time => "10m",
#                                    cache_size => "30m",
                                    unlink_on_exit => 0
                                  );
#$statusmap->clear();
$greylistmap->clear();
#$sessionmap->clear();

&init_ipcountry_base($conf{countrylistfile});

$HEADERLEN = 12;
$PACKETSZ = 512;
$MAXLEN = 1024;
$PORTNO = 531;
$PORTNOres = 554;
$QR_MASK = 0x8000;
$OP_MASK = 0x7800;
$AA_MASK = 0x0400;
$TC_MASK = 0x0200;
$NOTIMP = 4;
$NOERROR = 0;
$NOSUCHNAME = 3;
$FORMERR = 1;

$PFTBLVERSION = 2;
$PFTBLCOMMAND = 1; # 0x01 - add, 0x02 - del, 0x03 -flush
$PFTBLMASK = 32;
$PFTBLNAME = "spamzone";
$PFTBLPORT = 56789;


if($conf{debug})
{
  &log("HELOBL: Helo Validation is Active. Entering Helo validation procedure") if($conf{helo_validation});
  &log("HELOBL: Warning !!!! reject_helo_check is active. rejecting hosts with incorrect helo string") if($conf{reject_helo_check});
  &log("FASTBL: Hostname validation is active") if($conf{hostname_validation});
  &log("FASTBL: Warning !!! reject_hostname_check is active. Rejecting all hosts with wrong hostname mask") if($conf{reject_hostname_check});
  &log("FASTBL: Connection throttling is active. Rejecting all hosts with more than $conf{countlimit} connection in $conf{timelimit} seconds") if($conf{connection_throttle});
  &log("GREYBL: Greylisting active !!! This can be slowly dependent of your system") if($conf{use_greylist});
}


&log("REBOOT: ",scalar localtime(time)) if ($conf{debug});
#&slog("SQL::START::",scalar localtime(time));
print scalar localtime(time),"\n";
print "Awaiting UDP messages on port $PORTNO and $PORTNOres\n";

#exit(0);

$sock = IO::Socket::INET->new(LocalPort => $PORTNO, Proto => 'udp')
    or die "socket: $@";

foreach my $pfip (keys %pfban)
  {
  $pfsock{$pfip} = IO::Socket::INET->new(Proto     => 'udp',
                                         PeerPort  => $PFTBLPORT,
                                         PeerAddr  => $pfip)
                                         or die "Creating socket: $!\n";
  }

#$sockres = IO::Socket::INET->new(LocalPort => $PORTNOres, Proto => 'udp')
#    or die "socket: $@";

if(!$conf{daemon})
{
  my $mux = new IO::Multiplex;
  $mux->add($sock);
  $mux->set_timeout($sock, 10);
  $mux->set_callback_object(__PACKAGE__);
  $mux->loop;
  exit(0);
  closelog();
}
else
{
  if(fork)
    {
      exit(0);
    }
  else
    {
      open FH,">/var/run/fastbl.pid";
      print FH $$;
      close FH;
#      if($conf{sessionlog})
#      {
        open SESSLOG,">$sesslog";
        SESSLOG->autoflush(1);
#      }
      my $mux = new IO::Multiplex;
      $mux->add($sock);
      #$mux->add($sockres);
      #$mux->listen($sock);
      #$mux->add(\*STDIN);
      #$mux->add(\*STDOUT);

      $mux->set_timeout($sock, 10);
      $mux->set_callback_object(__PACKAGE__);
      $mux->loop;
#      if($conf{sessionlog})
#      {
        close SESSLOG;
#      }
      exit(0);
      closelog();
    }
}
exit(0);

sub mux_input {
  my $package = shift;
  my $mux = shift;
  my $fh = shift;
  my $input = shift;
  
  if($fh == $sock)
  {
  undef $lastqueue;
  my $reply = &depack_packet($$input);
    if ($reply) {
        my $saddr = $mux->{_fhs}{$sock}{udp_peer};
        send($sock, $reply, 0, $saddr) or die "handle_udp_req: send: $!";
        if($banip)
        {
        if(!$banned->match_string($banip))
          {
            $banned->add_string($banip);
            foreach my $pfip (keys %pfban)
            {
              #prepare struct for pftabled
              my $addr = inet_aton($banip);
              my $time = time();
              my $block = pack("C1 S1 C1",$PFTBLVERSION,$PFTBLCOMMAND,$PFTBLMASK).$addr.pack("a32 N*",$PFTBLNAME,$time);
              my $digest = hmac_sha1($block, $pfban{$pfip});
              $block .= $digest;
              $pfsock{$pfip}->send($block);
            }
            undef $banip;
          }
        }
        
#        $sock->send($reply, 0) or die "handle_udp_req: send: $!";
#        print "Sended Reply\n";
        }
  }
#  elsif ($fh == $sockres)
#  {
#  my $reply = &depack_packet($$input);
#    if ($reply) {
#        my $saddr = $mux->{_fhs}{$sockres}{udp_peer};
#        send($sockres, $reply, 0, $saddr) or die "handle_udp_req: send: $!";
#        $sock->send($reply, 0) or die "handle_udp_req: send: $!";
#        print "Sended Reply HeloBL\n";
#        }
#  }
  else
  {
   die "$$: Not my fh?";
  }
  $$input = '';
}

sub mux_close
{
  print STDERR "Connection Closed\n";
  exit;
}

sub mux_timeout
{
  my $self    = shift;
  my $mux     = shift;
  my $fh      = shift;
  $mux->set_timeout($fh,20);
  $loopcount++;
  if($loopcount >= 90)
  {
    $sessionmap->purge();
    $statusmap->purge();
    $greylistmap->purge();
    $queuelist->purge();
    undef $banned;
    $banned = new Net::Patricia;
    $loopcount = 0;
    &slog('-------Flushing all expired data');
  }
#    &slog("------LOOP $loopcount");
    &read_conf if($wlmtime != (stat($config))[9]);
}

#$SIG{CHLD} = \&REAPER;

sub ipvalid
{
  my $ip=shift;
  if($ip !~ /[^0-9\.]/)
  {
   return 1 if(inet_aton($ip));
  }
  return undef;
}

sub check_rcpt_zone
{	#begin check_rcpt_zone

  my $data = shift;
  $data =~ s/.rcptbl.dmz$//;
  my($queue,$to,$todomain,$msgid) = split (/$delim/o,$data,4);

#
# if connection arrive from localhost directly to queue, helo string
# not present. we make current IP 127.0.0.1
#
  if(!$sessionmap->get($queue."_ip"))
  {
    $sessionmap->set($queue."_ip","127.0.0.1");
  }
  my $ip = $sessionmap->get($queue."_ip");
  
  if(!ipvalid($ip))
    {
#        &slog("SQL::ERROR::QUEUE::$queue::IP::$ip");
        $errorcode = 0x7f0000FF;
        $countrec+=1;
        return 0;
    }

  $lastqueue = $queue;
  $to = lc($to);
  $todomain = lc($todomain);
  $sessionmap->set($queue."_to",$to);
  $sessionmap->set($queue."_to_domain",$todomain);

  if($statusmap->get($ip."_white"))
  {
    &log("RCPTBL:$ip: Host already whitelisted") if($conf{debug});
    return 0;
  }

  if($sessionmap->get($queue."_white"))
  {
  &log("RCPTBL:$ip: Session $queue already whitelisted") if($conf{debug});
  return 0;
  }
  
  my $rcpt = $to."\@".$todomain;
  &log("RCPTBL:$ip: QUEUEID $queue RCPT $rcpt") if($conf{debug});
  
#  &log("RCPTBL:$ip: Check aborted. Host is whitelisted") if($white->match_string($ip) && $conf{debug});
#  return 0 if($white->match_string($ip));
      
  if($commonmap->get("wl_to_user_".$rcpt))
  {
  &log("RCPTBL:$ip: Recipient $rcpt is whitelisted") if($conf{debug});
#  &slog("SQL::WHITE::USER::$rcpt::QUEUE::$queue::IP::$ip::HST::$residual");
  return 0;
  }

  if($commonmap->get("wl_to_domain_".$todomain))
  {
  &log("RCPTBL:$ip: Recipient domain $todomain is whitelisted") if($conf{debug});
#  &slog("SQL::WHITE::DOMAIN::$todomain::RCPT::$to::QUEUE::$queue::IP::$ip");
  return 0;
  }

  &log("RCPTBL:$ip: Recipient $rcpt is blacklisted") if($commonmap->get("bl_to_user_".$rcpt) && $conf{debug});
    if($commonmap->get("bl_to_user_".$rcpt))
    {
#      &slog("SQL::BLACK::USER::$rcpt::QUEUE::$queue::IP::$ip");
      $errorcode = 0x7f0000D5;
      $countrec+=1;
      return 0;
    }

  &log("RCPTBL:$ip: Recipient domain $todomain is blacklisted") if($commonmap->get("bl_to_domain_".$todomain) && $conf{debug});
    if($commonmap->get("bl_to_domain_".$todomain))
    {
#      &slog("SQL::BLACK::DOMAIN::$todomain::RCPT::$to::QUEUE::$queue::IP::$ip");
      $errorcode = 0x7f0000D4;
      $countrec+=1;
      return 0;
    }

    
    if($domaincontrol->get("control_".$todomain) && !defined($domaincontrol->get($rcpt)))
    {
      &log("RCPTBL:$ip: Recipient not found in domain control list $todomain") if($conf{debug});
      $errorcode = 0x7f0000D6;
      $countrec+=1;
      return 0;
    }

   my $rcptpair = $sessionmap->get($queue."_from_domain").':'.$sessionmap->get($queue."_to").'@'.$sessionmap->get($queue."_to_domain");
#   &slog("$lastqueue\trcptpair\t$rcptpair");
#   &slog("$queue");
#  &log("RCPTBL:$ip: Pair of recipient $rcpt and  $todomain is blacklisted") if($commonmap->get("bl_to_domain_".$todomain) && $conf{debug});
    if($commonmap->get("bl_domain_to_user_".$rcptpair))
    {
#      &slog("SQL::BLACK::DOMAIN::$todomain::RCPT::$to::QUEUE::$queue::IP::$ip");
      $errorcode = 0x7f0000D7;
      $countrec+=1;
      return 0;
    }

# sessions variables
#
# $queue."_ip"		Incoming IP
# $queue."_type"	Type of incoming IP
# $queue."_helo"	HELO
# $queue."_helotype"	Type of incoming HELO
# $queue."_from"	Sender name
# $queue."_from_domain"	Sender domain
# $queue."_to"		Recipient name
# $queue."_to_domain"	Recipient domain
# $queue."_mx"		mx list for current sender domain

#  $sessionmap->set($queue."_msgid",$msgid);

#  my @types = ('_ip','_type','_helo','_helotype','_from','_from_domain','_to','_to_domain','_msgid','_mx');
#  foreach my $type (@types)
#    {
#      print "queue",$type," = ",$sessionmap->get($queue.$type),"\n";
#    }

#
# Trying to file host in greylisting database, if host found as result we give
# next visit time
#
if($conf{use_greylists})
{	# begin greylist block

  my $greylist_pack = join ("_",$sessionmap->get($queue."_ip"),$sessionmap->get($queue."_from"),$sessionmap->get($queue."_from_domain"),$sessionmap->get($queue."_to"),$sessionmap->get($queue."_to_domain"));

#  &log("GREYBL: Greylisting is active") if($conf{debug});
#  &log("GREYBL:$ip: Trying to find $greylist_pack") if($conf{debug});

  my $ctime = time();

# Finding greylistpack string in database
  my $iptime = find_host_in_greylist($greylist_pack);
#  &slog("------- GREYLISTPACK $greylist_pack ::: $iptime");

#
#

if(!$iptime)
  {
    &log("GREYBL:$ip: Host is not greylisted. Start processing greylist rules") if($conf{debug});
  }
elsif($iptime > $ctime)
  {
    &log("GREYBL:$ip: Host arrived before appointed time. Increase missed sessions hits. Rejecting") if($conf{debug});
    &log("GREYBL:$ip: Next planned host arrival time ".scalar localtime($iptime)." now ".scalar localtime(time)) if($conf{debug});
    $statusmap->get_and_set($ip."_greylist_missed_hits", sub { return ++$_[1]; });
#    &slog("SQL::GREY::MISS::$ip::QUEUE::$queue");
    $errorcode = 0x7f0000fd;
    $countrec+=1;
    return 0;
  }
elsif($iptime <= $ctime)
  {
    &log("GREYBL:$ip: Host arrived at the appointed time. Increase good sessions hits.Passing host") if($conf{debug});
    $statusmap->get_and_set($ip."_greylist_positive_hits", sub { return ++$_[1]; });
    $greylistmap->remove($greylist_pack);
#    &slog("SQL::GREY::PASS::$ip::QUEUE::$queue");
    return 0;
  }

my $nexttime = $ctime + &make_expire_time($conf{greylistexpiretime});
# if nost not found ($iptime is undefined) we make a new procedure putting host to greylist
#
# Checking greylist for recipient
my $greylistuser = $sessionmap->get($queue."_to").'@'.$sessionmap->get($queue."_to_domain");
if($commonmap->get("gl_to_user_".$greylistuser))
  {
    &log("GREYBL:$ip: Process greylisting for rcpt $greylistuser") if($conf{debug});
    &log("GREYBL:$ip: Next arrival time for $greylist_pack is ".scalar localtime($nexttime)) if($conf{debug});
    $greylistmap->set($greylist_pack,$nexttime);
#    &slog("SQL::GREY::INIT::$ip::QUEUE::$queue::RCPT::$greylistuser::TIME::$nexttime");
    $errorcode = 0x7f0000f0;
    $countrec+=1;
    return 0;
  }

# Checking greylist for sender
my $greylistuser = $sessionmap->get($queue."_from").'@'.$sessionmap->get($queue."_from_domain");
if($commonmap->get("gl_from_user_".$greylistuser))
  {
    &log("GREYBL:$ip: Process greylisting from sender $greylistuser") if($conf{debug});
    &log("GREYBL:$ip: Next arrival time for $greylist_pack is ".scalar localtime($nexttime)) if($conf{debug});
    $greylistmap->set($greylist_pack,$nexttime);
#    &slog("SQL::GREY::INIT::$ip::QUEUE::$queue::SENDER::$greylistuser::TIME::$nexttime");
    $errorcode = 0x7f0000f1;
    $countrec+=1;
    return 0;
  }
# Checking greylist for recipient domain
if($commonmap->get("gl_to_domain_".$todomain))
  {
    &log("GREYBL:$ip: Process greylisting for rcpt domain $todomain") if($conf{debug});
    &log("GREYBL:$ip: Next arrival time for $greylist_pack is ".scalar localtime($nexttime)) if($conf{debug});
    $greylistmap->set($greylist_pack,$nexttime);
#    &slog("SQL::GREY::INIT::$ip::QUEUE::$queue::RCPTDOM::$todomain::TIME::$nexttime");
    $errorcode = 0x7f0000f2;
    $countrec+=1;
    return 0;
  }

# Checking greylist for sender domain
if($commonmap->get("gl_from_domain_".$sessionmap->get($queue."_from_domain")))
  {
    &log("GREYBL:$ip: Process greylisting from sender domain ".$sessionmap->get($queue."_from_domain")) if($conf{debug});
    &log("GREYBL:$ip: Next arrival time for $greylist_pack is ".scalar localtime($nexttime)) if($conf{debug});
    $greylistmap->set($greylist_pack,$nexttime);
#    &slog("SQL::GREY::INIT::$ip::QUEUE::$queue::SENDDOM::".$sessionmap->get($queue."_from_domain"))."::TIME::$nexttime");
    $errorcode = 0x7f0000f3;
    $countrec+=1;
    return 0;
  }
# Checking greylist for sender geozone
my $zone = $zonemap->match_string($sessionmap->get($queue."_ip"));
if($commonmap->get("gl_from_zone_".$zone))
  {
    &log("GREYBL:$ip: Process greylisting for geozone $zone") if($conf{debug});
    &log("GREYBL:$ip: Next arrival time for $greylist_pack is ".scalar localtime($nexttime)) if($conf{debug});
    $greylistmap->set($greylist_pack,$nexttime);
#    &slog("SQL::GREY::INIT::$ip::QUEUE::$queue::ZONE::$zone::TIME::$nexttime");
    $errorcode = 0x7f0000f4;
    $countrec+=1;
    return 0;
  }
# Checking greylist for each host
if($conf{greylist_by_host})
  {
    &log("GREYBL:$ip: Process greylisting by host") if($conf{debug});
    &log("GREYBL:$ip: Next arrival time for $greylist_pack is ".scalar localtime($nexttime)) if($conf{debug});
    $greylistmap->set($greylist_pack,$nexttime);
#    &slog("SQL::GREY::INIT::$ip::QUEUE::$queue::HOST::$ip::TIME::$nexttime");
    $errorcode = 0x7f0000f5;
    $countrec+=1;
    return 0;
  }
if(!$greylistmap->get($greylist_pack))
  {
    &log("GREYBL:$ip: No greylist rules found. RCPT: $greylistuser GEOZONE: $zone DOMAIN: $todomain") if($conf{debug});
  }

}	# end greylist block


# Heuristic
if($conf{heuristic})	# begin heuristic block
{
  my $ip = $sessionmap->get($queue."_ip");
  my $heloip = $sessionmap->get($queue."_helores");
  my $fromdomain = $sessionmap->get($queue."_from_domain");
  ($heloip,undef) = split (/:/,$heloip,2) if ($heloip =~ /\:/);

  # checking heloip for any chars.
    if(!ipvalid($heloip))
      {
      # if helo unresovable or contain illegal symbols
        $heloip = "255.255.255.255";
      }
    else
      {
        $heloip =~ s/[^0-9\.]//g;
      }
      
    &log("HEURIS:$ip: HELOIP: $heloip FROMDOMAIN: $fromdomain") if($conf{debug});

#
# Heuristic types for hostname
# cidr - IP address in hostname: 62-33-53-101.customer.novochek.net
# hex - IP address in hex: p549ACBAE.dip.t-dialin.net
# decimal - IP address in decimal: e181227115.adsl.alicedsl.de
# word - reserved words: ppp85-140-135-161.pppoe.mtu-net.ru
#
# Heuristic types for helo
# numeric - any type (cidr,hex,decimal)
# localhost - helo without dots, single name(USER-1BC,MSHOME-ABCDEF), localhost in helo.
#
# Heuristic types for other parts(experimental)
# reject_null_from - reject any senders with null sender
# reject_own_dom_from_nontrust - reject any senders which try to send with own domain name not in trust hosts list
# send_conn_geo - sender IP geozone not like domain geozone of sender
# helo_conn_geo - helo IP geozone not like domann geozone of sender.
# unres_helo - helo without ip address(unresolvable).

 if($sessionmap->get($queue."_from") eq 'undefined')
   {
      &log("HEURIS:$ip: null From: found") if($conf{debug});
      if($conf{greylist_null_from})
        {
          my $ctime = time();
          my $nexttime = $ctime + &make_expire_time($conf{greylistexpiretime});
          my $greylist_pack = join ("_",$sessionmap->get($queue."_ip"),$sessionmap->get($queue."_from"),$sessionmap->get($queue."_from_domain"),$sessionmap->get($queue."_to"),$sessionmap->get($queue."_to_domain"));
          &log("HEURIS:$ip: Process greylisting for null from") if($conf{debug});
          &log("HEURIS:$ip: Next arrival time for $greylist_pack is ".scalar localtime($nexttime)) if($conf{debug});
          $greylistmap->set($greylist_pack,$nexttime);
#          &slog("SQL::HEURIS::NULL::".$sessionmap->get($queue."_from")."::QUEUE::$queue");
          $errorcode = 0x7f0000e0;
          $countrec+=1;
          return 0;
        }
   }


 if($commonmap->get("own_domains_".$fromdomain))
   {
     if(!$white->match_string($ip))
     {
      &log("HEURIS:$ip: Sender ip with own domain name not in trust list") if($conf{debug});
      if($conf{reject_own_dom_from_nontrust})
        {
#          &slog("SQL::HEURIS::TRUST::$ip::QUEUE::$queue");
          $errorcode = 0x7f0000e1;
          $countrec+=1;
          return 0;
        }
     }
   }

  if($hr_types{$sessionmap->get($queue."_helotype")})
    {
      &log("HEURIS:$ip: Helo in blocked category found") if($conf{debug});
        if($conf{reject_advanced_heuristic})
        {
#          &slog("SQL::HEURIS::HELO::".$sessionmap->get($queue."_helotype")."::QUEUE::$queue");
          $errorcode = 0x7f0000e2;
          $banip = $ip if($banaction{$sessionmap->get($queue."_helotype")});
          $countrec+=1;
          return 0;
        }
    }
  if($hr_types{$sessionmap->get($queue."_type")})
    {
      &log("HEURIS:$ip: Hostname in blocked category found") if($conf{debug});
        if($conf{reject_advanced_heuristic})
        {
#          &slog("SQL::HEURIS::HOSTNAME::".$sessionmap->get($queue."_type")."::QUEUE::$queue");
          $errorcode = 0x7f0000e3;
          $banip = $ip if($banaction{$sessionmap->get($queue."_type")});
          $countrec+=1;
          return 0;
        }
    }

#
# EXPERIMENTAL
#
  if($hr_types{unprintable_from})
    {
      if($sessionmap->get($queue."_from") =~ /[^0-9A-Za-z+-_]/)
      {
        &log("HEURIS:$ip: found unprintable chars in From:") if($conf{debug});
        if($conf{reject_advanced_heuristic})
          {
            $errorcode = 0x7f0000e8;
            $banip = $ip if($banaction{unprintable_from});
            $countrec+=1;
            return 0;
          }
      }
    }

  if($hr_types{unprintable_to})
    {
      if($sessionmap->get($queue."_to") =~ /[^0-9A-Za-z+-_]/)
      {
        &log("HEURIS:$ip: found unprintable chars in To:") if($conf{debug});
        if($conf{reject_advanced_heuristic})
          {
            $errorcode = 0x7f0000e9;
            $banip = $ip if($banaction{unprintable_to});
            $countrec+=1;
            return 0;
          }
      }
      $sessionmap->get($queue."_to"); 
    }

  if($hr_types{numeric_from})
    {
      if($sessionmap->get($queue."_from") =~ /[0-9]/)
      {
        &log("HEURIS:$ip: found numeric in From: ") if($conf{debug});
        if($conf{reject_advanced_heuristic})
          {
            $errorcode = 0x7f0000ea;
            $banip = $ip if($banaction{numeric_from});
            $countrec+=1;
            return 0;
          }
      }
    }

  if($hr_types{numeric_to})
    {
      if($sessionmap->get($queue."_to") =~ /[0-9]/)
      {
        &log("HEURIS:$ip: found unprintable chars in To:") if($conf{debug});
        if($conf{reject_advanced_heuristic})
          {
            $errorcode = 0x7f0000eb;
            $banip = $ip if($banaction{numeric_to});
            $countrec+=1;
            return 0;
          }
      }
      $sessionmap->get($queue."_to"); 
    }


#
# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
#

  if($hr_types{unres_helo}) # STABLE
    {
      if($heloip eq '255.255.255.255')
      {
        &log("HEURIS:$ip: unresolvable helo received") if($conf{debug});
        if($conf{reject_advanced_heuristic})
        {
#          &slog("SQL::HEURIS::UNRESHELO::$heloip::QUEUE::$queue");
          $errorcode = 0x7f0000e4;
          $banip = $ip if($banaction{unres_helo});
          $countrec+=1;
          return 0;
        }
      }
    }
#
#
  if($hr_types{send_conn_geo}) # STABLE
    {
      &log("HEURIS:$ip: Found MX record ".$sessionmap->get($queue."_mx")) if($conf{debug});
      my $geozone_mx = 0;
      my $geozone_sender_ip = $zonemap->match_string($ip);
      foreach my $mx (split (/\:/,$sessionmap->get($queue."_mx")))
      {
        &log("HEURIS:$ip: check MX record for $mx") if ($conf{debug});
        next if($mx =~ /[a-zA-Z]/);
        $mx =~ s/\.$//g;
        next if(!ipvalid($mx));
        if($black->match_string($mx))
          {
#            &slog("SQL::BLACK::MX::$mx::QUEUE::$queue::IP::$ip");
            $errorcode = 0x7f0000D3;
            $banip = $ip if($banaction{send_conn_geo});
            $countrec+=1;
            return 0;
          }
        my $geozone_mx_ip = $zonemap->match_string($mx);
        &log("HEURIS:$ip: Found geozone $geozone_mx_ip for MX $mx. Expected geozone $geozone_sender_ip") if($conf{debug});
        if($geozone_sender_ip eq $geozone_mx_ip)
          {
            $geozone_mx = $geozone_mx_ip;
            last;
          }
        else
          {
            $geozone_mx = $geozone_mx_ip;
          }
      }
      if(!$geozone_mx || !$geozone_sender_ip)
      {
          &log("HEURIS:$ip: Some geozones not found. geozone MX $geozone_mx, geozone ip $geozone_sender_ip") if($conf{debug});
      }
      elsif($geozone_mx ne $geozone_sender_ip)
        {
          &log("HEURIS:$ip: geozone MX $geozone_mx and geozone sender ip $geozone_sender_ip is not valid") if($conf{debug});
          if($conf{send_conn_geo_grey} && $conf{use_greylists})
          {
            my $ctime = time();
            my $nexttime = $ctime + &make_expire_time($conf{greylistexpiretime});
            my $greylist_pack = join ("_",$sessionmap->get($queue."_ip"),$sessionmap->get($queue."_from"),$sessionmap->get($queue."_from_domain"),$sessionmap->get($queue."_to"),$sessionmap->get($queue."_to_domain"));
#            &slog("$greylist_pack".scalar localtime($nexttime));
            &log("HEURIS:$ip: Process greylisting for mx geozone $geozone_mx") if($conf{debug});
            &log("HEURIS:$ip: Next arrival time for $greylist_pack is ".scalar localtime($nexttime)) if($conf{debug});
            $greylistmap->set($greylist_pack,$nexttime);
#            &slog("SQL::GREY::INIT::$ip::QUEUE::$queue::ZONE::$zone::TIME::$nexttime");
            $errorcode = 0x7f0000f7;
#            $banip = $ip if($banaction{send_conn_geo});
            $countrec+=1;
            return 0;
            
          }
          if($conf{reject_advanced_heuristic})
          {
#            &slog("SQL::HEURIS::MXGEO::$geozone_mx::QUEUE::$queue::SENDGEO::$geozone_sender_ip");
            $errorcode = 0x7f0000e5;
            $banip = $ip if($banaction{send_conn_geo});
            $countrec+=1;
            return 0;
          }
        }
    }
#  
  if($hr_types{helo_conn_geo}) # UNSTABLE
    {
      &log("HEURIS:$ip: Check HELOIP $heloip") if($conf{debug});
      return 0 if (!$heloip || $heloip =~ /[a-zA-Z]/);
      my $helo_geozone = 0;
      my $ip_geozone = $zonemap->match_string($ip);
      if($heloip =~ /\:/)
      {
        foreach my $zo (split (/\:/,$heloip))
          {
          next if(!$zo || $zo =~ /^$/ || $zo =~ /[a-zA-Z]/);
          $zo =~ s/\.$//g;
          next if(!ipvalid($zo));
          my $tmpzone = $zonemap->match_string($zo);
          &log("HEURIS:$ip: Found geozone $tmpzone for HELOIP $zo") if($conf{debug});
              if($ip_geozone eq $tmpzone)
                {
                  $helo_geozone = $tmpzone;
                  last;
                }
              else
                {
                  $helo_geozone = $tmpzone;
                }
          }
      }
      else
      {
          $heloip =~ s/\.$//g;
          $helo_geozone = $zonemap->match_string($heloip);
          &log("HEURIS:$ip: Found geozone $helo_geozone for HELOIP $heloip") if($conf{debug});
      }

      if($ip_geozone ne $helo_geozone)
        {
          &log("HEURIS:$ip: geozone helo $helo_geozone and geozone sender ip $ip_geozone is not valid") if($conf{debug});
          if($conf{reject_advanced_heuristic})
          {
#            &slog("SQL::HEURIS::IPGEO::$geozone_mx::QUEUE::$queue::HELOGEO::$geozone_sender_ip");
            $errorcode = 0x7f0000e6;
            $banip = $ip if($banaction{helo_conn_geo});
            $countrec+=1;
            return 0;
          }
        }
    }
    
#
#

  if($hr_types{helo_reshelo}) # UNSTABLE
    {
      if($heloip ne $ip)
        {
          &log("HEURIS:$ip: Resolved heloip $heloip != $ip ") if($conf{debug});
          if($conf{reject_advanced_heuristic})
            {
#              &slog("SQL::HEURIS::HELOIP::$geozone_mx::QUEUE::$queue::HELOGEO::$geozone_sender_ip");
              $errorcode = 0x7f0000e7;
              $banip = $ip if($banaction{helo_reshelo});
              $countrec+=1;
              return 0;
            }
        }
    }


}	# end heuristic block

}	# end check_rcpt_zone

sub upd_zone
{
#
# update mx list and helo for current queue
#
  my $data = shift;
  $data =~ s/.upd.dmz$//;
  my($queue,$ip,$flag,$data) = split (/:/,$data,4);
  if($data =~ /\:$/) { $data =~ s/\:$//g; }

  if(!ipvalid($ip))
    {
        $errorcode = 0x7f0000FF;
        $countrec+=1;
        return 0;
    }

  if($flag eq 'MX')
  {
  # $MXLIST
  #
  
    &log("UPDATE:$ip: MX for queue $queue -> $data") if ($conf{debug});
    $sessionmap->set($queue."_mx",$data);
  }
  elsif($flag eq 'HL')
  {
  # $helo:$resolved_ip_of_helo
  #
    &log("UPDATE:$ip: HELO for queue $queue -> $data") if ($conf{debug});
    ($flag,$data) = split (/:/,$data,2);
    if($flag && $data)
    {
      $sessionmap->set($queue."_helo",$flag);
#      $data =~ s/(\d+\.\d+\.\d+\.\d+)(.*)/$1/;
      $sessionmap->set($queue."_helores",$data);
    }
  }
  elsif($flag eq 'MSGID')
  {
    &log("UPDATE:$ip: MSGID for queue $queue -> $data") if ($conf{debug});
    $sessionmap->set($queue."_msgid",$data);
    # MessageID check
    my $msgidsave = $sessionmap->get($queue."_msgid");
    my $msgidfrom = $sessionmap->get($queue."_from");
    &log("MESSAGEID:$queue: MSGID: $msgidsave FROM: $msgidfrom") if ($conf{debug});
    if($sessionmap->get($queue."_msgid") eq $sessionmap->get($queue."_from"))
     {
        &log("HEURIS:$ip: msgid equal sender name") if($conf{debug});
        $errorcode = 0x7f0000df;
        $banip = $ip if($banaction{$sessionmap->get($queue."_type")});
        $countrec+=1;
        return 0;
    }
  }
  return 0;
}

sub check_helo_zone
{
  my $residual = shift;
  my $reslen = length($residual);
  $residual =~ s/.helobl.dmz$//;
#  my $ip = '';
#  my $queue = '';
#  my $from = '';
#  my $fromdomain = '';
#
# <queue name>:<ip>:<From>.helobl.dmz
#
  my($queue,$ip,$from,$fromdomain) = split (/$delim/o,$residual,4);

# If ip is not valid, reject host(sendmail bug)
#
  if(!ipvalid($ip))
    {
        $errorcode = 0x7f0000FF;
        $countrec+=1;
        return 0;
    }

  &log("HELOBL:$ip: QUEUEID $queue SENDER $from\@$fromdomain") if($conf{debug});

# saving sessions parameters
  $from = lc($from);
  $fromdomain = lc($fromdomain);
  $sessionmap->set($queue."_ip",$ip);
  $sessionmap->set($queue."_from",$from);
  $sessionmap->set($queue."_from_domain",$fromdomain);
  $sessionmap->set($queue."_type",$statusmap->get($ip."_type"));
  my $sender = $from."\@".$fromdomain;

  if($statusmap->get($ip."_white"))
  {
    &log("HELOBL:$ip: Host already whitelisted. Passing") if($conf{debug});
    return 0;
  }

  if($commonmap->get("wl_from_domain_".$fromdomain))
  {
    &log("HELOBL:$ip: STOP !!! check aborted. Sender domain $fromdomain is whitelisted") if($conf{debug});
    $sessionmap->set($queue."_white",1);
    return 0;
  }

  if($commonmap->get("wl_from_user_".$sender))
  {
    &log("HELOBL:$ip: STOP !!! check aborted. Sender name $sender is whitelisted") if($conf{debug});
    $sessionmap->set($queue."_white",1);
    return 0;
  }

  if($commonmap->get("bl_from_domain_".$fromdomain))
    {
      &log("HELOBL:$ip: STOP !!! check aborted. Sender domain $fromdomain is blacklisted") if($conf{debug});
      $errorcode = 0x7f0000D0;
      $countrec+=1;
      return 0;
    }
#  my $sender = lc($from)."\@".lc($fromdomain);
  if($commonmap->get("bl_from_user_".$sender))
    {
      &log("HELOBL:$ip: STOP !!! check aborted. Sender name $sender is blacklisted") if($conf{debug});
      $errorcode = 0x7f0000D1;
      $countrec+=1;
      return 0;
    }
  
  $residual = $sessionmap->get($queue."_helo");

if($conf{helo_validation})
{
  if ($residual eq 'localhost' || $residual eq 'localhost.localdomain' || $residual =~ /\.lan$/ || $residual !~ /\./)
  {
    &log("HELOBL:$ip: $residual found single helo or localhost.localdomain type") if($conf{debug});###
    if($conf{reject_helo_check})
    {
      $errorcode = 0x7f00000C;
      $countrec+=1;
      return 0;
    }
    else
    {
      $sessionmap->set($queue."_helotype","localhost");
    }
  }

  if($residual =~ /\d+(\-|\.|x)\d+(\-|\.|x)\d+/ || $residual =~ /([0-9A-F]{2})([0-9A-F]{2})([0-9A-F]{2})([0-9A-F]{2})(\.)?/i || $residual =~ /([0-9]{8,15})/)
  {
   &log("HELOBL:$ip: $residual found NUMERIC tags") if($conf{debug});###
    if($conf{reject_helo_check})
    {
      $errorcode = 0x7f00000C;
      $countrec+=1;
      return 0;
    }
    else
    {
      $sessionmap->set($queue."_helotype","numeric");
    }
  }

  if(!$sessionmap->get($queue."_helotype"))
  {
    &log("HELOBL:$ip: tags not found for $residual") if($conf{debug});###
      $sessionmap->set($queue."_helotype","blank");
  }
#
# Saving helo for next checking
#
  $sessionmap->set($queue."_helo",$residual);
  return 0;
}

}

sub find_host_in_greylist
{
  my $ip = shift;
  my $time = $greylistmap->get($ip);
  return $time if $time;
  return 0;
}

sub make_expire_time
{
  my $expire_time = shift || '';
  my %Times = ('' => 1, s => 1, m => 60, h => 60*60, d => 24*60*60, w => 7*24*60*60);
  return $expire_time =~ /^(\d+)\s*([mhdws]?)/i ? $1 * $Times{$2} : 0;
}

sub check_fast_zone
{
  my $residual = shift;
  my $reslen = length($residual);
  $residual =~ s/.fastbl.dmz$//;
  my $ip = '';

  ($ip,$residual) = split (/$delim/o,$residual,2);

  if(!ipvalid($ip))
    {
#        &slog("SQL::ERROR::IP::$ip::HST::$residual");
        $errorcode = 0x7f0000FF;
        $countrec+=1;
        return 0;
    }
    
  &log("FASTBL:$ip: Incoming Hostname $residual, data length $reslen") if($conf{debug});

  my $geozone = $zonemap->match_string($ip);
  &log("FASTBL:$ip: Geozone $geozone found") if($conf{debug});
  $statusmap->set($ip."_geozone",$geozone);
  $statusmap->set($ip."_hostname",$residual);

#  &log("SQL::GEO::IP::$ip::HST::$residual::GEO::$geozone") if($conf{slog});

  if($white->match_string($ip))
  {
    &log("FASTBL:$ip: STOP !!! check aborted. Host is whitelisted") if($conf{debug});
#    &slog("SQL::WHITE::HOST::$ip::HST::$residual");
#    &log("SQL::WHITE::HOST::IP::$ip::HST::$residual") if($conf{slogl});
    $statusmap->set($ip."_white",1);
    return 0;
  }
  
  if($commonmap->get("wl_from_zone_".$geozone))
  {
    &log("FASTBL:$ip: STOP !!! check aborted. Geozone $geozone is whitelisted") if($conf{debug});
#    &slog("SQL::WHITE::ZONE::$geozone::IP::$ip::HST::$residual");
    $statusmap->set($ip."_white",1);
    return 0;
  }

  if($black->match_string($ip))
    {
      &log("FASTBL:$ip: STOP !!! check aborted. Host is blacklisted") if($conf{debug});
#      &slog("SQL::BLACK::HOST::$ip::HST::$residual");
      $errorcode = 0x7f0000D3;
      $countrec+=1;
      return 0;
    }            

  if($commonmap->get("bl_from_zone_".$geozone))
    {
      &log("FASTBL:$ip: STOP !!! check aborted. Geozone $geozone is blacklisted") if($conf{debug});
#      &slog("SQL::BLACK::ZONE::$geozone::IP::$ip::HST::$residual");
      $errorcode = 0x7f0000D2;
      $countrec+=1;
      return 0;
    }

  
# ----------------------------------------------------------------------------------------------
# Checking incoming hostname for chars and ip types in name
#
if ($residual =~ /[a-zA-Z]+/ && $conf{hostname_validation})
{ 	# begin hostname with any chars validation 

  if ($residual =~ /\d+(\-|\.|x)\d+(\-|\.|x)\d+/)
  {
    &log("FASTBL:$ip: $residual found NUMERIC cidr") if($conf{debug});###
    $statusmap->set($ip."_type","cidr");
      if($conf{reject_hostname_check})
      {
#        &slog("SQL::FASTBL::HELO::$residual::IP::$ip::TYPE::cidr");
        $errorcode = 0x7f00000D;
        $countrec+=1;
        return 0;
      }
  }
#
#
  elsif ($residual =~ /([0-9A-F]{2})([0-9A-F]{2})([0-9A-F]{2})([0-9A-F]{2})(\.)?/i)
  {
    &log("FASTBL:$ip: $residual found NUMERIC hex") if($conf{debug});###
    $statusmap->set($ip."_type","hex");
      if($conf{reject_hostname_check})
      {
#        &slog("SQL::FASTBL::HELO::$residual::IP::$ip::TYPE::hex");
        $errorcode = 0x7f00000D;
        $countrec+=1;
        return 0;
      }
  }
#
#
  elsif ($residual =~ /([0-9]{8,15})/)
  {
    &log("FASTBL:$ip: $residual found NUMERIC decimal") if($conf{debug});###
    $statusmap->set($ip."_type","decimal");
      if($conf{reject_hostname_check})
      {
#        &slog("SQL::FASTBL::HELO::$residual::IP::$ip::TYPE::decimal");
        $errorcode = 0x7f00000D;
        $countrec+=1;
        return 0;
      }
  }
#
#
  elsif ($residual =~ /(-dynamic)(dialup)|(dhcp)|(dsl)|(pppo)|(ppp\-?\d?)|(\.cable\.)|(\.user\.)|(\.dyn\.)|(host\-?\d+\-)|(dynip)/i)
  {
    &log("FASTBL:$ip: $residual found word") if($conf{debug});###
    $statusmap->set($ip."_type","word");
      if($conf{reject_hostname_check})
      {
#        &slog("SQL::FASTBL::HELO::$residual::IP::$ip::TYPE::word");
        $errorcode = 0x7f00000D;
        $countrec+=1;
        return 0;
      }
  }
  else
  {
          &log("FASTBL:$ip: No mask found for $residual") if($conf{debug});
          $statusmap->set($ip."_type","blank");
  }
  
} 	# end hostname with chars validation
elsif ($residual =~ /\[(.*)\]/)
  {	
          &log("FASTBL:$ip: Unresolvable host type found for $residual") if($conf{debug});
          $statusmap->set($ip."_type","unresolvable");
  }
else
  {
          &log("FASTBL:$ip: No mask found for $residual") if($conf{debug});
          $statusmap->set($ip."_type","blank");
  }

  &log("FASTBL:$ip: found iptype ".$statusmap->get($ip."_type")) if($conf{debug});

if($conf{connection_throttle})
{
  my $tm = time();
  foreach my $host (keys %ttlh)
    {
        my $difftm = $tm - $ttlh{$host};
        if ($difftm > $conf{timelimit})
        {
          delete $ttlh{$host}; delete $count{$host};
          &log("FASTBL:$host: Throttling IP address is deactivated") if($conf{debug});
        }
    }

      $ttlh{$ip} = $tm if (!$ttlh{$ip});
      $count{$ip} = 0 if (!$count{$ip});
      $count{$ip} = $count{$ip} + 1;

      if($count{$ip})
        {
          if($count{$ip} > $conf{countlimit} && ($tm-$ttlh{$ip}) < $conf{timelimit})
            {
#              &slog("FASTBL:$ip: Throttling IP address activated") if($conf{debug});
#              &slog("SQL::FASTBL::THROTTLE::$ip");
              $errorcode = 0x7f00000A;
              $countrec+=1;
              return 0;
            }
        }
}
  return 0;
}


sub create_answer
{
  my($ttl,$retcode) = @_;
  my $rdata = pack('N',$retcode);
  return pack('n', 0xc00c) . pack('nnNna*', 1, 1, $ttl, length $rdata, $rdata);
}

sub log
{
  my $data = shift;
  syslog("info|local6",$data);
}

sub slog
{
  return 0 if(!$conf{sessionlog});
  my $data = shift;
  print SESSLOG $data,"\n";
}

sub read_conf
{
$wlmtime = (stat($config))[9];
undef $white;
undef $black;
undef %hr_types;
undef %conf;
#$commonmap->clear() if($commonmap);
$white = new Net::Patricia;
$black = new Net::Patricia;
my $section = '';

open CONF,"<$config" or die "Config file not found $!\n";
while(<CONF>)
{
  my $str = $_;
  $str =~ s/\s+|\t+|\"//g;
  next if ($str =~ /^\#|^$/);
  ($str,undef) = split (/\;(.*)$/,$str,2);
  chomp($str);
  if($str =~ /^\[/)
    {
      $str =~ s/^\[(.*)\]$/$1/;
      $section = $str;
      next;
    }
  if($section eq 'global')
    {
      my($param,$value) = split(/\=/,$str);
      $conf{$param} = $value;
      if(!$commonmap && ($param eq 'commonmapfile'))
        {
          $commonmap = Cache::FastMmap->new(
                                    share_file => "/tmpfs/common.map",
#                                    expire_time => "240h",
#                                    cache_size => "256k",
                                    unlink_on_exit => 0
                                  );
        }
      elsif($commonmap && ($param eq 'commonmapfile')) { $commonmap->clear(); }
    }
  elsif(($section eq 'trusted_hosts') || ($section eq 'wl_from_host'))
    {
      eval
      {
        local $SIG{__DIE__} = $SIG{DIE} = sub { my @sig = shift; print "Error in $section section. Dying Signal Arrived\n @sig"; };
        $white->add_string($str,'1');
      };
      $SIG{__DIE__} = $SIG{DIE} = 'DEFAULT';
    }
  elsif($section eq 'bl_from_host')
    {
      eval
      {
        local $SIG{__DIE__} = $SIG{DIE} = sub { my @sig = shift; print "Error in $section section. Dying Signal Arrived\n @sig"; };
        $black->add_string($str,'1');
      };
      $SIG{__DIE__} = $SIG{DIE} = 'DEFAULT';
    }
  elsif ($section eq 'heuristic')
    {
      my($param,$value) = split(/\=/,$str);
      $hr_types{$param} = $value;
    }
  elsif ($section eq 'banaction')
    {
      my($param,$value) = split(/\=/,$str);
      $banaction{$param} = $value;
    }
  elsif ($section eq 'pfban')
    {
      my($ip,$key) = split(/\:/,$str);
      $pfban{$ip}=$key;
    }
  else
    {
      if($str =~ /\,/)
        {
          foreach my $value (split (/\,/,$str))
            {
              next if (!$value);
              $commonmap->set($section."_".$value,1);
            }
        }
      else
        {
              $commonmap->set($section."_".$str,1);
        }
    }
}

  &log("CONFIG: Reloaded at ".scalar localtime(time));
#print Dumper($commonmap->get_keys(1));
#print Dumper($black);
close CONF;
}



# deaggreate int range block to cidr
sub deaggregate
{
  my $start = shift;
  my $end   = shift;
  my $base = $start;
  my $step = 0;
  my $thirtytwobits = 4294967295;
  while (($base | (1 << $step))  != $base)
    {
      if (($base | (((~0) & $thirtytwobits) >> (31-$step))) > $end)
      {
        last;
      }
      $step++;
    }
  return IntToIP($base)."/" .(32-$step);
}

# transcoding Integer value to IP
sub IntToIP
{
    return join ".",unpack("CCCC",pack("N",shift));
}


sub init_ipcountry_base
{
#
# At first step we load Full List of Countries
#
print "Init ipcountry database\n" if($conf{debug});
my $zonefile = shift;
my $numzones = 1;
open IN,"<$zonefile";
#
# Base format
#"0","16777215","IANA","410227200","ZZ","ZZZ","RESERVED"
#
while(<IN>)
{
  my $act = 0; # 0 - adding, 1 - removing
  next if (/^#|^\d+/);
  $_ =~ s/\"//g;
  if(/^\</) { $act = 1; s/^\<\s//; } elsif (/^\>/) { $act = 0; s/^\>\s//; }
  my($start,$end,undef,undef,undef,$country,undef) = split (/\,/,$_);
  next if ($start !~ /^[0-9]+/);
  my $net_mask = deaggregate($start,$end);
  if($act)
    {
      $zonemap->remove_string($net_mask);
    }
  else
    {
      $zonemap->add_string($net_mask,$country);
    }
  print "Putted $numzones records to memory\n" if ((int($numzones/10000) == ($numzones/10000)) && $conf{debug});
  $numzones++;
}
close IN;
}

sub dn_expand {
# Expand dns message
    my ($msg, $offset) = @_;

    my $cp       = $offset;
    my $result   = '';
    my $comp_len = -1;
    my $checked  = 0;

    while (my $n = ord(substr($$msg, $cp++, 1))) {
        if (($n & 0xc0) == 0) {
            $checked += $n + 1;
            $result .= '.' if $result;
            while (--$n >= 0) {
                my $c = substr($$msg, $cp++, 1);
                $result .= ($c ne '.') ? $c : '\\';
            }
        } elsif (($n & 0xc0) == 0xc0) {  # pointer, follow it
            $checked += 2;
            return (undef, undef) if $checked >= length $$msg;
            $comp_len = $cp - $offset if $comp_len == -1;
            $cp = ($n & 0x3f) << 8 + ord(substr($$msg, $cp, 1));
        } else {  # unknown (or extended) type
            return (undef, undef);
        }
    }
    $comp_len = $cp - $offset if $comp_len == -1;
    return ($result, $offset + $comp_len);
}

sub depack_packet
{
    my $buff = shift;
    my ($header, $question, $ptr);
    my $buff_len = length $buff;

    return '' if $buff_len <= $HEADERLEN;  # short packet, ignore it.

    $header   = substr($buff, 0, $HEADERLEN);
    $question = substr($buff, $HEADERLEN);
    $ptr      = $HEADERLEN;

    my ($id, $flags, $qdcount, $ancount, $aucount, $adcount) = unpack('n6C*', $header);

#    print "id=$id flags=$flags qdcount=$qdcount ancount=$ancount aucount=$aucount adcount=$adcount\n";

    
    my $opcode  = ($flags & $OP_MASK) >> 11;
    my $qr      = ($flags & $QR_MASK) >> 15;  # query/response
    return '' if $qr;  # should not be set on a query, ignore packet

    if ($opcode != 0) {
        $flags |= $QR_MASK | $AA_MASK | $NOTIMP;
        return pack('n6', $id, $flags, 1, 0, 0, 0) . $question;
    }

    my $qname;
    ($qname, $ptr) = dn_expand(\$buff, $ptr);
#    print "Qname = $qname\n";
    if (not defined $qname) {
        $flags |= $QR_MASK | $AA_MASK | $FORMERR;
        return pack('n6', $id, $flags, 1, 0, 0, 0) . $question;
    }
    
    my ($qtype, $qclass) = unpack('nn', substr($buff, $ptr, 4));
    $ptr += 4;
#    print "Qtype=$qtype QClass=$qclass\n";

    if ($ptr != $buff_len) {  # we are not at end of packet (we should be :-) )
        $flags |= $QR_MASK | $AA_MASK | $FORMERR;
        return pack('n6', $id, $flags, 1, 0, 0, 0) . $question;
    }

    if($qtype != 1 || $qclass != 1)
    # || $qname !~ /fastbl.dmz$|helobl.dmz$/)
    {
      return pack('n6', $id, $flags, 1, 0, 0, 0) . $question;
    }

    $errorcode = "";
    $countrec = 0;

    &check_fast_zone($qname) if ($qname =~ /.fastbl.dmz$/);
    &upd_zone($qname) if ($qname =~ /.upd.dmz$/);
    &check_helo_zone($qname) if ($qname =~ /.helobl.dmz$/);
    &check_rcpt_zone($qname) if ($qname =~ /.rcptbl.dmz$/);

    if($errorcode)
    {
      my $errorip = inet_ntoa( pack 'N', $errorcode ) if($conf{debug});
      &log("BLOCKR: Result for $qname has errorcode $errorip\n") if($conf{debug});
      
    }
    else
    {
      &log("BLOCKR: Result for $qname has no errorcode. Passing connection.\n") if($conf{debug});
    }

    if($lastqueue)
      {
# $queue."_ip"		Incoming IP
# $queue."_type"	Type of incoming IP
# $queue."_helo"	HELO
# $queue."_helotype"	Type of incoming HELO
# $queue."_from"	Sender name
# $queue."_from_domain"	Sender domain
# $queue."_to"		Recipient name
# $queue."_to_domain"	Recipient domain
# $queue."_mx"		mx list for current sender domain
        if($queuelist->get($lastqueue))
          {
            &slog("$lastqueue\tto\t".$sessionmap->get($lastqueue."_to").'@'.$sessionmap->get($lastqueue."_to_domain")."\t".&IntToIP($errorcode));
          }
        else
          {
            $queuelist->set($lastqueue,1);
            my $statusip = $sessionmap->get($lastqueue."_ip");
            &slog("$lastqueue\tip\t".$statusip."\t".$sessionmap->get($lastqueue."_type")."\t".$statusmap->get($statusip."_hostname")."\t".$statusmap->get($statusip."_geozone"));
            &slog("$lastqueue\thelo\t".$sessionmap->get($lastqueue."_helo")."\t".$sessionmap->get($lastqueue."_helotype"));
            &slog("$lastqueue\tfrom\t".$sessionmap->get($lastqueue."_from").'@'.$sessionmap->get($lastqueue."_from_domain"));
            &slog("$lastqueue\tto\t".$sessionmap->get($lastqueue."_to").'@'.$sessionmap->get($lastqueue."_to_domain")."\t".&IntToIP($errorcode));
            &slog("$lastqueue\tmx\t".$sessionmap->get($lastqueue."_mx"));
            &slog("$lastqueue\tmsgid\t".$sessionmap->get($lastqueue."_msgid"));
            &slog("---------");
          }
      }

    $RCODE = ($countrec) ? $NOERROR : $NOSUCHNAME;
#    if($countrec)
#      {
#        $RCODE = $NOERROR;
#      }
#    else
#      {
#        $RCODE = $NOSUCHNAME;
#      }
    $qname = lc($qname);
    my %dnsmsg = (
                  rcode   => $RCODE,
                  qdcount => $qdcount,
                  ancount => 0,
                  aucount => 0,
                  adcount => 0,
                  answer  => '',  # response sections
                  auth    => '',
                  add     => ''
                 );
    my $from = $sock->peerhost();

    my $FOUND = 1;

    if ($countrec)
    {
        $dnsmsg{ancount}=1;
        $dnsmsg{answer} = &create_answer(15,$errorcode);
        $flags |= $QR_MASK | $AA_MASK | $dnsmsg{rcode};
    } else {
        $flags |= $QR_MASK | $dnsmsg{rcode};
    }

# build the response packet, truncating if necessary
    my $reply = $question . $dnsmsg{answer} . $dnsmsg{auth} . $dnsmsg{add};

    if (length $reply > ($PACKETSZ - $HEADERLEN)) {
        $flags |= $TC_MASK;
        $reply = substr($reply, 0, ($PACKETSZ - $HEADERLEN));
    }

    return pack('n6', $id, $flags, $qdcount, $dnsmsg{ancount},
                $dnsmsg{aucount}, $dnsmsg{adcount}) . $reply;
#}

}
