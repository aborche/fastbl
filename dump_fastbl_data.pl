#!/usr/bin/perl

use Cache::FastMmap;
use Data::Dumper;
use strict;

my %conf;
my $path = "/tmpfs";
$conf{commonmapfile} = $path."/common.map";			# settings common info
$conf{greylistmapfile} = $path."/greylist.map";		# greylist file with all entries
$conf{sessionmapfile} = $path."/session.map";		# temporary session file
$conf{statusmapfile} = $path."/status.map";			# hosts status info
$conf{queuemapfile} = $path."/queuemap.map";
$conf{domaincontrolfile} = $path."/domaincontrol.map";

my $commonmap = Cache::FastMmap->new(
                                    share_file => $conf{commonmapfile},
#                                    expire_time => "240h",
#                                    cache_size => "256k",
                                    unlink_on_exit => 0
                                  );


my $sessionmap = Cache::FastMmap->new(
                                    share_file => $conf{sessionmapfile},
#                                    expire_time => "2h",
#                                    cache_size => "30m",
                                    unlink_on_exit => 0
                                  );
# greylist sessions list
my $greylistmap = Cache::FastMmap->new(
                                    share_file => $conf{greylistmapfile},
#                                    expire_time => "1h",
#                                    cache_size => "10m",
                                    unlink_on_exit => 0
                                  );
# stat info for hosts
my $statusmap = Cache::FastMmap->new(
                                    share_file => $conf{statusmapfile},
#                                    expire_time => "120h",
#                                    cache_size => "30m",
                                    unlink_on_exit => 0
                                  );
my $queuelist = Cache::FastMmap->new(
                                    share_file => $conf{queuemapfile},
#                                    expire_time => "10m",
#                                    cache_size => "30m",
                                    unlink_on_exit => 0
                                  );
my $domaincontrol = Cache::FastMmap->new(
                                    share_file => $conf{domaincontrolfile},
#                                    expire_time => "10m",
#                                    cache_size => "30m",
                                    unlink_on_exit => 0
                                  );
print "DomainControl\n";
foreach my $key ($domaincontrol->get_keys(2))
{
  print Dumper($key);
}
exit(0);
print "CommonMap\n";
foreach my $key ($commonmap->get_keys(2))
{
  print Dumper($key);
}
print "SessionMap\n";
foreach my $key ($sessionmap->get_keys(2))
{
  print Dumper($key);
}
print "Greylistmap\n";
foreach my $key ($greylistmap->get_keys(2))
{
  print Dumper($key);
}
print "StatusMap\n";
foreach my $key ($statusmap->get_keys(2))
{
  print Dumper($key);
}
