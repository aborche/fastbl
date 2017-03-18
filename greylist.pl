#!/usr/bin/perl

use Cache::FastMmap;
use Data::Dumper;


$sessionmap = Cache::FastMmap->new(
                                    share_file => "/tmpfs/session.map",
#                                    expire_time => "2h",
#                                    cache_size => "30m",
                                    unlink_on_exit => 0
                                  );
# greylist sessions list
$greylistmap = Cache::FastMmap->new(
                                    share_file => "/tmpfs/greylist.map",
#                                    expire_time => "30m",
#                                    cache_size => "10m",
                                    unlink_on_exit => 0
                                  );
# stat info for hosts
$statusmap = Cache::FastMmap->new(
                                    share_file => "/tmpfs/status.map",
#                                    expire_time => "120h",
#                                    cache_size => "30m",
                                    unlink_on_exit => 0
                                  );
$queuelist = Cache::FastMmap->new(
                                    share_file => "/tmpfs/queuemap.map",
#                                    expire_time => "10m",
#                                    cache_size => "30m",
                                    unlink_on_exit => 0
                                  );



#$greylistmap = Cache::FastMmap->new(
#                                    share_file => "/tmpfs/greylist.map",
#                                    expire_time => "30m",
#                                    cache_size => "10m",
#                                    unlink_on_exit => 0
#                                  );

my @str = $greylistmap->get_keys(2);
print Dumper(@str);
print " ===================== ";
my @str = $sessionmap->get_keys(2);
print Dumper(@str);
print " ===================== ";
my @str = $statusmap->get_keys(2);
print Dumper(@str);
print " ===================== ";
my @str = $queuelist->get_keys(2);
print Dumper(@str);

