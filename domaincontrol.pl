#!/usr/bin/perl

use Cache::FastMmap;
use Data::Dumper;

my %domains;
$domaincontrol = Cache::FastMmap->new(
                                    share_file => "/tmpfs/domaincontrol.map",
#                                    $conf{domaincontrol},
#                                    expire_time => "10m",
#                                    cache_size => "30m",
                                    unlink_on_exit => 0
                                  );
$domaincontrol->clear();
exit(0);
my @userlist = ('zhecka@oeg.su','postmaster@oeg.su','shemmy@oeg.su','kovad@oeg.su','common@oeg.su','robot@323f.net.ru','zhecka@323f.net.ru','autoru@323f.net.ru');

foreach my $mail (@userlist)
{
        my ($name,$domain) = split("\@",$mail);
        $domains{$domain} = 1;
        print $mail," ",$status,"\n";
        $domaincontrol->set($mail,$status);
}

#print Dumper($domaincontrol->get_keys(2));
foreach my $domain (keys %domains)
{
  $domaincontrol->set("control_".$domain,1);
}

#print join "\n",keys %domains;


sub tmp
{
                              

}