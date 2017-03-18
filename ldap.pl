#!/usr/bin/perl

use Cache::FastMmap;
use Net::LDAP;
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

#,debug => 2
$ldap = Net::LDAP->new('domain.my') or die "$@";
$searchbase = 'dc=domain,dc=my';
$mesg = $ldap->bind('CN=ldapreader,CN=Users,DC=domain,DC=my',password => 'MyPass12345');
&check_domain;
# Unbinding
$ldap->unbind; 

print join "\n",keys %domains;

sub check_domain
{
$mesg = $ldap->search (base => $searchbase,
#                        filter => "(mail=zhecka*)",
                        #(msExchHideFromAddressLists=TRUE)(|(objectClass=user)(objectClass=group)(objectClass=publicFolder)(!(objectClass=computer)))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
                        filter => "
                        (&
                          (proxyAddresses=SMTP*)
                          (|
                            (objectClass=user)
                            (objectClass=group)
                            (objectClass=publicFolder))
                          (!(objectClass=contact))
                          (!(objectClass=computer))
                          (!
                            (&
                              (|
                                (cn=SystemMailbox{*)
                                (cn=exchangeV1)
                                (cn=globalevents*)
                                (cn=Default)
                                (cn=internal*)
                                (cn=microsoft)
                                (cn=Offline Address Book*)
                                (cn=OWAScratchPad{*)
                                (cn=schema-root)
                                (cn=Schedule+*)
                                (cn=StoreEvents{*)
                              )
                              (objectClass=publicFolder)
                            )
                          )
                          (!(mail=xxx_*))
                          (!(mail=publicfolder*))
                          (!(mail=oabversion*))
                          (!(cn=SystemMailbox*))
                        )",
                        attrs => "proxyAddresses"
                        );

#my %domains;
foreach my $entry ( $mesg->entries ) {
   # LDAP Attributes are multi-valued, so we have to print each one.
#   my $name = $entry->get_value("cn");
    my $status = $entry->get_value("userAccountControl") & 2;
#   $account = $account & 2;
#   print "Name: $name Status:",$account,"\n";
   foreach my $mail ( $entry->get_value( "proxyAddresses" ) ) {
     if ( $mail =~ s/^(smtp|SMTP)://gs ) {
        $mail = lc($mail);
        my ($name,$domain) = split("\@",$mail);
        $domains{$domain} = 1;
        print $mail," ",$status,"\n";
        $domaincontrol->set($mail,$status);
     }
   }
}

#print Dumper($domaincontrol->get_keys(2));
foreach my $domain (keys %domains)
{
$domaincontrol->set("control_".$domain,1);
}

}
#print join "\n",keys %domains;


sub tmp
{
                              

}