use Data::Dumper;
use Win32::PingICMP;

my $p = Win32::PingICMP->new();
$p->requestdata('Hi there!');
print $p->ping(@ARGV),"\n";

my $details = $p->details;
delete($details->{buffer});
print Dumper([$details]);

