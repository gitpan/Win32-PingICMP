###########################################################################
# Copyright 2002 Toby Everett.  All rights reserved.
#
# This file is distributed under the Artistic License. See
# http://www.ActiveState.com/corporate/artistic_license.htm or
# the license that comes with your perl distribution.
#
# For comments, questions, bugs or general interest, feel free to
# contact Toby Everett at teverett@alascom.att.com
##########################################################################

use strict;

package Win32::PingICMP;
use Carp;
use Win32::API;

use vars qw($VERSION $IcmpCreateFile $IcmpCloseHandle $IcmpSendEcho $IpStatusConsts);

$VERSION='0.02';

&classinit();

sub classinit {
  $IcmpCreateFile = Win32::API->new('icmp', 'IcmpCreateFile', [qw()], 'N') or
      croak "Win32::PingICMP::classinit Unable to create Win32::API object for IcmpCreateFile";
  $IcmpSendEcho = Win32::API->new('icmp', 'IcmpSendEcho', [qw(N N P I N P N N)], 'N') or
      croak "Win32::PingICMP::classinit Unable to create Win32::API object for IcmpSendEcho";
  $IcmpCloseHandle = Win32::API->new('icmp', 'IcmpCloseHandle', [qw(N)], 'I') or
      croak "Win32::PingICMP::classinit Unable to create Win32::API object for IcmpCloseHandle";

  $IpStatusConsts = {
    0 => 'IP_SUCCESS',
    11001 => 'IP_BUF_TOO_SMALL',
    11002 => 'IP_DEST_NET_UNREACHABLE',
    11003 => 'IP_DEST_HOST_UNREACHABLE',
    11004 => 'IP_DEST_PROT_UNREACHABLE',
    11005 => 'IP_DEST_PORT_UNREACHABLE',
    11006 => 'IP_NO_RESOURCES',
    11007 => 'IP_BAD_OPTION',
    11008 => 'IP_HW_ERROR',
    11009 => 'IP_PACKET_TOO_BIG',
    11010 => 'IP_REQ_TIMED_OUT',
    11011 => 'IP_BAD_REQ',
    11012 => 'IP_BAD_ROUTE',
    11013 => 'IP_TTL_EXPIRED_TRANSIT',
    11014 => 'IP_TTL_EXPIRED_REASSEM',
    11015 => 'IP_PARAM_PROBLEM',
    11016 => 'IP_SOURCE_QUENCH',
    11017 => 'IP_OPTION_TOO_BIG',
    11018 => 'IP_BAD_DESTINATION',
  };
}

sub new {
  my $class = shift;
  my($proto, $def_timeout, $bytes) = @_;

  (defined $proto && $proto ne 'icmp') and
      croak "Win32::PingICMP::new Illegal protocol value - only 'icmp' is supported";

  my $self = {
    def_timeout => defined $def_timeout ? $def_timeout+0 : 5,
    RequestData => "\0" x (defined $bytes ? $bytes+0 : 0),
  };

  $self->{IcmpHandle} = $IcmpCreateFile->Call() or
      croak "Win32::PingICMP::new Call to IcmpCreateFile failed: ".Win32::GetLastError();

  bless $self, $class;
  return $self;
}

sub ping {
  my $self = shift;
  my($host, $timeout) = @_;

  my $details = $self->{details} = {};


  $self->{IcmpHandle} or croak "Win32::PingICMP::ping IcmpHandle has been closed";

  $details->{host} = $host;
  my($ipaddr);
  if ($host =~ /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/) {
    $details->{ipaddr} = $host;
    $ipaddr = ((($4*256)+$3)*256+$2)*256+$1;
  } else {
    $host ne '' or croak "Win32::PingICMP::ping requires \$host parameter";
    my(undef, undef, undef, undef, @addrs) = gethostbyname($host);
    my(@x) = unpack('C4', $addrs[0]);
    $details->{ipaddr} = join('.', @x);
    $ipaddr = ((($x[3]*256)+$x[2])*256+$x[1])*256+$x[0];
    $ipaddr or return undef;
  }

  $details->{timeout} = (defined $timeout ? $timeout : $self->{def_timeout}) * 1000;
  $details->{buffer} = "\0" x 1024;

  my $count = $IcmpSendEcho->Call($self->{IcmpHandle}, $ipaddr,
      $self->{RequestData}, length($self->{RequestData}), 0,
      $details->{buffer}, 1024, $details->{timeout});

  $self->parse_details($count);

  return $details->{success};
}

sub requestdata {
  my $self = shift;

  $self->{RequestData} = $_[0] if scalar(@_);
  return $self->{RequestData};
}

sub parse_details {
  my $self = shift;
  my($count) = @_;

  my $details = $self->{details};
  my $count = $count || 1;
  my $poffset;

  foreach my $i (0..$count-1) {
    my $reply = $details->{replies}->[$i] = {};

    @{$reply}{qw(address status roundtriptime datasize
          reserved pdata ttl tos flags optionssize poptionsdata)} =
        unpack('a4LLSSLCCCCL', substr($details->{buffer}, 28 * $i, 28));

    if (!defined $poffset) {
      $poffset = $reply->{pdata} - 28 * $count;
    }

    $reply->{data} = substr($details->{buffer}, $reply->{pdata}-$poffset, $reply->{datasize});
    delete($reply->{pdata});
    delete($reply->{datasize});

    $reply->{optionsdata} = substr($details->{buffer}, $reply->{poptionsdata}-$poffset, $reply->{optionssize});
    delete($reply->{poptionsdata});
    delete($reply->{optionssize});

    delete($reply->{reserved});

    $reply->{address} = join(".", unpack('C4', $reply->{address}));

    $details->{success} ||= ($reply->{status} == 0);

    $reply->{status} = $IpStatusConsts->{$reply->{status}} || $reply->{status};
  }

  foreach my $i (qw(status roundtriptime)) {
    $details->{$i} = $details->{replies}->[0]->{$i};
  }

  $details->{success} = $details->{success} ? 1 : 0;
}

sub details {
  my $self = shift;

  return {%{$self->{details}}};
}

sub close {
  my $self = shift;

  $IcmpCloseHandle->Call($self->{IcmpHandle}) or
      carp "Win32::PingICMP::new Call to IcmpCloseHandle failed: ".Win32::GetLastError();
  delete($self->{IcmpHandle});
}

sub DESTROY {
  my $self = shift;

  $self->close();
}

1;

__END__

=head1 NAME

Win32::PingICMP - ICMP Ping support for Win32 based on ICMP.DLL

=head1 SYNOPSIS

  use Win32::PingICMP;

  my $p = Win32::PingICMP->new();
  if ($p->ping($@ARGV)) {
    print "Ping took ".$p->details->{roundtriptime}."\n";
  } else {
    print "Ping unsuccessful: ".$p->details->{status}."\n";
  }

=head1 DESCRIPTION

C<Win32::PingICMP> is designed to mimic the ICMP ping functionality of
C<Net::Ping>, but because C<Win32::PingICMP> uses C<ICMP.DLL> instead of raw
sockets, it will work without local Administrative privileges under Windows
NT/2000/XP.  In addition, access to the C<ICMP_ECHO_REPLY> data structure is
provided, making it possible to get more accurate timing values from pings.

=head2 Installation instructions

This module requires Aldo Calpini's C<Win32::API>, available from CPAN and
via PPM.

=head1 AUTHOR

Toby Everett, teverett@alascom.att.com

=head1 ACKNOWLEDGEMENTS

Some of the documentation is copied from that for C<Net::Ping> 2.02.  Since I
was attempting to make this a replacement for that module, similarity in
documentation struck me as a Good Thing(TM).

I would never have done this if I hadn't seen
http://perlmonks.thepen.com/42739.html.  I would never have attempted this if
C<Win32::API> didn't bring the Win32 API within the reach of mere mortals
like me.

I would never have seen that if Christopher Elkin hadn't tried using
C<Win32::ProcFarm> on his web server to do monitoring via pings and asked
me why things weren't working when the code ran without admin privs.

=head1 METHODS

=over 4

=item Win32::PingICMP->new([$proto [, $def_timeout [, $bytes]]]);

Create a new ping object.  All of the parameters are optional.  C<$proto>
specifies the protocol to use when doing a ping.  The only currently
supported choice is 'C<icmp>'.

If a default timeout (C<$def_timeout>) in seconds is provided, it is used
when a timeout is not given to the C<ping()> method (below).  It is
recommended that the timeout be greater than C<0> and the default, if not
specified, is C<5> seconds. Fractional values are permitted.

If the number of data bytes (C<$bytes>) is given, that many data bytes
are included in the ping packet sent to the remote host.  The default is C<0>
bytes.  The maximum is C<996>.

=item $p->ping($host [, $timeout]);

Ping the remote host and wait for a response.  C<$host> can be either the
hostname or the IP number of the remote host.  The optional timeout should be
greater than 0 seconds and defaults to whatever was specified when the ping
object was created.  Fractional values are permitted for the timeout.  If the
hostname cannot be found or there is a problem with the IP number, C<undef>
is returned.  Otherwise, C<1> is returned if the host is reachable and C<0>
if it is not.  For all practical purposes, C<undef> and C<0> and can be
treated as the same case.


=item $p->close();

Close the network connection for this ping object.  The network connection is
also closed by "C<undef $p>".  The network connection is automatically closed
if the ping object goes out of scope (e.g. C<$p> is local to a subroutine and
you leave the subroutine).

=item $p->requestdata([$requestdata]);

Get and/or set the request data to be used in the packet.

=item $p->details();

Returns the gory details of the last ping attempted by the object.  This is a
reference to an anonymous hash and contains:

=over 4

=item replies

This is a reference to an anonymous array containing anonymous hash
references with the gory details of the replies to the ping.  In certain
pathological cases, it I<might> be possible for there to be multiple replies,
which is why this is an array. This would be the case if the C<IcmpSendEcho>
call returned a value greater than 1, indicating that more than one packet
was received in response.  Of course, the first packet received should cause
C<IcmpSendEcho> to return, so I'm not quite sure how this would happen.  The
Microsoft documentation is incomplete on this point - they clearly state
"Upon return, the buffer contains an array of C<ICMP_ECHO_REPLY> structures
followed by options and data."  This would seem to indicate that multiple
C<ICMP_ECHO_REPLY> structures might reasonably be expected, as does the
comment "The call returns when the time-out has expired or the reply buffer
is filled."  However, the functions appears to return as soon as there is one
entry in the reply buffer, even when there is copious space left in the reply
buffer and the time-out has yet to expire.  My best guess is that there will
never be more than one C<ICMP_ECHO_REPLY> structure returned, but I have
written the code to deal with the multiple structure case should it occur.

The anonymous hashes consist of the following elements:

=over 4

=item address

Address from which the reply packet was sent.

=item data

Data present in the reply packet.

=item flags

IP header flags from the reply packet.

=item optionsdata

Bytes from the options area following the IP header.

=item roundtriptime

Round trip time.  This appears to be inaccurate if there is no actual reply
packet (as in the case of a 'C<IP_REQ_TIMED_OUT>').

=item status

The per reply status returned by the C<IcmpSendEcho>.  If the returned value
matches a known constant, a text string is returned (i.e. 'C<IP_SUCCESS>',
'C<IP_REQ_TIMED_OUT>', etc.).

=item tos

The type-of-service for the reply packet.

=item ttl

The time-to-live for the reply packet.

=back

=item host

The originally specified IP address or DNS name from the C<ping> call.

=item ipaddr

The IP address used for the actual ping.

=item roundtriptime

The C<roundtriptime> value for the first reply.

=item status

The C<status> value for the first reply.

=item success

The same value returned by the C<ping> call.  This is absent if an IP address
could not be determined for the host, C<1> if there were one or more replies
with a status value of 'C<IP_STATUS>', and C<0> if there were none.

=item timeout

The specified timeout value in milliseconds.

=back

=back

=cut
