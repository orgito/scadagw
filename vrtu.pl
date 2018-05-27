#!/usr/bin/perl

use warnings;
use strict;

use POE qw(Component::Client::TCP Filter::Stream);

POE::Component::Client::TCP->new(
    BindAddress => "20.20.5.105",
    RemoteAddress => "20.20.0.5",
    RemotePort    => 8000,
    Filter => POE::Filter::Stream->new(),
    Connected     => sub {
      my $id = pack( "H*", "0F" );
      $_[HEAP]{server}->put($id);
    },
    ServerInput   => sub {
      my $input = $_[ARG0];
	  my $hdata = unpack 'H*', $input;

	  #fix input revertendo destinho e origem
      if ( $hdata =~ /^0564/ ) {
			$hdata =~ s/(........)(....)(....)(.*)/$1$3$2$4/;
            $input = pack 'H*', $hdata;
       }

	   print "from server: $hdata\n";
      #$_[HEAP]{server}->put($input);
    },
);

POE::Kernel->run();
exit;
