#!/usr/bin/perl
use strict;
use warnings;
use IO::Socket;
use POSIX;

#use DNPCRC qw(crcDNP);

my $ReadClass0 = pack( 'H*', '05640bc4010000008c85c0c7013c0106edb9' );

my $nsca_host = "20.20.170.42";
my $config    = "/etc/nagios/send_nsca.cfg";
my $send_nsca = "/usr/sbin/send_nsca -c $config -H $nsca_host";

my $host = '20.20.170.44';
my $port = '20000';

my $sock = IO::Socket::INET->new(
    PeerAddr => $host,
    PeerPort => $port,
    Proto    => 'tcp'
) or die "Couldn't connect to $host:$port : $@\n";

my @dnpapp = split( //, sendCmdDNP3($ReadClass0) );

my %bitservices = (
    RTR_ALR_AC_FASE_A  => [ 144, 1, 0 ],
    RTR_ALR_AC_FASE_B  => [ 144, 2, 0 ],
    RTR_ALR_AC_FASE_C  => [ 144, 3, 0 ],
    RTR_ALR_GER_RET    => [ 145, 0, 0 ],
    RCV_ALR_AC_FASE_A  => [ 147, 6, 0 ],
    RCV_ALR_AC_FASE_B  => [ 147, 7, 0 ],
    RCV_ALR_AC_FASE_C  => [ 148, 0, 0 ],
    RCV_ALR_GER_RET    => [ 148, 7, 0 ],
    SDCI_ALR_AC_FASE_A => [ 151, 7, 0 ],
    SDCI_ALR_AC_FASE_B => [ 152, 0, 0 ],
    SDCI_ALR_AC_FASE_C => [ 152, 1, 0 ],
    SDCI_ALR_GER_RET   => [ 153, 6, 0 ],
);

my %byteservices = (
    COC_ALR_AC_FASE_A_RET => 9,
    COC_ALR_AC_FASE_B_RET => 10,
    COC_ALR_AC_FASE_C_RET => 11,
    COC_ALR_GER_RET_1     => 19,
    COC_ALR_GER_RET_2     => 20,
    RMFG_ALR_AC_FASE_A    => 47,
    RMFG_ALR_AC_FASE_B    => 48,
    RMFG_ALR_AC_FASE_C    => 49,
    RMFG_ALR_GER_RET      => 59,
    RMC_ALR_AC_FASE_A     => 80,
    RMC_ALR_AC_FASE_B     => 81,
    RMC_ALR_AC_FASE_C     => 82,
    RMC_ALR_GER_RET       => 87,
    RRNS_ALR_AC_FASE_A    => 110,
    RRNS_ALR_AC_FASE_B    => 111,
    RRNS_ALR_AC_FASE_C    => 112,
    RRNS_ALR_GER_RET      => 120,
    RMM_ALR_AC_FASE_A     => 191,
    RMM_ALR_AC_FASE_B     => 192,
    RMM_ALR_AC_FASE_C     => 193,
    RMM_ALR_GER_RET       => 205,
    RPA_ALR_AC_FASE_A     => 225,
    RPA_ALR_AC_FASE_B     => 226,
    RPA_ALR_AC_FASE_C     => 227,
    RPA_ALR_GER_RET       => 234,
    RPH_ALR_AC_FASE_A     => 258,
    RPH_ALR_AC_FASE_B     => 259,
    RPH_ALR_AC_FASE_C     => 260,
    RPH_ALR_GER_RET       => 267,
    RSC_ALR_AC_FASE_A     => 287,
    RSC_ALR_AC_FASE_B     => 288,
    RSC_ALR_AC_FASE_C     => 289,
    RSC_ALR_GER_RET       => 310,
    RSER_ALR_AC_FASE_A    => 314,
    RSER_ALR_AC_FASE_B    => 315,
    RSER_ALR_AC_FASE_C    => 316,
    #RSER_ALR_GER_RET      => 322,
    RST_ALR_AC_FASE_A     => 335,
    RST_ALR_AC_FASE_B     => 336,
    RST_ALR_AC_FASE_C     => 337,
    RST_ALR_GER_RET       => 338,
);

my $services = "cocrtu\t0\tOK: HOST OK\n";

while ( my ( $key, $value ) = each(%byteservices) ) {
    $services .= checkBinaryInput( $dnpapp[$value], 'cocrtu', $key, 0 );
}

while ( my ($key) = each(%bitservices) ) {
    $services .= checkBitBinaryInput(
        $dnpapp[ $bitservices{$key}[0] ],
        'cocrtu', $key,
        $bitservices{$key}[1],
        $bitservices{$key}[2]
    );
}

open( SEND, "|$send_nsca" ) || die "Could not run $send_nsca: $!\n";
print SEND "$services";
close SEND;

#print $services;

sub sendCmdDNP3 {
    my $class = shift;
    my $answer;
    my $frags;
    my $trfin;    #Final: set
    my $bytes;

    #print "Pergunta:\n" . unpack( 'H*', $class ) . "\n\n";
    print $sock $class;

    do {
        $bytes = sysread( $sock, my $dnpf, 292 );
        $answer = $answer . $dnpf;

        #print "PACOTE:\n" . unpack( 'H*', $dnpf ) . "\n";
        my $tlbyte = unpack( 'C1', substr( $dnpf, 10, 1 ) );
        $trfin = $tlbyte & 128;
        my $chks     = floor( ( $bytes - 11 ) / 18 );
        my $lstchksz = ( $bytes - 12 ) % 18;
        my $pos      = 28;
        my $i        = 1;
        my $frag     = substr( $dnpf, 11, 15 );
        $frags = $frags . $frag;

        #print "Chunk 1:\t" . unpack( 'H*', $frag ) . "\n";
        while ( $i < $chks ) {
            $frag = substr( $dnpf, $pos, 16 );
            $frags = $frags . $frag;
            $i++;
            $pos += 18;

            #print "Chunk $i:\t" . unpack( 'H*', $frag ) . "\n";
        }
        if ( $lstchksz > 0 ) {
            my $frag = substr( $dnpf, $pos, $lstchksz );
            $frags = $frags . $frag;
            $i++;

            #print "Chunk $i $lstchksz\t" . unpack( 'H*', $frag ) . "\n";
        }
    } while ( !$trfin );

    #print "\n" . unpack( 'H*', $frags ) . "\n";
    return $frags;
}

close($sock);

sub checkBinaryInput {
    my ( $byte, $host, $service, $ok ) = @_;

    my $test = ( unpack( 'C1', $byte ) & 0x80 ) ? 1 : 0;
    my $retval = ( $ok == $test ) ? 0 : 2;
    my $line = "$host\t$service\t$retval\tBinary Input with Status = " . unpack( 'B*', $byte ) . "\n";
    return $line;
}

sub checkBitBinaryInput {
    my ( $byte, $host, $service, $pos, $ok ) = @_;
    my %hpos = (
        0 => 0x01,
        1 => 0x02,
        2 => 0x04,
        3 => 0x08,
        4 => 0x10,
        5 => 0x20,
        6 => 0x40,
        7 => 0x80,
    );

    my $test = ( unpack( 'C1', $byte ) & $hpos{$pos} ) ? 1 : 0;
    my $retval = ( $ok == $test ) ? 0 : 2;
    my $line = "$host\t$service\t$retval\tSingle Bit Position: $pos Byte: " . unpack( 'B*', $byte ) . "\n";
    return $line;
}
