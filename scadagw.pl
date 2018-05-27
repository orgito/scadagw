#!/usr/bin/perl
use warnings;
use strict;
use Socket qw(IPPROTO_TCP SOL_SOCKET PF_INET SOCK_STREAM SO_KEEPALIVE TCP_NODELAY inet_aton sockaddr_in);
use IO::Socket::INET;
use POE qw(Component::Server::TCP);
use DBI;
use POSIX qw/strftime setsid/;
use Time::HiRes qw(gettimeofday);
use Log::Dispatch::FileRotate;

use constant {
    DATAGRAM_MAXLEN        => 292,
    RTUS_SERVER_PORT       => 8000,
    MGMT_SERVER_PORT       => 4000,
    RTU_TIMEOUT            => 240,
    RTU_PORTA              => 0,
    RTU_ENDERECO           => 1,
    RTU_TCP_SESSION        => 2,
    RTU_UDP_SESSION        => 3,
    RTU_MNG_SESSION        => 4,
    RTU_MNG_REMOTE_ADDRESS => 5,
};

# daemonize the program
local $| = 1;
&daemonize;
&savepid;

my $db_hostname = 'localhost';
my $db_name     = 'scadagw';
my $db_user     = 'scadagw';
my $db_password = 'platoe';

my $rtu_being_traced    = -1;
my %rtu_of_portaddress  = ();
my %rtu_of_tcp_session  = ();
my %udp_session_of_port = ();
my %info_for_rtu        = ();
my @udp_ports           = ();

# logar mensagens
my $log = Log::Dispatch::FileRotate->new(
    name        => 'log',
    min_level   => 'info',
    filename    => '/var/log/scadagw/scadagw.log',
    mode        => 'append',
    TZ          => 'BRT',
    DatePattern => 'yyyy-MM-dd',
    format      => '%m',
);

# rastrear a RTU
my $trace = Log::Dispatch::FileRotate->new(
    name        => 'trace',
    min_level   => 'info',
    filename    => '/var/log/scadagw/scadagw_trace.log',
    mode        => 'append',
    TZ          => 'BRT',
    DatePattern => 'yyyy-MM-dd',
    format      => '%m',
);

# formatar as mensagens e logar
sub print_log {
    my $message_string = join( "", @_ );
    my $date_string = localtime();
    $log->log( message => "$date_string $message_string\n", level => "info" );
    return;
}

# rastrear a RTU
sub trace {
    my ( $dir, $rtu, $dnp ) = @_;

    return if ( $rtu != $rtu_being_traced );

    # separar os bytes com um espaço para melhor visualização
    $dnp =~ s/(..)/$1 /g;
    $dnp =~ s/ $//;

    # formatar e logar as mensagens
    my ( $seconds, $microseconds ) = gettimeofday;
    my $hsec    = sprintf( "%02.0f",          $microseconds / 10000 );
    my $horario = strftime( "%H:%M:%S.$hsec", localtime($seconds) );
    my $msg     = "$dir$rtu ($horario): $dnp";
    $msg =~ s/(.{81})/$1\n/g;
    $trace->log( message => "$msg\n", level => "info" );
    return;
}

sub create_udp_session {
    my $listening_port = shift;
    POE::Session->create(
        inline_states => {
            _start => sub {
                my $kernel = $_[KERNEL];
                my $socket = IO::Socket::INET->new(
                    Proto     => 'udp',
                    LocalPort => $listening_port,
                );
                $_[HEAP]{socket}                 = $socket;
                $_[HEAP]{this_sesssion_udp_port} = $listening_port;
                die "Impossivel iniciar servidor: $!\n" unless $socket;
                $udp_session_of_port{$listening_port} = $_[SESSION]->ID();
                $kernel->select_read( $socket, "get_dnp_request" );
            },

            # receber uma mensagem de outra sessão
            end_session => sub {
                my ( $kernel, $heap ) = @_[ KERNEL, HEAP ];

                my $this_sesssion_udp_port = $_[HEAP]{this_sesssion_udp_port};

                # apaga os wheels.
                delete $heap->{wheel};

                # limpa os alias
                $kernel->alias_remove( $heap->{alias} );

                # remover qualquer alarme que tenha sido configurado
                $kernel->alarm_remove_all();

                # propagar a mensagem para os filhotes
                $kernel->post( $heap->{child_session}, 'shutdown' );

                delete( $udp_session_of_port{$this_sesssion_udp_port} );

                $kernel->select_read( delete $_[HEAP]{socket} );

                $kernel->yield("shutdown");

                return;
            },

            # receber a requisição do SCADA e enviar para a RTU
            get_dnp_request => sub {
                my ( $kernel, $socket ) = @_[ KERNEL, ARG0 ];
                my $remote_address = recv( $socket, my $dnp_request = "", DATAGRAM_MAXLEN, 0 );

                return unless defined $remote_address;

                $_[HEAP]{remote_address} = $remote_address;
                my ( $peer_port, $peer_addr ) = unpack_sockaddr_in($remote_address);
                my $local_port          = $socket->sockport();
                my $dnp_request_in_hexa = unpack 'H*', $dnp_request;
                my $endereco            = -1;

                # extrair o endereço e validar se é DNP
                if ( $dnp_request_in_hexa =~ /^0564....(..)(..)/ ) {
                    $endereco = hex("$2$1");
                }
                else {
                    print_log("SCADAFE $peer_port MENSAGEM INVALIDA $dnp_request_in_hexa");
                    return;
                }

                # descarta a mensagem se a RTU não existir
                if ( !exists $rtu_of_portaddress{"$local_port:$endereco"} ) {
                    print_log("SCADAFE $peer_port -> RTU nao cadastrada $endereco $local_port $dnp_request_in_hexa");
                    return;
                }

                my $current_rtu = $rtu_of_portaddress{"$local_port:$endereco"};

                # descartar se a RTU não estiver conectada
                if ( $info_for_rtu{$current_rtu}[RTU_TCP_SESSION] < 0 ) {
                    print_log("SCADAFE $peer_port -> RTU nao conectada $current_rtu  $dnp_request_in_hexa");
                    trace( "T", $current_rtu, $dnp_request_in_hexa );
                    return;
                }

                # identifcar RTU
                my $current_rtu_session = $info_for_rtu{$current_rtu}[RTU_TCP_SESSION];
                $info_for_rtu{$current_rtu}[RTU_UDP_SESSION] = $_[SESSION]->ID();

                # enviar  requisição
                $kernel->post( $current_rtu_session => send_dnp_request => $dnp_request );

                # logar
                my $connection_data = sprintf( "% 3d %3d %3d %4d", $current_rtu, $endereco, $current_rtu_session, $_[SESSION]->ID() );
                print_log("SCADAFE $peer_port -> RTU $connection_data $dnp_request_in_hexa");
                trace( "T", $current_rtu, $dnp_request_in_hexa );

                return;
            },

            # receber a resposta da RTU e enviar ao SCADA
            send_dnp_answer => sub {
                my $dnp_answer         = $_[ARG0];
                my $dnp_answer_in_hexa = unpack 'H*', $dnp_answer;
                my $endereco           = -1;

                my $socket         = $_[HEAP]{socket};
                my $remote_address = $_[HEAP]{remote_address};
                my ( $peer_port, $peer_addr ) = unpack_sockaddr_in($remote_address);
                my $local_port = $socket->sockport();

                # enviar a resposta da remota para o servidor SCADA
                if ( $dnp_answer_in_hexa =~ /^0564........(..)(..)/ ) {
                    $endereco = hex("$2$1");
                }
                else {
                    print_log("ERRO: MENSAGEM INVALIDA PARA SCADAFE $peer_port: $dnp_answer_in_hexa");
                    return;
                }

                # enviar a resposta
                send( $socket, $dnp_answer, 0, $remote_address ) == length($dnp_answer)
                  or warn "Problema enviado a resposta: $!\n";

                # identifcar a RTU
                my $current_rtu         = $rtu_of_portaddress{"$local_port:$endereco"};
                my $current_rtu_session = $info_for_rtu{$current_rtu}[RTU_TCP_SESSION];

                # logar
                my $comdata = sprintf( "% 3d %3d %3d %4d", $current_rtu, $endereco, $current_rtu_session, $_[SESSION]->ID() );
                print_log("SCADAFE $peer_port <- RTU $comdata $dnp_answer_in_hexa");
                trace( "R", $current_rtu, $dnp_answer_in_hexa );

                return;
            },
        }
    );
    return;
}

#Conexão com o banco.
my $dsn = "DBI:mysql:database=$db_name;host=$db_hostname";
my $dbh = DBI->connect( $dsn, $db_user, $db_password ) or die("Impossível conectar ao Servidor de Banco de Dados\n");
$dbh->{'mysql_auto_reconnect'} = 1;

#Extrair os dados das remotas
my $sql = "SELECT id_utr, end_fis, porta FROM utrs";
my $sth = $dbh->prepare($sql);
$sth->execute();
while ( my $rtu_ref = $sth->fetchrow_hashref() ) {
    my ( $porta, $end_fis ) = ( $rtu_ref->{'porta'}, $rtu_ref->{'end_fis'} );
    $rtu_of_portaddress{"$porta:$end_fis"} = $rtu_ref->{'id_utr'};
    $info_for_rtu{ $rtu_ref->{'id_utr'} } = [
        $rtu_ref->{'porta'},      #RTU_PORTA
        $rtu_ref->{'end_fis'},    #RTU_ENDERECO
        -1,                       #RTU_TCP_SESSION
        -1,                       #RTU_UDP_SESSION
        -1,                       #RTU_MNG_SESSION
        undef,                    #RTU_MNG_REMOTE_ADDRESS
    ];
}

# extrar a lista de portas UDP a serem ouvidas
$sql = 'SELECT DISTINCT porta FROM utrs ORDER BY porta';
$sth = $dbh->prepare($sql);
$sth->execute();
while ( my $rtu_ref = $sth->fetchrow_hashref() ) {
    push( @udp_ports, $rtu_ref->{'porta'} );
}

# iniciar as sessões para ouvir as requisições do servidor SCADA
foreach my $port_to_listen (@udp_ports) {
    create_udp_session($port_to_listen);
}

# sessão para controlar os sinais
POE::Session->create(
    inline_states => {
        _start => sub {
            $_[KERNEL]->sig( INT  => 'handle_signal' );
            $_[KERNEL]->sig( HUP  => 'handle_signal' );
            $_[KERNEL]->sig( TERM => 'handle_signal' );
            $_[KERNEL]->sig( QUIT => 'handle_signal' );
            $_[KERNEL]->delay( tick => 1 );
        },

        tick => sub {
            $_[KERNEL]->delay( tick => 1 );
        },

        handle_signal => sub {
            print_log("Sinal $_[ARG0] recebido... shutting down");
            my $disconnected = strftime( "%Y-%m-%d %H:%M:%S", localtime );
            $sth = $dbh->prepare("UPDATE utrs SET estado = 'DESCONECTADA', desconectado=? WHERE estado <> 'DESCONECTADA'");
            $sth->execute($disconnected);
            $sth = $dbh->prepare("UPDATE utr_historico SET desconectado=? WHERE valido=0");
            $sth->execute($disconnected);
            $dbh->disconnect();
            $_[KERNEL]->sig_handled();
            exit(0);
        },
    },
);

# servidor para ouvir as remotas
POE::Component::Server::TCP->new(
    Alias        => "rtu_server",
    Port         => RTUS_SERVER_PORT,
    ClientFilter => "POE::Filter::Stream",

    Started => sub {
        print_log("Resetando o status das RTUs");
        $dbh->do("UPDATE utrs SET estado = 'DESCONECTADA'");
        print_log( "Aguardando conexoes das RTUs na porta ", RTUS_SERVER_PORT );
    },
    Error => sub {
        my ( $syscall, $error_number, $error_message ) = @_[ ARG0 .. ARG2 ];
        die( "Impossível iniciar servidor: ", "$syscall erro $error_number: $error_message\n" );
    },

    # logar a conexão de uma RTU
    ClientConnected => sub {
        my $client_id = $_[SESSION]->ID();
        $_[HEAP]{connect_time} = strftime( "%Y-%m-%d %H:%M:%S", localtime );
        print_log("Sessao $client_id iniciada para RTU $_[HEAP]{remote_ip}");
    },

    ClientError => sub {
        my ( $syscall_name, $error_num, $error_str ) = @_[ ARG0 .. ARG2 ];
        print_log("CLIENT ERROR: $syscall_name, $error_num, $error_str");
    },

    # logar a desconexão de um RTU
    ClientDisconnected => sub {
        my $client_id = $_[SESSION]->ID();

        print_log("Sessao $client_id terminada para RTU $_[HEAP]{remote_ip}");

        if ( exists $rtu_of_tcp_session{$client_id} ) {
            my $disconnect_time = strftime( "%Y-%m-%d %H:%M:%S", localtime );
            $sth = $dbh->prepare("UPDATE utrs SET desconectado=?, estado='DESCONECTADA' WHERE id_utr = ?");
            $sth->execute( $disconnect_time, $rtu_of_tcp_session{$client_id} );

            $sth = $dbh->prepare("UPDATE utr_historico SET desconectado=?, valido=1 WHERE id_utr=? AND conectado=?");
            $sth->execute( $disconnect_time, $rtu_of_tcp_session{$client_id}, $_[HEAP]{connect_time} );

            $info_for_rtu{ $rtu_of_tcp_session{$client_id} }[RTU_TCP_SESSION] = -1;

            delete( $rtu_of_tcp_session{$client_id} );
        }
    },

    # tratar mensagem vinda da RTU. "Autenticar", repassar a para o SCADA ou repassar para gerente
    ClientInput => sub {
        my ( $kernel, $heap, $dnp_answer ) = @_[ KERNEL, HEAP, ARG0 ];
        my $this_session_rtu   = $rtu_of_tcp_session{ $_[SESSION]->ID() };
        my $dnp_answer_in_hexa = unpack( 'H*', $dnp_answer );
        my $rtu_id             = '';

        # primeiro pacote da RTU. Verifica o ID
        if ( !exists $rtu_of_tcp_session{ $_[SESSION]->ID() } ) {

            # extrair o id
            if ( my @idpart = ( $dnp_answer_in_hexa =~ /^(..)(..)(..)(..)(..)................303031/ ) ) {
                foreach my $byte (@idpart) {
                    if ( $byte =~ /^3(.)/ ) {
                        $rtu_id .= $1;
                    }
                    else {
                        last;
                    }
                }
            }
            elsif ( $dnp_answer_in_hexa =~ /^(3.)+/ ) {
                $rtu_id = $dnp_answer;
            }
            else {
                $rtu_id = hex($dnp_answer_in_hexa);
            }

            # desconectar caso não tenha cadastro
            if ( !exists $info_for_rtu{$rtu_id}[RTU_TCP_SESSION] ) {
                print_log("RTU $rtu_id NAO CADASTRADA. DESCONECTANDO");
                $_[KERNEL]->yield("shutdown");
                return;
            }

            my $rtu_time_of_authentication = strftime( "%Y-%m-%d %H:%M:%S", localtime );

            print_log("RTU $rtu_id AUTENTICADA");

            # contagem regressiva para desconectar
            $kernel->delay( timed_out => RTU_TIMEOUT );

            # gravar informações da RTU e ligar
            $rtu_of_tcp_session{ $_[SESSION]->ID() } = $rtu_id;
            $info_for_rtu{$rtu_id}[RTU_TCP_SESSION] = $_[SESSION]->ID();

            #atualizar registro
            $sth = $dbh->prepare("UPDATE utrs SET conectado=?, ip_utr=?, estado = 'AUTENTICADA', desconectado=NULL WHERE id_utr=?");
            $sth->execute( $rtu_time_of_authentication, $_[HEAP]{remote_ip}, $rtu_id );

            #inserir no histórico
            $sth = $dbh->prepare("INSERT INTO utr_historico(id_utr,ip_utr,conectado,autenticado) VALUES(?,?,?,?)");
            $sth->execute( $rtu_id, $_[HEAP]{remote_ip}, $_[HEAP]{connect_time}, $rtu_time_of_authentication );
        }

        # tratar mensagem DNP
        elsif ( $dnp_answer_in_hexa =~ /^0564/ ) {
            $kernel->delay( timed_out => RTU_TIMEOUT );
            $kernel->post( $info_for_rtu{$this_session_rtu}[RTU_UDP_SESSION] => send_dnp_answer => $dnp_answer );
        }

        # tratar mensagem de gerência
        elsif ( $dnp_answer_in_hexa =~ /^0d0a.*0d0a$/ ) {
            my $answer = substr( $dnp_answer, 2, -2 );
            $kernel->delay( timed_out => RTU_TIMEOUT );
            $_[KERNEL]->post( $info_for_rtu{$this_session_rtu}[RTU_MNG_SESSION] => send_message => $answer );
        }

        # ignorar mensagem
        else {
            $kernel->delay( timed_out => RTU_TIMEOUT );
            print_log("RTU $rtu_of_tcp_session{$_[SESSION]->ID()} IGNORADA - $dnp_answer_in_hexa");
        }

        return;
    },

    InlineStates => {

        # derruba a sessão em caso de inatividade da RTU
        timed_out => sub {
            my ( $kernel, $heap ) = @_[ KERNEL, HEAP ];
            my $disconnect_time = strftime( "%Y-%m-%d %H:%M:%S", localtime );
            my $this_session_rtu = $rtu_of_tcp_session{ $_[SESSION]->ID() };

            delete( $rtu_of_tcp_session{ $_[SESSION]->ID() } );
            $info_for_rtu{$this_session_rtu}[RTU_TCP_SESSION] = -1;

            $sth = $dbh->prepare("UPDATE utrs SET desconectado=?, estado='DESCONECTADA' WHERE id_utr = ?");
            $sth->execute( $disconnect_time, $this_session_rtu );

            $sth = $dbh->prepare("UPDATE utr_historico SET desconectado=?, valido=1 WHERE id_utr=? AND conectado=?");
            $sth->execute( $disconnect_time, $this_session_rtu, $_[HEAP]{connect_time} );

            print_log( "Sessao ", $_[SESSION]->ID(), " finalizada para a remota ", $this_session_rtu, " por time out!" );
            $kernel->yield("shutdown");
        },

        # finalizar sessão
        end_session => sub {
            my $kernel = $_[KERNEL];
            my $this_session_rtu = $rtu_of_tcp_session{ $_[SESSION]->ID() };

            delete( $rtu_of_tcp_session{ $_[SESSION]->ID() } );
            $info_for_rtu{$this_session_rtu}[RTU_TCP_SESSION] = -1;
            $kernel->yield('shutdown');

            return;
        },

        send_dnp_request => sub {
            my ( $heap, $dnp_request ) = @_[ HEAP, ARG0 ];

            $heap->{client}->put($dnp_request);

            return;
        },
    },
);

# servidor para receber comandos da interface web
POE::Session->create(
    inline_states => {
        _start => sub {
            my $kernel = $_[KERNEL];
            my $socket = IO::Socket::INET->new(
                LocalAddr => 'localhost',
                Proto     => 'udp',
                LocalPort => MGMT_SERVER_PORT,
            );
            die "Impossivel iniciar servidor: $!\n" unless $socket;
            $_[HEAP]{socket} = $socket;
            print_log( "Iniciando servidor MGMT na porta ", MGMT_SERVER_PORT );
            $kernel->select_read( $socket, "handle_cmd" );
        },

        # avisar o cliente sobre o timeout na resposta de gerencia da RTU
        at_timed_out => sub {
            $info_for_rtu{ $_[HEAP]{rtu} }[RTU_MNG_SESSION] = -1;
            send( $_[HEAP]{socket}, "-TIMEOUT", 0, $info_for_rtu{ $_[HEAP]{rtu} }[RTU_MNG_REMOTE_ADDRESS] );
            $_[KERNEL]->yield("shutdown");
        },

        # receber a resposta de gerência da sessão TCP
        send_message => sub {
            my $msg = $_[ARG0];
            $_[KERNEL]->delay( at_timed_out => undef );
            $info_for_rtu{ $_[HEAP]{rtu} }[RTU_MNG_SESSION] = -1;
            send( $_[HEAP]{socket}, $msg, 0, $info_for_rtu{ $_[HEAP]{rtu} }[RTU_MNG_REMOTE_ADDRESS] );
        },

        # tratar os comandos recebidos via web
        handle_cmd => sub {
            my ( $kernel, $socket ) = @_[ KERNEL, ARG0 ];
            my $remote_address = recv( $socket, my $message = "", DATAGRAM_MAXLEN, 0 );
            my ( $ref, $id, $porta, $end_fis, %hash );
            return unless defined $remote_address;
            my @cmd = split( /\s+/, $message );

            # comando de gerência. Mandar para a RTU
            if ( $cmd[0] eq 'MNG' ) {

                # extrair o comando de gerencia
                $message =~ /^MNG (.*)/;
                my $msg = $1;
                my ( $rtu, $atcmd ) = split( /;/, $msg );

                # validação básica do comando
                if ( $atcmd !~ /^AT\+/i ) {
                    send( $_[HEAP]{socket}, "-Comando inválido: $atcmd", 0, $remote_address );
                    return;
                }

                # a RTU esta conectada?
                if ( ( not exists( $info_for_rtu{$rtu}[RTU_TCP_SESSION] ) ) or ( $info_for_rtu{$rtu}[RTU_TCP_SESSION] < 0 ) ) {
                    send( $_[HEAP]{socket}, "-Remota $rtu não conectada! Comando: $atcmd", 0, $remote_address );
                    return;
                }

                # não mandar comandos se a RTU já estiver ocupada
                if ( $info_for_rtu{ $_[HEAP]{rtu} }[RTU_MNG_SESSION] > 0 ) {
                    my $ses = $_[SESSION]->ID();
                    send( $_[HEAP]{socket}, "-Remota $rtu ocupada! Comando:$atcmd", 0, $remote_address );
                    return;
                }

                # guardar as informações para perimitir a sessão TCP identificar pra onde retornar
                # a resposta
                $info_for_rtu{ $_[HEAP]{rtu} }[RTU_MNG_SESSION]        = $_[SESSION]->ID();
                $info_for_rtu{ $_[HEAP]{rtu} }[RTU_MNG_REMOTE_ADDRESS] = $remote_address;
                $_[HEAP]{rtu}                                          = $rtu;

                # enviar o comando pra sessão TCP apropriada
                $_[KERNEL]->post( $info_for_rtu{$rtu}[RTU_TCP_SESSION] => send_dnp_request => $atcmd );

                # iniciar contagem regressiva
                $_[KERNEL]->delay( at_timed_out => 10 );

                return;
            }

            # validação básica
            if ( @cmd != 2 ) {
                print_log("MGMT SERVER: Comando invalido recebido: @cmd");
                return;
            }

            # tratar adição de RTU
            if ( $cmd[0] eq 'ADD' ) {
                $id = $cmd[1];
                print_log("MGMT SERVER: ADD $id");

                if ( exists $info_for_rtu{$id}[RTU_TCP_SESSION] ) {
                    print_log("MGMT SERVER: Tentativa de adicionar remota $id ja existente!");
                    return;
                }

                $sql = "SELECT id_utr, end_fis, porta FROM utrs WHERE id_utr=?";
                $sth = $dbh->prepare($sql);
                $sth->execute($id);

                #Preenche as variáveis de controle
                $ref = $sth->fetchrow_hashref();

                if ( !$ref ) {
                    print_log("MGMT SERVER: Tentativa de adicionar remota $id nao existente no BD!");
                    return;
                }

                $rtu_of_portaddress{"$ref->{'porta'}:$ref->{'end_fis'}"} = $ref->{'id_utr'};
                $info_for_rtu{ $ref->{'id_utr'} } = [ $ref->{'porta'}, $ref->{'end_fis'}, -1, -1, -1, undef ];

                print_log("MGMT SERVER: Remota $id adicionada");

                #Cria uma nova secao UDP ser for uma nova porta
                @hash{@udp_ports} = ();
                if ( !exists $hash{ $ref->{'porta'} } ) {
                    push( @udp_ports, $ref->{'porta'} );
                    create_udp_session( $ref->{'porta'} );
                    print_log("MGMT SERVER: Iniciada sessao UDP na porta $ref->{'porta'}");
                }

                return;
            }

            # tratar exclusão de RTU
            if ( $cmd[0] eq 'DEL' ) {
                $id = $cmd[1];
                print_log("MGMT SERVER: DEL $id");

                if ( !exists $info_for_rtu{$id}[RTU_TCP_SESSION] ) {
                    print_log("MGMT SERVER: Tentando Apagar remota inexistente: $id");
                    return;
                }

                $porta   = $info_for_rtu{$id}[RTU_PORTA];
                $end_fis = $info_for_rtu{$id}[RTU_ENDERECO];

                #Se estiver conectada elimina a sessão TCP
                if ( $info_for_rtu{$id}[RTU_TCP_SESSION] > 0 ) {
                    $kernel->post( $info_for_rtu{$id}[RTU_TCP_SESSION] => end_session => "" );
                }

                #Se esta for a única remota na porta elimina a sessão UDP
                $sql = "SELECT porta FROM utrs WHERE porta=?";
                $sth = $dbh->prepare($sql);
                $sth->execute($porta);
                $ref = $sth->fetchrow_hashref();
                if ( !$ref ) {
                    print_log("MGMT SERVER: Removendo sessao UDP da porta $porta");
                    @udp_ports = grep { $_ != $porta } @udp_ports;
                    $kernel->post( $udp_session_of_port{$porta} => end_session => "" );
                }
                delete( $rtu_of_portaddress{"$porta:$end_fis"} );
                delete( $info_for_rtu{$id} );

                print_log("MGMT SERVER: Remota $id deletada porta $porta end $end_fis");
                return;
            }

            # tratar atualização de RTU
            if ( $cmd[0] eq 'UPD' ) {
                $id = $cmd[1];
                print_log("MGMT SERVER: UPD $id");

                if ( !exists $info_for_rtu{$id}[RTU_TCP_SESSION] ) {
                    print_log("MGMT SERVER: Tentando atualizar remota inexistente: $id");
                    return;
                }

                $porta   = $info_for_rtu{$id}[RTU_PORTA];
                $end_fis = $info_for_rtu{$id}[RTU_ENDERECO];

                #Verificando se a remota está conectada
                if ( $info_for_rtu{$id}[RTU_TCP_SESSION] > 0 ) {
                    print_log("MGMT SERVER: Nao e permitido atualizar uma remota conectada: $id");
                    return;
                }

                $sql = "SELECT id_utr, end_fis, porta FROM utrs WHERE id_utr=?";
                $sth = $dbh->prepare($sql);
                $sth->execute($id);

                #Preenche as variáveis de controle
                $ref = $sth->fetchrow_hashref();

                if ( !$ref ) {
                    print_log("MGMT SERVER: Tentativa de atualizar remota $id nao existente no BD!");
                    return;
                }

                $rtu_of_portaddress{"$ref->{'porta'}:$ref->{'end_fis'}"} = $ref->{'id_utr'};
                $info_for_rtu{ $ref->{'id_utr'} } = [ $ref->{'porta'}, $ref->{'end_fis'}, -1, -1, -1, undef ];

                print_log("MGMT SERVER: Remota $id atualizada");

                #Cria uma nova secao UDP ser for uma nova porta
                @hash{@udp_ports} = ();
                if ( !exists $hash{ $ref->{'porta'} } ) {
                    push( @udp_ports, $ref->{'porta'} );
                    create_udp_session( $ref->{'porta'} );
                    print_log("MGMT SERVER: Iniciada sessao UDP na porta $ref->{'porta'}");
                }

                #Se esta for a única remota na porta elimina a sessão UDP
                $sql = "SELECT porta FROM utrs WHERE porta=?";
                $sth = $dbh->prepare($sql);
                $sth->execute($porta);
                $ref = $sth->fetchrow_hashref();
                if ( !$ref ) {
                    @udp_ports = grep { $_ != $porta } @udp_ports;
                    $kernel->post( $udp_session_of_port{$porta} => end_session => "" );
                    print_log("MGMT SERVER: Removida sessao UDP da porta $porta");
                }

                return;
            }

            # iniciar rastreamento da RTU
            if ( $cmd[0] eq 'TRC' ) {
                $rtu_being_traced = $cmd[1];
                print_log("MGMT SERVER: TRC $rtu_being_traced");
                return;
            }

            print_log("MGMT SERVER: comando $cmd[0] nao implementado!");

            return;
          }
    }
);

sub daemonize {
    chdir '/' or die "Can’t chdir to /: $!\n";
    open( STDIN,  '<',  '/dev/null' ) or die "Can’t read /dev/null: $!\n";
    open( STDOUT, '>>', '/dev/null' ) or die "Can’t write to /dev/null: $!\n";
    defined( my $pid = fork ) or die "Can’t fork: $!\n";
    exit if $pid;
    setsid or die "Can’t start a new session: $!\n";
    $poe_kernel->has_forked();
    open( STDERR, '>>', '/var/log/scadagw/scadagw.err' ) or die "Can’t write to scadagw.err: $!\n";
    return;
}

sub savepid {
    my $pid = $$;
    open( my $fd, '>', '/var/run/scadagw.pid' ) or die "$!\n";
    print $fd $pid;
    close $fd or die "$!\n";
    return;
}

$poe_kernel->run();
exit 0;
