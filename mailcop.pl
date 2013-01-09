#!/usr/bin/perl

=head1 NAME

MailCop - Postfix delegation pluggable policy

=head1 SYNOPSIS

Edit the mailcop.ini file for all the configuration variables

=head1 DESCRIPTION

MailCop is one pluggable postfix delegation policy.

=cut

package MailCop;

use strict;
use warnings;

use Socket;
use Config::IniFiles;
use Sys::Syslog qw(:DEFAULT setlogsock);
use Data::Dumper;
use Switch;
use Cache::Memcached;
use Module::Pluggable::Ordered search_path => ['plugins-enabled'], 
															 sub_name    => "policy_plugins";


use Socket;
use POE qw(	Wheel::SocketFactory
		Wheel::ReadWrite
		Driver::SysRW
		Filter::Stream
		Component::Server::TCP
					);

use vars qw( 
        $current_folder
        $cfg
		$port
		$listenaddr
		$syslog_socktype
		$syslog_options
		$syslog_priority
		$syslog_facility
		$greylist_stage1
		$greylist_stage2
		$greylist_stage3
		$debug
		$memcache
		@plugins 
		$start
		$messages
		$dunno
		$greylist
		$reject
		$ok
	);


$| = 1;

BEGIN {
#Certifica-se que esta no diretorio corrent
	chdir (${[($0 =~ /^(.*)[\\\/][^\\\/]+$/)]}[0] || ".");
}



eval {
    $current_folder  = ${[($0 =~ /^(.*)[\\\/][^\\\/]+$/)]}[0];
	$cfg             = new Config::IniFiles( -file => $current_folder."/mailcop.ini" );

	$syslog_socktype = $cfg->val("syslog","socktype");
	$syslog_options  = $cfg->val("syslog","options");
	$syslog_priority = $cfg->val("syslog","priority");
	$syslog_facility = $cfg->val("syslog","facility");

	setlogsock $syslog_socktype;
	$0 =~ m/.*\/([^\/].+)$/;
	openlog $1, $syslog_options, $syslog_facility;

	syslog $syslog_priority, "Starting MailCop";
	print STDERR "Starting MailCop\n";

	$SIG{'HUP'} = \&Reload;
	$SIG{'USR1'} = \&Stats; 
	$SIG{'ALRM'} = \&Alarm;

	$debug			= $cfg->val("debug","debug");

	$port            = $cfg->val("network","port");
	$listenaddr      = $cfg->val("network","listen");


	$greylist_stage1 = $cfg->val("greylist","stage1");
	$greylist_stage2 = $cfg->val("greylist","stage2");
	$greylist_stage3 = $cfg->val("greylist","stage3");

	@plugins				 = MailCop->policy_plugins_ordered();
	$start					 = time;
	$messages				 = 0;
	$greylist				 = 0;
	$ok							 = 0;
	$dunno					 = 0;
	$reject					 = 0;

	foreach (@plugins) {
		print STDERR "Adding plugin: $_\n";
		syslog $syslog_priority, "Adding plugin: %s", $_;
	}
		
	$memcache = new Cache::Memcached {
							'servers' 					 => [ "10.0.0.5:11211" ],
							'debug'   					 => 0,
							'compress_threshold' => 10_000,
						};
	alarm(10);
	&Main;
};


if ($@) {
	syslog $syslog_priority, "Ending MailCop: %s", $@;
	print STDERR "Ending Mailcop: $@\n";
}

sub Reload {
	print STDERR "Reloading\n";
	syslog $syslog_priority, "Reloading\n";
	$cfg             = new Config::IniFiles( -file => $current_folder."/mailcop.ini" );

	$debug	   			 = $cfg->val("debug","debug");

	$port            = $cfg->val("network","port");
	$listenaddr      = $cfg->val("network","listen");

	$syslog_socktype = $cfg->val("syslog","socktype");
	$syslog_options  = $cfg->val("syslog","options");
	$syslog_priority = $cfg->val("syslog","priority");
	$syslog_facility = $cfg->val("syslog","facility");

	$greylist_stage1 = $cfg->val("greylist","stage1");
	$greylist_stage2 = $cfg->val("greylist","stage2");
	$greylist_stage3 = $cfg->val("greylist","stage3");

	@plugins				 = MailCop->policy_plugins_ordered();

	foreach (@plugins) {
		print STDERR "Adding plugin: $_\n";
		syslog $syslog_priority, "Adding plugin: %s", $_;
	}

}

sub Alarm {
	&Stats;
	alarm(300);
}

sub Stats {
	my $seconds = time - $start;
	my $mps		  = $messages/$seconds;
	print STDERR "======================================\n";
	print STDERR "MailCop Statistics\n";
	print STDERR "======================================\n";
	print STDERR "Uptime (seconds): ".$seconds."\n";
	print STDERR "Messages parsed: ".$messages."\n";
	print STDERR "Messages per second: ".$mps."\n";
	print STDERR "DUNNO: ".$dunno."\n";
	print STDERR "REJECT: ".$reject."\n";
	print STDERR "GREYILST: ".$greylist."\n";
	print STDERR "OK: ".$ok."\n";
	print STDERR "======================================\n";
}

#####
sub Main {
	syslog $syslog_priority, "Criando sessao POE" if $debug;
	POE::Session->create(
		inline_states => {
			_start => \&parent_start,
			_stop  => \&parent_stop,

			socket_birth => \&socket_birth,
			socket_death => \&socket_death,
		}
	);
	syslog $syslog_priority, "Inicialiando kernel POE" if $debug;
	$poe_kernel->run();
}

####################################

sub parent_start {
	my $heap = $_[HEAP];
	syslog $syslog_priority, "Criando listener" if $debug;
	$heap->{listener} = POE::Wheel::SocketFactory->new(
		BindAddress  => $listenaddr,
		BindPort     => $port,
		Reuse        => 'yes',
		SuccessEvent => 'socket_birth',
		FailureEvent => 'socket_death',
	);
}

sub parent_stop {
	my $heap = $_[HEAP];
	syslog $syslog_priority, "Encerrando listener" if $debug;
	delete $heap->{listener};
	delete $heap->{session};
}

sub socket_birth {
	my ( $socket, $address, $port ) = @_[ ARG0, ARG1, ARG2 ];
	syslog $syslog_priority, "Criando socket" if $debug;

	$address = inet_ntoa($address);

	POE::Session->create(
		inline_states => {
			_start => \&socket_success,
			_stop  => \&socket_death,

			socket_input => \&socket_input,
			socket_death => \&socket_death,
		},
		args => [ $socket, $address, $port ],
	);
}

sub socket_death {
	my $heap = $_[HEAP];
	syslog $syslog_priority, "Encerrando socket" if $debug;

	if ( $heap->{socket_wheel} ) {
		delete $heap->{socket_wheel};
	}
	if ( $heap->{attr} ) {
		delete $heap->{attr};
	}
}

sub socket_success {
	my ( $heap, $kernel, $connected_socket, $address, $port ) = @_[ HEAP, KERNEL, ARG0, ARG1, ARG2 ];
	my $session_id = $_[SESSION]->ID;

	syslog $syslog_priority, "Conexao de %s:%s sessao numero %s", $address, $port, $session_id if $debug;

	$heap->{attr} = ();


	$heap->{socket_wheel} = POE::Wheel::ReadWrite->new(
		Handle => $connected_socket,
		Driver => POE::Driver::SysRW->new(),
		Filter => POE::Filter::Stream->new(),
		
		InputEvent => 'socket_input',
		ErrorEvent => 'socket_death',
	);

}

sub socket_input {
	my ( $heap, $buf ) = @_[ HEAP, ARG0 ];
	my $session_id = $_[SESSION]->ID;
	
	my @lines;
	if ($buf =~ m/\n/g) {
		$buf =~ s/\r//g;
		@lines = split(/\n/,$buf);
	} else {
		push @lines, $buf;
	}
	if ($buf =~ m/\n\n$/g or m/^\n$/g) {
		push @lines, "\n";
	}

	foreach (@lines) {
		if (m/([^=]+)=(.*)/) {
			syslog $syslog_priority, "Adicionando atributo %s como valor %s", $1, $2 if $debug;
			$heap->{attr}->{lc(substr($1, 0, 512))} = lc(substr($2, 0, 512));
		} elsif ( $_ eq "\n") {
			syslog $syslog_priority, "Processando email para %s", $heap->{attr}->{recipient} if $debug;
			$messages++;
			my $email = $heap->{attr}->{recipient};
			$email =~ m/^([^\@]+)\@(.*)/g;
			my $username = $1;
			my $domain = $2;

			my $result;
			for my $plugin (@plugins) {
			  syslog $syslog_priority, "Carregando plugin %s", $plugin if $debug;
				next unless $plugin->can('check');
				my $tmp;
				my $tmpcheck;
				eval {
				  $tmp = new $plugin;
					$tmp->attr(\%{$heap->{attr}});
					if ($plugin->can('heap')) {
						$tmp->heap($heap);
					}
					$tmpcheck = $tmp->check();
				};
				if ($@) {
				  print STDERR $@;
					syslog $syslog_priority, "Plugin error %s: %s", $plugin, $@;
				}
				syslog $syslog_priority, "Plugin %s retornou %s", $plugin, $tmpcheck if $debug;

				last if defined $result and ($result =~ m/^reject/i or $result =~ m/^ok/i);
				$result = (defined $tmpcheck) ? $tmpcheck : $result;
				syslog $syslog_priority, "Valor de retorno: %s", $result if $debug;
			}

			if ($result) {
				if ($result =~ m/^greylist (.*)$/i) {
					my $reason = $1;
					my @keys;
					my $key = $heap->{attr}->{recipient}."/".$heap->{attr}->{sender}."/".$heap->{attr}->{client_address};
					push @keys, $key."/stage1";
					push @keys, $key."/stage2";
					push @keys, $key."/stage3";
					my $retkeys = $memcache->get_multi(@keys);
					if (defined $retkeys->{$key."/stage1"} and defined $retkeys->{$key."/stage2"}) {
						$greylist++;
						$heap->{socket_wheel}->put("action=DEFER_IF_PERMIT $reason\n\n");
					} elsif (defined $retkeys->{$key."/stage2"} and not defined $retkeys->{$key."/stage1"}) {
						$dunno++;
						$memcache->set($key."/stage3","1",$greylist_stage3);
						$heap->{socket_wheel}->put("action=DUNNO\n\n");
					} elsif (defined $retkeys->{$key."/stage3"}) {
						$dunno++;
						$memcache->delete($key."/stage3");
						$memcache->set($key."/stage3","1",$greylist_stage3);
						$heap->{socket_wheel}->put("action=DUNNO\n\n");
					} else {
						if ($memcache->set($key."/stage1",$reason,$greylist_stage1) and $memcache->set($key."/stage2","1",$greylist_stage2)) {
							$greylist++;
							$heap->{socket_wheel}->put("action=DEFER_IF_PERMIT $reason\n\n");
						} else {
							$dunno++;
							$heap->{socket_wheel}->put("action=DUNNO\n\n");
						}
					}
				} elsif ($result =~ m/^ok/i) {
					syslog $syslog_priority, "OK" if $debug;
					$ok++;
				  	syslog $syslog_priority, "NOQUEUE: ok: RCPT from %s[%s]: %s; from=<%s> to=<%s> proto=%s helo=<%s>", $heap->{attr}->{client_name}, $heap->{attr}->{client_address}, $result, $heap->{attr}->{recipient}, $heap->{attr}->{sender}, $heap->{attr}->{protocol_name}, $heap->{attr}->{helo_name} if $debug;
					$heap->{socket_wheel}->put("action=OK\n\n");
				} else  {
					$reject++;
				  syslog $syslog_priority, "NOQUEUE: reject: RCPT from %s[%s]: %s; from=<%s> to=<%s> proto=%s helo=<%s>", $heap->{attr}->{client_name}, $heap->{attr}->{client_address}, $result, $heap->{attr}->{recipient}, $heap->{attr}->{sender}, $heap->{attr}->{protocol_name}, $heap->{attr}->{helo_name} if $debug;
					$heap->{socket_wheel}->put("action=$result\n\n");
				}
			} else {
				$dunno++;
				  syslog $syslog_priority, "NOQUEUE: dunno: RCPT from %s[%s]: %s; from=<%s> to=<%s> proto=%s helo=<%s>", $heap->{attr}->{client_name}, $heap->{attr}->{client_address}, $result, $heap->{attr}->{recipient}, $heap->{attr}->{sender}, $heap->{attr}->{protocol_name}, $heap->{attr}->{helo_name} if $debug;
				$heap->{socket_wheel}->put("action=DUNNO\n\n");
			}

			$heap->{attr} = ();

		} else {
			syslog $syslog_priority, "Ignorando lixo: %.100s", $_ if $debug;
		}
	}
}
