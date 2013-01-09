package MailCop::BlackList;
use Socket;

sub _order { 2 };

sub new {
	my $class = shift;
	my $self = {};
	$self->{ldap} = "";
	$self->{attr} = "";
	bless $self;
	return $self;
}

sub ldap {
	my $self = shift;
	my $ldap = shift;
	$self->{ldap} = $ldap;
}

sub attr {
	my $self = shift;
	my $attr = shift;
	$self->{attr} = $attr;
}

sub check {
  my ($self)  = @_;

	my $attr = $self->{attr};
	my $ldap = $self->{ldap};

	if ($attr->{request} eq "smtpd_access_policy") {
		for ( my $index = $ldap->count ; $index; $index-- ) {
			my $entry = $ldap->entry($index-1);
			my @netBlacklist = $entry->get_value('netBlacklist');
			my @domainBlacklist = $entry->get_value('domainBlacklist');
			my @mailBlacklist = $entry->get_value('mailBlacklist');
			foreach (@netBlacklist) {
				my $ip = substr($_,0,index($_," "));
				my $mask = substr($_,index($_," ")+1);
				if (is_in_net($attr->{client_address},$ip,$mask)) {
					return "REJECT Bloqueado pelo sistema antispam (CODE 21)";
				}
			}
			foreach (@domainBlacklist) {
				if ($attr->{sender} =~ m/.+?[^\@]\@$_/) {
					return "REJECT Bloqueado pelo sistema antispam (CODE 22)";
				}
			}
			foreach (@mailBlacklist) {
				if ($attr->{sender} eq $_) {
					return "REJECT Bloqueado pelo sistema antispam (CODE 23)";
				}
			}
		}
	}		
	return undef;
}

sub is_in_net {
    my ( $host, $network, $mask ) = @_ ;
    my ( $h, $n, $m ) ;


    $h = inet_aton ( $host ) ;
    $n = inet_aton ( $network ) ;
    $m = inet_aton ( $mask ) ;
#Teste nao usando o inet_ntoa para diminuir 1 chamada a uma funcao
#   if ( inet_ntoa ( $h & $m ) ne inet_ntoa ( $n & $m ) )
    if ( ($h & $m ) ne ( $n & $m ) )
    {
        return 0 ;
    }
    return 1 ;
}



1;
