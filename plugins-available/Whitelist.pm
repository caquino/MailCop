package MailCop::Whitelist;
use Socket;

sub _order { 1 };

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
			my @netWhitelist = $entry->get_value('netWhitelist');
			my @domainWhitelist = $entry->get_value('domainWhitelist');
			my @mailWhitelist = $entry->get_value('mailWhitelist');
			foreach (@netWhitelist) {
				my $ip = substr($_,0,index($_," "));
				my $mask = substr($_,index($_," ")+1);
				if (is_in_net($attr->{client_address},$ip,$mask)) {
					return "OK";
				}
			}
			foreach (@domainWhitelist) {
				if ($attr->{sender} =~ m/.+?[^\@]\@$_/) {
					return "OK";
				}
			}
			foreach (@mailWhitelist) {
				if ($attr->{sender} eq $_) {
					return "OK";
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
