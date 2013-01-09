package MailCop::HeloCheck;


sub _order { 30 };


sub new {
	my $class = shift;
	my $self = {};
	$self->{attr} = "";
	bless $self;
	return $self;
}


sub attr {
	my $self = shift;
	my $attr = shift;
	$self->{attr} = $attr;
}

sub check {
  my ($self)  = @_;

	my $attr = $self->{attr};

  if ($attr->{request} eq "smtpd_access_policy") {
		if ($attr->{helo_name} =~ m/\d+\.\d+\.\d+\.\d+/ and ($attr->{helo_name} ne $attr->{client_address})) {
			return "REJECT Bloqueado pelo sistema antispam (CODE 300)"
		}
	
		if ($attr->{helo_name} !~ m/\./) {
			return "REJECT Bloqueado pelo sistema antispam (CODE 301)"
		}

		$attr->{recipient} =~ m/^([^\@]+)\@(.*)/g;
		my $domain = $2;

		if (lc($domain) eq lc($attr->{helo_name})) {
			return "REJECT Bloqueado pelo sistema antispam (CODE 302)"
		}
	}
	return undef;
}

1;
