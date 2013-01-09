package MailCop::PTRCheck;


sub _order { 40 };

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
		if ($attr->{client_name} eq "unknown") {
			return "GREYLIST Greylist indicada pelo sistema antispam (CODE 400)"
		}
	}
	return undef;
}

1;
