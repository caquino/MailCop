package MailCop::SPFCheck;
use Mail::SPF::Query;

sub _order { 50 };

sub new {
	my $class = shift;
	my $self = {};
	$self->{ldap} = "";
	$self->{attr} = "";
	$self->{heap} = "";
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

	my $query = new Mail::SPF::Query (ip => $attr->{client_address}, sender => $attr->{sender}, helo => $attr->{helo_name}, guess => 0, trusted => 0);
	my ($result, $smtp_comment,$header_comment,$spf_record) = $query->result();
	if	($result eq "softfail") {
		return "GREYLIST Greylist indicada pelo sistema anti spam (CODE 500)";
	}

	if ($result eq "fail") {
		return "REJECT Bloqueado pelo sistema anti spam (CODE 501) $smtp_comment";
	}

	return undef; #"PREPEND Received-SPF: $result ($header_comment)";

}

1;
