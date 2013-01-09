package MailCop::ASNGrey;
use Net::DNS;

my $asndomain = ".asn.routeviews.org";

sub _order { 50 };

sub new {
	my $class = shift;
	my $self = {};
	$self->{ldap} = "";
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
	my $ldap = $self->{ldap};

  if ($attr->{request} eq "smtpd_access_policy") {
		my $gl = 0;
		if ($attr->{"sender"} =~ m/.+?\@(.*)/) { 
			my $senderdomain = $1;
			$gl = 2 if ($attr->{"client_name"} =~ m/$senderdomain$/);
			my $ClientASN = $self->asn_lookup($attr->{"client_address"});
			my @mxs = $self->mx_lookup($senderdomain);
			foreach (@mxs) {
				my $MX = $_;	
				my $MX = $_;	
				if ($gl ne 2) {
					my $mxASN = $self->asn_lookup($MX);
					$gl = 2 if $ClientASN eq $mxASN;
					$gl = 1 if $ClientASN ne $mxASN;
				}
			}
		}
		if ($gl eq 1) {
						return "GREYLIST Greylist indicada pelo sistema antispam (CODE 510)"
		} 
	}
	return undef;
}

sub asn_lookup {
	my $self = shift;
	my $IP = shift;
	my $res = Net::DNS::Resolver->new();
	my $result = $res->query(join('.', reverse(split(/\./, $IP))).$asndomain, "TXT", "IN");
	my $asn = $result->{answer}->[0]->{char_str_list}->[0];
	return $asn;
}

sub mx_lookup {
	my $self = shift;
	my $domain = shift;
	my @addresses;
	my $res = Net::DNS::Resolver->new;
	my @mx = mx($res,$domain);
	if (@mx) {
		foreach my $rr (@mx) {
			my $mxaddress = $rr->exchange;
			if (not $mxaddress =~ m/\d.\d.\d.\d/) {
				my $query = $res->search($mxaddress);
				if ($query) {
					foreach my $rr ($query->answer) {
						next unless $rr->type eq "A";
						push @addresses, $rr->address;
					} 
				}
			} else {
				push @addresses, $mxaddress;
			}
		}
	}
	return @addresses;
}


1;


