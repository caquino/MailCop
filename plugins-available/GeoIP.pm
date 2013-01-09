package MailCop::GeoIP;
use Geo::IP;

sub _order { 70 };

sub new {
	my $class = shift;
	my $self = {};
	$self->{gi} = Geo::IP->new(GEOIP_STANDARD);
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
	my $gi = $self->{gi};

  if ($attr->{request} eq "smtpd_access_policy") {
		my $country = $gi->country_code_by_addr($attr->{client_address});

		my $cfg = new Config::IniFiles( -file => "/srv/policy/mailcop/mailcop.ini" );
		my $glcountry = $cfg->val("GeoIP","glcountry");
		my $rejectcountry = $cfg->val("GeoIP","rejectcountry");

		if (defined $rejectcountry) {
			if ($country =~ m/$rejectcountry/gi) {
				return "REJECT Bloqueado pelo sistema antispam (CODE 700)";
			}
		}

		if (defined $glcountry) {
			if ($country =~ m/$glcountry/gi) {
				return "GREYLIST Greylist indicada pelo sistema antispam (CODE 701)";
			}
		}

	}

	return undef;
}

1;
