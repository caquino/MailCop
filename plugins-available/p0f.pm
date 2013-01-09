package MailCop::p0f;
use IO::Socket;
use Net::IP;

sub _order { 60 };

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

	my $QUERY_MAGIC = 0x0defaced;
	my $QTYPE_FINGERPRINT = 1;

  if ($attr->{request} eq "smtpd_access_policy") {
    my $cfg = new Config::IniFiles( -file => "/srv/policy/mailcop/mailcop.ini" );
    my $p0fsocket = $cfg->val("p0f","socket");
    my $glgenre = $cfg->val("p0f","glgenre");
    my $gldetails = $cfg->val("p0f","gldetails");
    my $rejectgenre = $cfg->val("p0f","rejectgenry");
    my $rejectdetails = $cfg->val("p0f","rejectdetails");
		my $localaddress = $cfg->val("network","localaddress");

		my $src = new Net::IP($attr->{client_address});
		my $dst = new Net::IP($localaddress);
		my $query = pack("L L L N N S S", $QUERY_MAGIC, $QTYPE_FINGERPRINT,  0x12345678, $src->intip(), $dst->intip(), 0, 25);
		my $sock = new IO::Socket::UNIX ( Peer => $p0fsocket,
																			Type => SOCK_STREAM ) or warn "Could not create socket: $!\n";
		print $sock $query;
		my $response = <$sock>;
		close $sock;
		my ($magic, $id, $type, $genre, $detail, $dist, $link, $tos, $fw, $nat, $real, $score, $mflags, $uptime) = unpack ("L L C Z20 Z40 c Z30 Z30 C C C s S N", $response);
		warn "Bad response magic.\n" if $magic != $QUERY_MAGIC;
		warn "P0f did not honor our query.\n" if $type == 1;
		warn "This connection is not (no longer?) in the cache.\n" if $type == 2;


    if (defined $rejectgenre) {
			if ($genre =~ m/$rejectgenre/gi) {
				if (defined $rejectdetails) {
					if ($detail =~ m/$rejectdetails/gi) {
						return "REJECT Bloqueado pelo sistema antispam (CODE 600)";
					}
				} else {
					return "REJECT Bloqueado pelo sistema antispam (CODE 601)";
				}
			}
		}

    if (defined $glgenre) {
			if ($genre =~ m/$glgenre/gi) {
				if (defined $gldetails) {
					if ($detail =~ m/$gldetails/gi) {
						return "GREYLIST Greylist indicado pelo sistema antispam (CODE 602)";
					}
				} else {
					return "GREYLIST Greylist Indicado pelo sistema antispam (CODE 603)";
				}
			}
		}

		return undef;
	}
}

1;
