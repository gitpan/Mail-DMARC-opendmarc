package Mail::DMARC::opendmarc;

use 5.012004;
use strict;
use warnings;
use Carp;
#use Switch;

our $VERSION = '0.07';
our $DEBUG = 0;

require Exporter;


my $_symbols_present = 0;

BEGIN {
    eval {
		require Mail::DMARC::opendmarc::Constants::C::Symbols;
	};
    $_symbols_present = 1 unless $@;

    eval {
		require Mail::DMARC::opendmarc::Constants::C::ForwardDecls;
	};
}

# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.

# This allows declaration	use Mail::DMARC::opendmarc ':all';
# If you do not need this, moving things directly into @EXPORT or @EXPORT_OK
# will save memory.
our %EXPORT_TAGS = ( 'all' => [ qw(
	
) ] );

our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );

our @EXPORT = (
	
                $_symbols_present ? @Mail::DMARC::opendmarc::Constants::C::Symbols::ALL
                                  : (),
);

use AutoLoader;

sub AUTOLOAD {
    # This AUTOLOAD is used to 'autoload' constants from the constant()
    # XS function.

    my $constname;
    our $AUTOLOAD;
    ($constname = $AUTOLOAD) =~ s/.*:://;
    croak "&Mail::DMARC::opendmarc::constant not defined" if $constname eq 'constant'
;
    my ($error, $val) = constant($constname);
    if ($error) { croak $error; }
    {
        no strict 'refs';
		no warnings;
        *$AUTOLOAD = sub { $val };
    }
    goto &$AUTOLOAD;
}
require XSLoader;


require XSLoader;
XSLoader::load('Mail::DMARC::opendmarc', $VERSION);

# Below is stub documentation for your module. You'd better edit it!

=head1 NAME

Mail::DMARC::opendmarc - Perl extension wrapping OpenDMARC's libopendmarc library

=head1 SYNOPSIS

  use Mail::DMARC::opendmarc;

  my $dmarc = Mail::DMARC::opendmarc->new();

  # Get spf and dkim auth results from Authentication-Results (RFC5451) header
  # Store them into the dmarc object
  $dmarc->store_auth_results(
        'mlu.contactlab.it',  # From: domain
        'example.com',  # envelope-from domain
        Mail::DMARC::opendmarc::DMARC_POLICY_SPF_OUTCOME_NONE, # SPF check result
        'neutral', # human-readable SPF check result
        'mlu.contactlab.it', # DKIM domain
        Mail::DMARC::opendmarc::DMARC_POLICY_DKIM_OUTCOME_PASS, # DKIM check result
        'ok' # human-readable DKIM check result
		);
		
  my $result = $dmarc->verify();
  
  # result is a hashref with the following attributes:
  #		'spf_alignment' 
  #		'dkim_alignment'
  #		'policy' => 
  #		'human_policy' 

  print "DMARC check result: " . $result->{human_policy} . "\n";
  
  # Diagnostic output of internal libopendmarc structure via this handy function:
  print $dmarc->dump_policy() if ($debug);
  
  if ($result->{policy} == Mail::DMARC::opendmarc::DMARC_POLICY_PASS)
		...

=head1 DESCRIPTION

A very thin layer wrapping Trusted Domain Project's libopendmarc.
Please refer to http://www.trusteddomain.org/opendmarc.html for more information on opendmarc

Look into the test suite for more usage examples.

=cut

#use vars;
#our $names = {
#	'spf_pass' => DMARC_POLICY_SPF_OUTCOME_PASS,
#	DMARC_POLICY_SPF_OUTCOME_PASS => 'spf_pass'
#};

sub new {
	my $class = shift;
	my $ip_addr = shift || 'localhost';

	my $self = {};
	bless $self, $class;

	# TODO add IPv6 support
	
	$self->{policy_t} = Mail::DMARC::opendmarc::opendmarc_policy_connect_init($ip_addr,4);

	die "Unable to initialize policy object" unless defined($self->{policy_t});
	die "Unable to initialize policy object" unless defined($self->{policy_t});
	
	return $self;
}

sub DESTROY {
	my $self = shift;

	Mail::DMARC::opendmarc::opendmarc_policy_connect_shutdown($self->{policy_t}) if defined($self->{policy});
	warn "Destructor called for $self" if $DEBUG;
}

sub policy_status_to_str {
	my $self = shift;
	my $status = shift;

	return Mail::DMARC::opendmarc::opendmarc_policy_status_to_str($status);
}

sub policy_t {
	my $self = shift;
	return $self->{policy_t};
}

sub dump_policy {
	my $self = shift;
	return Mail::DMARC::opendmarc::opendmarc_policy_to_buf($self->policy_t);
}

sub query {
	my $self = shift;
	my $domain = shift;

	return Mail::DMARC::opendmarc::opendmarc_policy_query_dmarc($self->{policy_t}, $domain);
}

sub parse {
	my $self = shift;
	my $domain = shift;
	my $record = shift;

	return Mail::DMARC::opendmarc::opendmarc_policy_parse_dmarc($self->{policy_t}, $domain, $record);
}

sub store {
	my $self = shift;
	my $record = shift;
	my $domain = shift;
	my $organizational_domain = shift;

	return Mail::DMARC::opendmarc::opendmarc_policy_store_dmarc($self->{policy_t}, $record, $domain, $organizational_domain);
}

sub store_from_domain {
	my $self = shift;
	my $from_domain = shift;

	return Mail::DMARC::opendmarc::opendmarc_policy_store_from_domain($self->{policy_t}, $from_domain);
}

sub store_dkim {
	my $self = shift;
	my $domain = shift;
	my $result = shift;
	my $human_result = shift;

	return Mail::DMARC::opendmarc::opendmarc_policy_store_dkim($self->{policy_t}, $domain, $result, $human_result);
}

sub store_spf {
	my $self = shift;
	my $domain = shift;
	my $result = shift;
	my $origin = shift;
	my $human_result = shift;

	return Mail::DMARC::opendmarc::opendmarc_policy_store_spf($self->{policy_t}, $domain, $result, $origin, $human_result);
}

# TODO
sub store_auth_results_from_header {
	my $self = shift;
	my $rfc5451_header = shift;
	# Implement parsing of RFC5451 Authentication-Results header and feed them to store_auth_results
	return undef;
}

# TODO
sub validate {
	my $self = shift;
	my $from_address = shift;
	my $rfc5451_header = shift;
	# all-in-one
	return undef;
}


sub store_auth_results {
	my $self = shift;
	my $from_domain = shift;
	my $spf_domain = shift;
	my $spf_result = shift;
	my $spf_human_result = shift;
	my $dkim_domain = shift;
	my $dkim_result = shift;
	my $dkim_human_result = shift;

	$self->{valid} = undef;
	$self->{policy_t} = Mail::DMARC::opendmarc::opendmarc_policy_connect_rset($self->{policy_t});
	return Mail::DMARC::opendmarc::DMARC_PARSE_ERROR_NULL_CTX unless defined($self->{policy_t});
	
	$self->{from_domain} = $from_domain;
	
	my $ret = $self->query($from_domain);
	return $ret unless ($ret == DMARC_PARSE_OKAY || $ret == DMARC_POLICY_ABSENT || $ret == DMARC_DNS_ERROR_NO_RECORD);
	
	$self->{spf} = {
		'domain' => $spf_domain,
		'result' => $spf_result,
		'human' => $spf_human_result
	};
	$self->{dkim} = {
		'domain' => $dkim_domain,
		'result' => $dkim_result,
		'human' => $dkim_human_result
	};

	$ret = $self->store_from_domain($from_domain);
	return $ret unless $ret == DMARC_PARSE_OKAY;
	$ret = $self->store_spf($spf_domain, $spf_result, DMARC_POLICY_SPF_ORIGIN_MAILFROM, $spf_human_result);
	return $ret unless $ret == DMARC_PARSE_OKAY;
	$ret = $self->store_dkim($dkim_domain, $dkim_result, $dkim_human_result);
	$self->{valid} = 1 if $ret == DMARC_PARSE_OKAY;
	return $ret;

}

our %POLICY_VALUES = (
		Mail::DMARC::opendmarc::DMARC_POLICY_ABSENT => 'DMARC_POLICY_ABSENT',
		Mail::DMARC::opendmarc::DMARC_POLICY_NONE => 'DMARC_POLICY_NONE',
		Mail::DMARC::opendmarc::DMARC_POLICY_PASS => 'DMARC_POLICY_PASS',
		Mail::DMARC::opendmarc::DMARC_POLICY_QUARANTINE => 'DMARC_POLICY_QUARANTINE',
		Mail::DMARC::opendmarc::DMARC_POLICY_REJECT => 'DMARC_POLICY_REJECT'
);
our %SPF_ALIGNMENT_VALUES = (
		0 => 'N/A',
		Mail::DMARC::opendmarc::DMARC_POLICY_SPF_ALIGNMENT_PASS => 'DMARC_POLICY_SPF_ALIGNMENT_PASS',
		Mail::DMARC::opendmarc::DMARC_POLICY_SPF_ALIGNMENT_FAIL => 'DMARC_POLICY_SPF_ALIGNMENT_FAIL'
);
our %DKIM_ALIGNMENT_VALUES = (
		0 => 'N/A',
		Mail::DMARC::opendmarc::DMARC_POLICY_DKIM_ALIGNMENT_PASS => 'DMARC_POLICY_DKIM_ALIGNMENT_PASS',	
		Mail::DMARC::opendmarc::DMARC_POLICY_DKIM_ALIGNMENT_FAIL => 'DMARC_POLICY_DKIM_ALIGNMENT_FAIL'	
);
	

sub verify {
	my $self = shift;

	return undef unless $self->{valid};	
	my $result = {
		'spf_alignment' => undef,
		'dkim_alignment' => undef,
		'policy' => undef,
		'human_policy' => undef
	};

	my $ret = Mail::DMARC::opendmarc::opendmarc_get_policy_to_enforce($self->{policy_t});
	return undef unless (exists $POLICY_VALUES{$ret});
	$result->{human_policy} = $self->human_policy($ret);
	$result->{policy} = $ret;
	my $sa = 0;
	my $da = 0;
	$ret = Mail::DMARC::opendmarc::opendmarc_policy_fetch_alignment($self->{policy_t}, $da, $sa);
	return undef unless $ret == DMARC_PARSE_OKAY;
	$result->{spf_alignment} = $sa;
	$result->{dkim_alignment} = $da;

	return $result;
	
}

sub human_policy {
	my $self = shift;
	my $val = shift;
	return $POLICY_VALUES{$val} if (exists $POLICY_VALUES{$val});
	return 'Invalid';
}

sub human_spf_alignment {
	my $self = shift;
	my $val = shift;
	return $SPF_ALIGNMENT_VALUES{$val} if (exists $SPF_ALIGNMENT_VALUES{$val});
	return 'Invalid';
}

sub human_dkim_alignment {
	my $self = shift;
	my $val = shift;
	return $DKIM_ALIGNMENT_VALUES{$val} if (exists $DKIM_ALIGNMENT_VALUES{$val});
	return 'Invalid';
}



=head2 get_policy_to_enforce()

=begin text

/**************************************************************************
** OPENDMARC_GET_POLICY_TO_ENFORCE -- What to do with this message. i.e. allow
**				possible delivery, quarantine, or reject.
**	Parameters:
**		pctx	-- A Policy context
**	Returns:
**		DMARC_PARSE_ERROR_NULL_CTX	-- pctx == NULL
**		DMARC_POLICY_ABSENT		-- No DMARC record found
**		DMARC_FROM_DOMAIN_ABSENT	-- No From: domain
**		DMARC_POLICY_NONE		-- Accept if other policy allows
**		DMARC_POLICY_REJECT		-- Policy advises to reject the message
**		DMARC_POLICY_QUARANTINE		-- Policy advises to quarantine the message
**		DMARC_POLICY_PASS		-- Policy advises to accept the message
**	Side Effects:
**		Checks for domain alignment.
***************************************************************************/

=end text

=cut

sub get_policy_to_enforce {
	my $self = shift;

	return Mail::DMARC::opendmarc::opendmarc_get_policy_to_enforce($self->{policy_t});
}

sub get_policy {
	my $self = shift;

	my $result = {};

	$result->{policy} = $self->get_policy_to_enforce();
	my $i = 0;
	my $ret = Mail::DMARC::opendmarc::opendmarc_policy_fetch_p($self->{policy_t}, $i);
	$result->{p} = ($ret == Mail::DMARC::opendmarc::DMARC_PARSE_OKAY && $i > 0 ? chr($i) : undef);
	$ret = Mail::DMARC::opendmarc::opendmarc_policy_fetch_sp($self->{policy_t}, $i);
	$result->{sp} = ($ret == Mail::DMARC::opendmarc::DMARC_PARSE_OKAY && $i > 0 ? chr($i) : undef);
	$ret = Mail::DMARC::opendmarc::opendmarc_policy_fetch_pct($self->{policy_t}, $i);
	$result->{pct} = $i;
	$ret = Mail::DMARC::opendmarc::opendmarc_policy_fetch_adkim($self->{policy_t}, $i);
	$result->{adkim} = ($ret == Mail::DMARC::opendmarc::DMARC_PARSE_OKAY && $i > 0 ? chr($i) : undef);
	$ret = Mail::DMARC::opendmarc::opendmarc_policy_fetch_aspf($self->{policy_t}, $i);
	$result->{aspf} = ($ret == Mail::DMARC::opendmarc::DMARC_PARSE_OKAY && $i > 0 ? chr($i) : undef);
	my $k = 0;
	$ret = Mail::DMARC::opendmarc::opendmarc_policy_fetch_alignment($self->{policy_t}, $i, $k);
	$result->{spf_alignment} = $i;
	$result->{dkim_alignment} = $k;

	return $result;
}

1;
__END__

=head1 SEE ALSO

About DMARC: http://www.opendmarc.org

Abount opendmarc and libopendmarc: http://www.trusteddomain.org/opendmarc.html

=head1 AUTHOR

Davide Migliavacca, E<lt>shari@cpan.orgE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2012 by Davide Migliavacca and ContactLab

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.14.2 or,
at your option, any later version of Perl 5 you may have available.

This license is not covering the required libopendmarc package from
http://www.trusteddomain.org/opendmarc.html. Please refer to appropriate
license details for the package.

Please try to have the appropriate amount of fun.


=cut

