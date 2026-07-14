package Net::Firewall::BlockerHelper::backends::azure;

use 5.006;
use strict;
use warnings;
use base 'Error::Helper';
use Regexp::IPv4 qw($IPv4_re);
use Regexp::IPv6 qw($IPv6_re);

=head1 NAME

Net::Firewall::BlockerHelper::backends::azure - Azure NSG backend via the az CLI.

=head1 VERSION

Version 0.1.0

=cut

our $VERSION = '0.1.0';

=head1 SYNOPSIS

    use Net::Firewall::BlockerHelper;

    my $fw_helper = Net::Firewall::BlockerHelper->new(
        backend => 'azure',
        name    => 'ssh',
        options => {
            resource_group => 'my-rg',
            nsg            => 'my-nsg',
            rule           => 'blocklist',
        },
    );

    $fw_helper->init_backend;
    $fw_helper->ban( ban => '1.2.3.4' );
    $fw_helper->unban( ban => '1.2.3.4' );

=head1 DESCRIPTION

Blocks IPs on Azure by maintaining the C<--source-address-prefixes> of a
single deny rule in a Network Security Group, using the C<az> CLI. The full
set of currently banned IPs is rendered into the rule on every change, so
ban/unban are idempotent. Both IPv4 and IPv6 share the one rule.

This backend manages only the rule's source prefixes. The NSG, the inbound
deny security rule, and the NSG's association with the subnets or NICs to be
protected must already exist.

Requires the C<az> CLI in the C<PATH>, logged in with rights to update the
rule.

=head1 METHODS

=head2 new

    - options :: Backend specific options. See below.
    - name :: Required by Net::Firewall::BlockerHelper, otherwise unused.

The options hash accepts the following.

    - az_cmd :: Path to the az binary.
        - Default :: az

    - resource_group :: Resource group of the NSG. Required.
        - Default :: undef

    - nsg :: Network Security Group name. Required.
        - Default :: undef

    - rule :: Security rule whose source prefixes are managed. Required.
        - Default :: undef

    - subscription :: Optional subscription; appended as --subscription when set.
        - Default :: undef

All errors are considered fatal, meaning if new fails it will die.

=cut

sub new {
	my ( $blank, %opts ) = @_;

	my $self = {
		perror        => undef,
		error         => undef,
		errorLine     => undef,
		errorFilename => undef,
		errorString   => "",
		errorExtra    => {
			all_errors_fatal => 1,
			# all_fatal is what Error::Helper 2.1.0 actually checks; all_errors_fatal
			# is kept for the name documented in its POD
			all_fatal        => 1,
			flags            => {
				1  => 'notInited',
				8  => 'optionsNotHash',
				9  => 'noBanItem',
				10 => 'banItemNotIP',
				12 => 'backendInitError',
				13 => 'banFailed',
				14 => 'unbanFailed',
				15 => 'listFailed',
				16 => 'reInitFailed',
				17 => 'teardownFailed',
				18 => 'alreadyInited',
				24 => 'checkFailed',
				25 => 'flushFailed',
				30 => 'resourceGroupNotDefined',
				31 => 'nsgNotDefined',
				32 => 'ruleNotDefined',
			},
			fatal_flags      => {},
			perror_not_fatal => 0,
		},
		options      => {},
		ports        => [],
		protocols    => [],
		testing      => undef,
		test_data    => undef,
		prefix       => 'kur',
		name         => undef,
		frontend_obj => undef,
		inited       => 0,
		banned       => {},
	};
	bless $self;

	if ( defined( $opts{testing} ) ) {
		$self->{testing} = $opts{testing};
	}
	if ( defined( $opts{frontend_obj} ) ) {
		$self->{frontend_obj} = $opts{frontend_obj};
	}
	if ( defined( $opts{name} ) ) {
		$self->{name} = $opts{name};
	}

	if ( defined( $opts{options} ) && ref( $opts{options} ) ne 'HASH' ) {
		$self->{perror}      = 1;
		$self->{error}       = 8;
		$self->{errorString} = 'ref for options is "' . ref( $opts{options} ) . '" and not HASH';
		$self->warn;
	} elsif ( defined( $opts{options} ) ) {
		$self->{options} = $opts{options};
	}

	if ( !defined( $self->{options}{resource_group} ) || $self->{options}{resource_group} eq '' ) {
		$self->{perror}      = 1;
		$self->{error}       = 30;
		$self->{errorString} = 'the option resource_group is undef or blank';
		$self->warn;
	}
	if ( !defined( $self->{options}{nsg} ) || $self->{options}{nsg} eq '' ) {
		$self->{perror}      = 1;
		$self->{error}       = 31;
		$self->{errorString} = 'the option nsg is undef or blank';
		$self->warn;
	}
	if ( !defined( $self->{options}{rule} ) || $self->{options}{rule} eq '' ) {
		$self->{perror}      = 1;
		$self->{error}       = 32;
		$self->{errorString} = 'the option rule is undef or blank';
		$self->warn;
	}

	$self->{options}{az_cmd} = 'az' if ( !defined( $self->{options}{az_cmd} ) );

	return $self;
} ## end sub new

=head2 _suffix

Internal helper. Returns the trailing --subscription argument when configured,
or an empty string.

=cut

sub _suffix {
	my ($self) = @_;

	if ( defined( $self->{options}{subscription} ) && $self->{options}{subscription} ne '' ) {
		return ' --subscription ' . $self->{options}{subscription};
	}
	return '';
} ## end sub _suffix

=head2 _base

Internal helper. Returns the shared --resource-group/--nsg-name/--name
arguments identifying the rule.

=cut

sub _base {
	my ($self) = @_;

	return
		  ' --resource-group '
		. $self->{options}{resource_group}
		. ' --nsg-name '
		. $self->{options}{nsg}
		. ' --name '
		. $self->{options}{rule};
} ## end sub _base

=head2 _prefixes

Internal helper. Returns the current banned IPs, sorted, each as a CIDR
(/32 for IPv4, /128 for IPv6), joined with single spaces.

=cut

sub _prefixes {
	my ($self) = @_;

	my @prefixes;
	foreach my $ip ( sort( keys( %{ $self->{banned} } ) ) ) {
		push( @prefixes, $ip . ( ( $ip =~ /\A$IPv4_re\z/ ) ? '/32' : '/128' ) );
	}

	return join( ' ', @prefixes );
} ## end sub _prefixes

=head2 _update_command

Internal helper. Returns the az command that sets the rule's source prefixes
to the currently banned set.

=cut

sub _update_command {
	my ($self) = @_;

	return
		  $self->{options}{az_cmd}
		. ' network nsg rule update'
		. $self->_base
		. ' --source-address-prefixes '
		. $self->_prefixes
		. $self->_suffix;
} ## end sub _update_command

=head2 _show_command

Internal helper. Returns the az command used to verify the rule exists.

=cut

sub _show_command {
	my ($self) = @_;

	return $self->{options}{az_cmd} . ' network nsg rule show' . $self->_base . $self->_suffix;
}

=head2 _run

Internal helper. Runs a command unless testing, raising the passed error flag
on a non-zero exit.

=cut

sub _run {
	my ( $self, $command, $error_flag ) = @_;

	my $output = `$command 2>&1`;
	if ( $? != 0 ) {
		$self->{error}       = $error_flag;
		$self->{errorString} = 'command "' . $command . '" failed... ' . $output;
		$self->warn;
	}

	return;
} ## end sub _run

=head2 init

Initiates the backend, verifying the rule exists.

=cut

sub init {
	my ( $self, %opts ) = @_;

	$self->errorblank;

	if ( $self->{inited} ) {
		$self->{error}       = 18;
		$self->{errorString} = 'backend has already been inited';
		$self->warn;
	}

	my @commands = ( $self->_show_command );

	if ( $self->{testing} ) {
		$self->{frontend_obj}->{test_data} = \@commands;
	} else {
		$self->_run( $commands[0], 12 );
	}

	$self->{inited} = 1;
} ## end sub init

=head2 ban

    $fw_helper->ban( ban => $ip );

=cut

sub ban {
	my ( $self, %opts ) = @_;

	$self->errorblank;

	if ( !$self->{inited} ) {
		$self->{error}       = 1;
		$self->{errorString} = 'backend has not been inited';
		$self->warn;
		return;
	}

	if ( !defined( $opts{ban} ) ) {
		$self->{error}       = 9;
		$self->{errorString} = 'Nothing specified for the value ban';
		$self->warn;
		return;
	} elsif ( ref( $opts{ban} ) ne '' ) {
		$self->{error}       = 10;
		$self->{errorString} = 'Bad ref type for ban... ref is "' . ref( $opts{ban} ) . '"';
		$self->warn;
		return;
	} elsif ( $opts{ban} !~ /\A$IPv4_re\z/
		&& $opts{ban} !~ /\A$IPv6_re\z/ )
	{
		$self->{error}       = 10;
		$self->{errorString} = 'ban item,"' . $opts{ban} . '", does not appear to be a IPv4 or IPv6 IP';
		$self->warn;
		return;
	}

	# lowercase so the same IPv6 IP in differing cases can't result in duplicate entries
	$opts{ban} = lc( $opts{ban} );

	if ( $self->{banned}{ $opts{ban} } ) {
		if ( $self->{testing} ) {
			$self->{frontend_obj}->{test_data} = 'already banned';
		}
		return;
	}

	$self->{banned}{ $opts{ban} } = 1;

	my $command = $self->_update_command;
	if ( $self->{testing} ) {
		$self->{frontend_obj}->{test_data} = $command;
	} else {
		$self->_run( $command, 13 );
	}
} ## end sub ban

=head2 unban

    $fw_helper->unban( ban => $ip );

=cut

sub unban {
	my ( $self, %opts ) = @_;

	$self->errorblank;

	if ( !$self->{inited} ) {
		$self->{error}       = 1;
		$self->{errorString} = 'backend has not been inited';
		$self->warn;
		return;
	}

	if ( !defined( $opts{ban} ) ) {
		$self->{error}       = 9;
		$self->{errorString} = 'Nothing specified for the value ban';
		$self->warn;
		return;
	} elsif ( ref( $opts{ban} ) ne '' ) {
		$self->{error}       = 10;
		$self->{errorString} = 'Bad ref type for ban... ref is "' . ref( $opts{ban} ) . '"';
		$self->warn;
		return;
	} elsif ( $opts{ban} !~ /\A$IPv4_re\z/
		&& $opts{ban} !~ /\A$IPv6_re\z/ )
	{
		$self->{error}       = 10;
		$self->{errorString} = 'ban item,"' . $opts{ban} . '", does not appear to be a IPv4 or IPv6 IP';
		$self->warn;
		return;
	}

	# lowercase so the same IPv6 IP in differing cases can't result in duplicate entries
	$opts{ban} = lc( $opts{ban} );

	if ( !$self->{banned}{ $opts{ban} } ) {
		if ( $self->{testing} ) {
			$self->{frontend_obj}->{test_data} = 'not banned';
		}
		return;
	}

	delete( $self->{banned}{ $opts{ban} } );

	my $command = $self->_update_command;
	if ( $self->{testing} ) {
		$self->{frontend_obj}->{test_data} = $command;
	} else {
		$self->_run( $command, 14 );
	}
} ## end sub unban

=head2 list

    my @banned = $fw_helper->list;

=cut

sub list {
	my ( $self, %opts ) = @_;

	$self->errorblank;

	if ( $self->{testing} ) {
		$self->{frontend_obj}->{test_data} = 'list';
	}

	return keys( %{ $self->{banned} } );
}

=head2 re_init

Re-applies the full banned set to the rule.

=cut

sub re_init {
	my ( $self, %opts ) = @_;

	$self->errorblank;

	if ( !$self->{inited} ) {
		$self->{error}       = 1;
		$self->{errorString} = 'backend has not been inited';
		$self->warn;
		return;
	}

	{
		local $@;
		eval { $self->teardown; };
	}
	$self->init;

	my $command = $self->_update_command;
	if ( $self->{testing} ) {
		$self->{frontend_obj}->{test_data} = [$command];
	} else {
		$self->_run( $command, 13 );
	}

	$self->{inited} = 1;
} ## end sub re_init

=head2 teardown

Empties the rule's source prefixes. The internal ban list is kept so a
following re_init restores them.

=cut

sub teardown {
	my ( $self, %opts ) = @_;

	$self->errorblank;

	$self->{inited} = 0;

	# render the update with an empty ban set without disturbing the retained list
	my %saved = %{ $self->{banned} };
	$self->{banned} = {};
	my $command = $self->_update_command;
	$self->{banned} = \%saved;

	if ( $self->{testing} ) {
		$self->{frontend_obj}->{test_data} = [$command];
	} else {
		$self->_run( $command, 17 );
	}
} ## end sub teardown

=head2 stop

Alias for L</teardown>.

=cut

sub stop {
	my ( $self, %opts ) = @_;

	return $self->teardown(%opts);
}

=head2 check

Verifies the rule still exists via a show. Zero exit is healthy.

=cut

sub check {
	my ( $self, %opts ) = @_;

	$self->errorblank;

	my $command = $self->_show_command;

	if ( $self->{testing} ) {
		$self->{frontend_obj}->{test_data} = [$command];
		return 1;
	}

	my $output = `$command 2>&1`;
	return $? == 0 ? 1 : 0;
} ## end sub check

=head2 flush

Empties the rule's source prefixes and clears the ban list.

=cut

sub flush {
	my ( $self, %opts ) = @_;

	$self->errorblank;

	if ( !$self->{inited} ) {
		$self->{error}       = 1;
		$self->{errorString} = 'backend has not been inited';
		$self->warn;
		return;
	}

	$self->{banned} = {};

	my $command = $self->_update_command;
	if ( $self->{testing} ) {
		$self->{frontend_obj}->{test_data} = [$command];
	} else {
		$self->_run( $command, 25 );
	}
} ## end sub flush

=head1 ERROR CODES / FLAGS

    1  notInited
    8  optionsNotHash
    9  noBanItem
    10 banItemNotIP
    12 backendInitError
    13 banFailed
    14 unbanFailed
    15 listFailed
    16 reInitFailed
    17 teardownFailed
    18 alreadyInited
    24 checkFailed
    25 flushFailed
    30 resourceGroupNotDefined
    31 nsgNotDefined
    32 ruleNotDefined

=head1 AUTHOR

Zane C. Bowers-Hadley, C<< <vvelox at vvelox.ent> >>

=head1 LICENSE AND COPYRIGHT

This software is Copyright (c) 2023 by Zane C. Bowers-Hadley.

This is free software, licensed under:

  The GNU Lesser General Public License, Version 2.1, February 1999

=cut

1;    # End of Net::Firewall::BlockerHelper::backends::azure
