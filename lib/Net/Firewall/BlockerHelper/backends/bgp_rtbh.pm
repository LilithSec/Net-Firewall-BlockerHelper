package Net::Firewall::BlockerHelper::backends::bgp_rtbh;

use 5.006;
use strict;
use warnings;
use base 'Error::Helper';
use Regexp::IPv4 qw($IPv4_re);
use Regexp::IPv6 qw($IPv6_re);

=head1 NAME

Net::Firewall::BlockerHelper::backends::bgp_rtbh - BGP Remote Triggered Black Hole backend (via ExaBGP).

=head1 VERSION

Version 0.1.0

=cut

our $VERSION = '0.1.0';

=head1 SYNOPSIS

    use Net::Firewall::BlockerHelper;

    my $fw_helper = Net::Firewall::BlockerHelper->new(
        backend => 'bgp_rtbh',
        name    => 'rtbh',
        options => {
            next_hop  => '192.0.2.1',
            community => '65535:666',
        },
    );

    $fw_helper->init_backend;
    $fw_helper->ban( ban => '1.2.3.4' );
    $fw_helper->unban( ban => '1.2.3.4' );
    $fw_helper->teardown;

=head1 DESCRIPTION

Blocks IPs with BGP Remote Triggered Black Holing. Rather than filtering
locally, each banned IP is announced to the network as a host route
(C<< /32 >> for IPv4, C<< /128 >> for IPv6) carrying the well-known
BLACKHOLE community (C<65535:666>, RFC 7999). Upstream routers that honor it
then drop the traffic, moving the drop off this host and, with a transit
provider that accepts blackhole announcements, off the local link entirely.

Announcements are driven through one of two BGP daemons, selected with the
C<driver> option: ExaBGP's C<exabgpcli> (the default) or C<gobgp>. Either
talks to a running daemon that holds the BGP session(s) to the routers; this
backend does not manage that session, it only announces and withdraws routes.

Whether the announced prefix blackholes the traffic's B<source> or
B<destination> depends on the receiving router: destination based RTBH drops
traffic toward the prefix, while source based RTBH (loose uRPF plus the
blackhole community) drops traffic B<from> it. As this tool bans attacker
source addresses, a source based RTBH setup is the usual pairing.

Requires C<exabgpcli> in the C<PATH> and a running, configured C<exabgp>.

=head1 METHODS

=head2 new

    - options :: A hash of options. See below.
    - name :: Required by Net::Firewall::BlockerHelper, otherwise unused.

The options hash accepts the following.

    - driver :: Which BGP daemon to drive, 'exabgp' or 'gobgp'.
        - Default :: exabgp

    - exabgpcli_cmd :: Path to the exabgpcli binary (driver 'exabgp').
        - Default :: exabgpcli

    - gobgp_cmd :: Path to the gobgp binary (driver 'gobgp').
        - Default :: gobgp

    - community :: BGP community attached to every announced route. The
            default is the RFC 7999 well-known BLACKHOLE community.
        - Default :: 65535:666

    - next_hop :: Next hop for IPv4 announcements. On the receiving router
            this is what maps to the discard interface.
        - Default :: 192.0.2.1

    - next_hop6 :: Next hop for IPv6 announcements.
        - Default :: 100::1

    - mask4 :: Prefix length used for IPv4 announcements.
        - Default :: 32

    - mask6 :: Prefix length used for IPv6 announcements.
        - Default :: 128

    - extra :: Optional extra attributes appended verbatim to each announce.
            The syntax is driver specific (exabgp 'local-preference 50' vs
            gobgp 'local-pref 50').
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
				20 => 'driverInvalid',
				24 => 'checkFailed',
				25 => 'flushFailed',
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
	if ( defined( $opts{prefix} ) ) {
		$self->{prefix} = $opts{prefix};
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

	# defaults
	$self->{options}{driver}        = 'exabgp'    if ( !defined( $self->{options}{driver} ) );
	$self->{options}{exabgpcli_cmd} = 'exabgpcli' if ( !defined( $self->{options}{exabgpcli_cmd} ) );
	$self->{options}{gobgp_cmd}     = 'gobgp'     if ( !defined( $self->{options}{gobgp_cmd} ) );
	$self->{options}{community}     = '65535:666' if ( !defined( $self->{options}{community} ) );
	$self->{options}{next_hop}      = '192.0.2.1' if ( !defined( $self->{options}{next_hop} ) );
	$self->{options}{next_hop6}     = '100::1'    if ( !defined( $self->{options}{next_hop6} ) );
	$self->{options}{mask4}         = 32          if ( !defined( $self->{options}{mask4} ) );
	$self->{options}{mask6}         = 128         if ( !defined( $self->{options}{mask6} ) );

	if ( $self->{options}{driver} ne 'exabgp' && $self->{options}{driver} ne 'gobgp' ) {
		$self->{perror}      = 1;
		$self->{error}       = 20;
		$self->{errorString} = 'driver is "' . $self->{options}{driver} . '" and not "exabgp" or "gobgp"';
		$self->warn;
	}

	return $self;
} ## end sub new

=head2 _route_command

Internal helper. Builds the announce/withdraw command for the given verb
('announce' or 'withdraw') and IP, in the syntax of the configured driver
(exabgp via C<exabgpcli> or C<gobgp>), picking the family-appropriate next
hop and prefix length and attaching the blackhole community.

=cut

sub _route_command {
	my ( $self, $verb, $ip ) = @_;

	my $is_v4 = ( $ip =~ /\A$IPv4_re\z/ ) ? 1 : 0;
	my $mask  = $is_v4 ? $self->{options}{mask4}    : $self->{options}{mask6};
	my $nh    = $is_v4 ? $self->{options}{next_hop} : $self->{options}{next_hop6};
	my $extra = ( defined( $self->{options}{extra} ) && $self->{options}{extra} ne '' ) ? $self->{options}{extra} : '';

	if ( $self->{options}{driver} eq 'gobgp' ) {
		# gobgp global rib add|del <prefix> [nexthop ..] [community ..] -a <afi>
		my $afi = $is_v4 ? 'ipv4' : 'ipv6';
		my $op  = ( $verb eq 'announce' ) ? 'add' : 'del';

		my $cmd = $self->{options}{gobgp_cmd} . ' global rib ' . $op . ' ' . $ip . '/' . $mask;

		# a withdrawal matches on prefix alone; attributes are only needed to add
		if ( $op eq 'add' ) {
			$cmd .= ' nexthop ' . $nh . ' community ' . $self->{options}{community};
			$cmd .= ' ' . $extra if ( $extra ne '' );
		}
		$cmd .= ' -a ' . $afi;

		return $cmd;
	} ## end if ( $self->{options}{driver...})

	# exabgp: exabgpcli 'announce|withdraw route <prefix> next-hop .. community [..]'
	my $route
		= $verb
		. ' route '
		. $ip . '/'
		. $mask
		. ' next-hop '
		. $nh
		. ' community [' . $self->{options}{community} . ']';
	$route .= ' ' . $extra if ( $extra ne '' );

	return $self->{options}{exabgpcli_cmd} . ' ' . $route;
} ## end sub _route_command

=head2 _check_command

Internal helper. Returns the driver-appropriate command used by L</check> to
confirm the BGP daemon is reachable.

=cut

sub _check_command {
	my ($self) = @_;

	if ( $self->{options}{driver} eq 'gobgp' ) {
		return $self->{options}{gobgp_cmd} . ' neighbor';
	}

	return $self->{options}{exabgpcli_cmd} . ' show neighbor summary';
} ## end sub _check_command

=head2 init

Initiates the backend. The BGP session is owned by the running exabgp, so
there is nothing to set up; this only flips the inited flag.

=cut

sub init {
	my ( $self, %opts ) = @_;

	$self->errorblank;

	if ( $self->{inited} ) {
		$self->{error}       = 18;
		$self->{errorString} = 'backend has already been inited';
		$self->warn;
	}

	if ( $self->{testing} ) {
		$self->{frontend_obj}->{test_data} = [];
	}

	$self->{inited} = 1;
} ## end sub init

=head2 ban

Announces a blackhole route for the IP.

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

	my $command = $self->_route_command( 'announce', $opts{ban} );

	if ( $self->{testing} ) {
		$self->{frontend_obj}->{test_data} = $command;
	} else {
		my $output = `$command 2>&1`;
		if ( $? != 0 ) {
			$self->{error} = 13;
			$self->{errorString}
				= 'ban failed. non-zero exit code for the command... "' . $command . '"... output... ' . $output;
			$self->warn;
		}
	}

	$self->{banned}{ $opts{ban} } = 1;
} ## end sub ban

=head2 unban

Withdraws the blackhole route for the IP.

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

	my $command = $self->_route_command( 'withdraw', $opts{ban} );

	if ( $self->{testing} ) {
		$self->{frontend_obj}->{test_data} = $command;
	} else {
		my $output = `$command 2>&1`;
		if ( $? != 0 ) {
			$self->{error} = 14;
			$self->{errorString}
				= 'unban failed. non-zero exit code for the command... "' . $command . '"... output... ' . $output;
			$self->warn;
		}
	}

	delete( $self->{banned}{ $opts{ban} } );
} ## end sub unban

=head2 list

List banned IPs.

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

Re-announces every retained blackhole route. exabgp does not persist state
across restarts, so this is how the announcements are restored after the
daemon is bounced.

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

	# teardown is best effort; a session that already dropped the routes is
	# exactly what re_init is meant to recover from
	{
		local $@;
		eval { $self->teardown; };
	}
	$self->init;

	my @re_init_test_data;
	foreach my $item ( keys( %{ $self->{banned} } ) ) {
		my $command = $self->_route_command( 'announce', $item );
		if ( $self->{testing} ) {
			push( @re_init_test_data, $command );
		} else {
			my $output = `$command 2>&1`;
			if ( $? != 0 ) {
				$self->{error} = 13;
				$self->{errorString}
					= 'ban failed. non-zero exit code for the command... "' . $command . '"... output... ' . $output;
				$self->warn;
			}
		}
	} ## end foreach my $item ( keys( %{ ...}))

	if ( $self->{testing} ) {
		$self->{frontend_obj}->{test_data} = \@re_init_test_data;
	}

	$self->{inited} = 1;
} ## end sub re_init

=head2 teardown

Withdraws every announced blackhole route.

=cut

sub teardown {
	my ( $self, %opts ) = @_;

	$self->errorblank;

	$self->{inited} = 0;

	my @commands;
	foreach my $item ( keys( %{ $self->{banned} } ) ) {
		push( @commands, $self->_route_command( 'withdraw', $item ) );
	}

	if ( $self->{testing} ) {
		$self->{frontend_obj}->{test_data} = \@commands;
	} else {
		foreach my $item (@commands) {
			my $output = `$item 2>&1`;
			if ( $? != 0 ) {
				$self->{error} = 17;
				$self->{errorString}
					= 'teardown failed. non-zero exit code for the command... "' . $item . '"... output... ' . $output;
				$self->warn;
			}
		}
	} ## end else [ if ( $self->{testing} ) ]
} ## end sub teardown

=head2 stop

Alias for L</teardown>.

=cut

sub stop {
	my ( $self, %opts ) = @_;

	return $self->teardown(%opts);
}

=head2 check

Runs the driver's neighbor summary command (C<exabgpcli show neighbor
summary> or C<gobgp neighbor>) and treats a zero exit as healthy. This
confirms the BGP daemon is reachable so the announcements are live.

=cut

sub check {
	my ( $self, %opts ) = @_;

	$self->errorblank;

	my $command = $self->_check_command;

	if ( $self->{testing} ) {
		$self->{frontend_obj}->{test_data} = $command;
		return 1;
	}

	my $output = `$command 2>&1`;
	return $? == 0 ? 1 : 0;
} ## end sub check

=head2 flush

Withdraws all announced routes at once and clears the ban list.

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

	my @commands;
	foreach my $item ( keys( %{ $self->{banned} } ) ) {
		push( @commands, $self->_route_command( 'withdraw', $item ) );
	}

	if ( $self->{testing} ) {
		$self->{frontend_obj}->{test_data} = \@commands;
	} else {
		foreach my $item (@commands) {
			my $output = `$item 2>&1`;
			if ( $? != 0 ) {
				$self->{error} = 25;
				$self->{errorString}
					= 'flush failed. non-zero exit code for the command... "' . $item . '"... output... ' . $output;
				$self->warn;
			}
		}
	} ## end else [ if ( $self->{testing} ) ]

	$self->{banned} = {};
} ## end sub flush

=head1 ERROR CODES / FLAGS

=head2 1, notInited

Backend has not been initted yet.

=head2 8, optionsNotHash

The item passed to new for options is not a hash.

=head2 9, noBanItem

No IP specified to ban.

=head2 10, banItemNotIP

The item to ban is not an IP.

=head2 12, backendInitError

Failed to init the backend.

=head2 13, banFailed

Failed to ban the item.

=head2 14, unbanFailed

Failed to unban the item.

=head2 15, listFailed

Failed to get a list of bans.

=head2 16, reInitFailed

Failed to re_init the backend.

=head2 17, teardownFailed

Failed to teardown the backend.

=head2 18, alreadyInited

Backend has already been initiated.

=head2 20, driverInvalid

The driver option is not one of 'exabgp' or 'gobgp'.

=head2 24, checkFailed

The backend check raised an error.

=head2 25, flushFailed

Failed to flush the bans.

=head1 AUTHOR

Zane C. Bowers-Hadley, C<< <vvelox at vvelox.ent> >>

=head1 LICENSE AND COPYRIGHT

This software is Copyright (c) 2023 by Zane C. Bowers-Hadley.

This is free software, licensed under:

  The GNU Lesser General Public License, Version 2.1, February 1999

=cut

1;    # End of Net::Firewall::BlockerHelper::backends::bgp_rtbh
