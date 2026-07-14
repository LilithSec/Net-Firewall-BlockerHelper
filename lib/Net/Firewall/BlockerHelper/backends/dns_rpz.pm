package Net::Firewall::BlockerHelper::backends::dns_rpz;

use 5.006;
use strict;
use warnings;
use base 'Error::Helper';
use Regexp::IPv4 qw($IPv4_re);
use Regexp::IPv6 qw($IPv6_re);

=head1 NAME

Net::Firewall::BlockerHelper::backends::dns_rpz - DNS RPZ blocklist backend via nsupdate.

=head1 VERSION

Version 0.1.0

=cut

our $VERSION = '0.1.0';

=head1 SYNOPSIS

    use Net::Firewall::BlockerHelper;

    my $fw_helper = Net::Firewall::BlockerHelper->new(
        backend => 'dns_rpz',
        name    => 'resolver',
        options => {
            zone    => 'rpz.example.org',
            keyfile => '/etc/rpz.key',
        },
    );

    $fw_helper->init_backend;
    $fw_helper->ban( ban => '1.2.3.4' );
    $fw_helper->unban( ban => '1.2.3.4' );

=head1 DESCRIPTION

Blocks IPs at the DNS layer using a BIND Response Policy Zone (RPZ). By
default the C<rpz-client-ip> trigger is used, so a banned IP is prevented from
resolving anything through the resolver (the policy action is NXDOMAIN via a
C<CNAME .> record). Set the C<trigger> option to C<ip> to instead use the
C<rpz-ip> trigger, which rewrites answers that contain the banned IP.

Records are added and removed with L<nsupdate(1)> (the DNS update protocol,
TSIG authenticated), so this backend runs the nsupdate command rather than
speaking HTTP. The RPZ zone must already exist and be referenced from the
resolver's C<response-policy> configuration.

The owner name is the RPZ IP format: for IPv4 C<1.2.3.4> it is
C<< 32.4.3.2.1.rpz-client-ip.<zone> >>, and for IPv6 the eight groups are
reversed with the longest zero run replaced by C<zz>, prefixed with the
C<128> length.

Blocking is per IP; ports and protocols are not supported and specifying
either is an error.

=head1 METHODS

=head2 new

    - options :: Backend specific options. See below.
    - name :: Required by Net::Firewall::BlockerHelper, otherwise unused.

The options hash accepts the following. zone and keyfile are required.

    - zone :: The RPZ zone name.
        - Default :: undef

    - keyfile :: Full path to the TSIG key file authenticating to the server.
        - Default :: undef

    - trigger :: 'client-ip' (block the querying client) or 'ip' (rewrite
            answers containing the IP).
        - Default :: client-ip

    - server :: Optional server to send the updates to; adds a server line.
        - Default :: undef

    - ttl :: TTL in seconds for the created records.
        - Default :: 60

    - nsupdate :: The nsupdate command to use.
        - Default :: nsupdate

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
				20 => 'triggerInvalid',
				23 => 'initFailed',
				24 => 'checkFailed',
				25 => 'flushFailed',
				26 => 'portsNotSupported',
				27 => 'protocolsNotSupported',
				30 => 'zoneInvalid',
				31 => 'keyfileInvalid',
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

	if ( defined( $opts{ports} ) && ref( $opts{ports} ) eq 'ARRAY' && defined( $opts{ports}[0] ) ) {
		$self->{perror}      = 1;
		$self->{error}       = 26;
		$self->{errorString} = 'the dns_rpz backend blocks whole IPs and does not support ports';
		$self->warn;
	}
	if ( defined( $opts{protocols} ) && ref( $opts{protocols} ) eq 'ARRAY' && defined( $opts{protocols}[0] ) ) {
		$self->{perror}      = 1;
		$self->{error}       = 27;
		$self->{errorString} = 'the dns_rpz backend blocks whole IPs and does not support protocols';
		$self->warn;
	}

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

	if ( !defined( $self->{options}{zone} ) || $self->{options}{zone} !~ /^[a-zA-Z0-9.\-]+$/ ) {
		$self->{perror} = 1;
		$self->{error}  = 30;
		$self->{errorString}
			= 'the option zone is '
			. ( defined( $self->{options}{zone} ) ? '"' . $self->{options}{zone} . '" and not a valid zone' : 'undef' );
		$self->warn;
	}

	# keyfile must be free of whitespace and single quotes so it is safe to embed
	if ( !defined( $self->{options}{keyfile} ) || $self->{options}{keyfile} !~ /^[^'\s]+$/ ) {
		$self->{perror} = 1;
		$self->{error}  = 31;
		$self->{errorString}
			= 'the option keyfile is '
			. (
			defined( $self->{options}{keyfile} )
			? '"' . $self->{options}{keyfile} . '" which contains whitespace or single quotes'
			: 'undef'
			);
		$self->warn;
	} ## end if ( !defined( $self->{options}{keyfile} )...)

	$self->{options}{trigger}  = 'client-ip' if ( !defined( $self->{options}{trigger} ) );
	$self->{options}{ttl}      = 60          if ( !defined( $self->{options}{ttl} ) );
	$self->{options}{nsupdate} = 'nsupdate'  if ( !defined( $self->{options}{nsupdate} ) );

	if ( $self->{options}{trigger} ne 'client-ip' && $self->{options}{trigger} ne 'ip' ) {
		$self->{perror}      = 1;
		$self->{error}       = 20;
		$self->{errorString} = 'the option trigger is "' . $self->{options}{trigger} . '" and not "client-ip" or "ip"';
		$self->warn;
	}

	return $self;
} ## end sub new

=head2 _owner

Internal helper. Returns the RPZ owner name for the passed IP: the reversed
address in RPZ IP format under the configured trigger and zone.

=cut

sub _owner {
	my ( $self, $ip ) = @_;

	my $rpz_ip;
	if ( $ip =~ /\A$IPv4_re\z/ ) {
		$rpz_ip = '32.' . join( '.', reverse( split( /\./, $ip ) ) );
	} else {
		# expand the eight IPv6 groups, reverse them, and replace the longest
		# run of zero groups with zz (the RPZ IPv6 encoding)
		my @groups = $self->_v6_groups($ip);
		my @rev    = reverse(@groups);

		# find the longest run of '0' groups
		my ( $best_start, $best_len ) = ( -1, 0 );
		my $i = 0;
		while ( $i < scalar(@rev) ) {
			if ( $rev[$i] eq '0' ) {
				my $j = $i;
				$j++ while ( $j < scalar(@rev) && $rev[$j] eq '0' );
				if ( ( $j - $i ) > $best_len ) {
					$best_len   = $j - $i;
					$best_start = $i;
				}
				$i = $j;
			} else {
				$i++;
			}
		} ## end while ( $i < scalar(@rev) )

		my @out;
		$i = 0;
		while ( $i < scalar(@rev) ) {
			if ( $i == $best_start && $best_len > 0 ) {
				push( @out, 'zz' );
				$i += $best_len;
			} else {
				push( @out, $rev[$i] );
				$i++;
			}
		}

		$rpz_ip = '128.' . join( '.', @out );
	} ## end else [ if ( $ip =~ /\A$IPv4_re\z/)]

	return $rpz_ip . '.rpz-' . $self->{options}{trigger} . '.' . $self->{options}{zone};
} ## end sub _owner

=head2 _v6_groups

Internal helper. Expands an IPv6 IP to its eight groups, each hex with leading
zeros stripped ('0' for a zero group).

=cut

sub _v6_groups {
	my ( $self, $ip ) = @_;

	my @groups;
	if ( $ip =~ /::/ ) {
		my ( $left, $right ) = split( /::/, $ip, 2 );
		my @l = ( defined($left)  && $left ne '' )  ? split( /:/, $left )  : ();
		my @r = ( defined($right) && $right ne '' ) ? split( /:/, $right ) : ();
		my $fill = 8 - scalar(@l) - scalar(@r);
		@groups = ( @l, ('0') x $fill, @r );
	} else {
		@groups = split( /:/, $ip );
	}

	# normalize each group: lowercase, strip leading zeros, empty becomes 0
	foreach my $g (@groups) {
		$g = lc($g);
		$g =~ s/^0+(?=.)//;
		$g = '0' if ( $g eq '' );
	}

	return @groups;
} ## end sub _v6_groups

=head2 _nsupdate_command

Internal helper. Returns the shell command piping the given update statements
into nsupdate, wrapped with the optional server line, zone, and send.

=cut

sub _nsupdate_command {
	my ( $self, @updates ) = @_;

	my @statements;
	if ( defined( $self->{options}{server} ) && $self->{options}{server} ne '' ) {
		push( @statements, 'server ' . $self->{options}{server} );
	}
	push( @statements, 'zone ' . $self->{options}{zone} );
	push( @statements, @updates );
	push( @statements, 'send' );

	return
		  "printf '"
		. join( '\n', @statements )
		. "\\n' | "
		. $self->{options}{nsupdate} . " -k '"
		. $self->{options}{keyfile} . "'";
} ## end sub _nsupdate_command

=head2 _ban_command / _unban_command

Internal helpers. Return the nsupdate command that adds/removes the RPZ record
for the IP.

=cut

sub _ban_command {
	my ( $self, $ip ) = @_;

	return $self->_nsupdate_command(
		'update add ' . $self->_owner($ip) . ' ' . $self->{options}{ttl} . ' IN CNAME .' );
}

sub _unban_command {
	my ( $self, $ip ) = @_;

	return $self->_nsupdate_command( 'update delete ' . $self->_owner($ip) . ' IN CNAME .' );
}

=head2 init

Initiates the backend. Verifies the keyfile exists.

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
		$self->{frontend_obj}->{test_data} = 'inited';
	} elsif ( !-f $self->{options}{keyfile} ) {
		$self->{error} = 23;
		$self->{errorString}
			= 'init failed. the keyfile, "' . $self->{options}{keyfile} . '", does not exist or is not a file';
		$self->warn;
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

	my $command = $self->_ban_command( $opts{ban} );
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

	my $command = $self->_unban_command( $opts{ban} );
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

Re-adds every retained RPZ record.

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

	my @commands;
	foreach my $item ( keys( %{ $self->{banned} } ) ) {
		my $command = $self->_ban_command($item);
		if ( $self->{testing} ) {
			push( @commands, $command );
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
		$self->{frontend_obj}->{test_data} = \@commands;
	}

	$self->{inited} = 1;
} ## end sub re_init

=head2 teardown

Removes the RPZ record for each currently banned IP. The internal ban list is
kept so a following re_init restores them.

=cut

sub teardown {
	my ( $self, %opts ) = @_;

	$self->errorblank;

	$self->{inited} = 0;

	my @commands;
	foreach my $item ( sort( keys( %{ $self->{banned} } ) ) ) {
		my $command = $self->_unban_command($item);
		if ( $self->{testing} ) {
			push( @commands, $command );
		} else {
			my $output = `$command 2>&1`;
			if ( $? != 0 ) {
				$self->{error} = 17;
				$self->{errorString}
					= 'teardown failed. non-zero exit code for the command... "' . $command . '"... output... ' . $output;
				$self->warn;
			}
		}
	} ## end foreach my $item ( sort( keys...))

	if ( $self->{testing} ) {
		$self->{frontend_obj}->{test_data} = \@commands;
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

Verifies the keyfile still exists. Zero is healthy.

=cut

sub check {
	my ( $self, %opts ) = @_;

	$self->errorblank;

	if ( $self->{testing} ) {
		$self->{frontend_obj}->{test_data} = 'check';
		return 1;
	}

	return ( -f $self->{options}{keyfile} ) ? 1 : 0;
} ## end sub check

=head2 flush

Removes every RPZ record and clears the ban list.

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
	foreach my $item ( sort( keys( %{ $self->{banned} } ) ) ) {
		my $command = $self->_unban_command($item);
		if ( $self->{testing} ) {
			push( @commands, $command );
		} else {
			my $output = `$command 2>&1`;
			if ( $? != 0 ) {
				$self->{error} = 25;
				$self->{errorString}
					= 'flush failed. non-zero exit code for the command... "' . $command . '"... output... ' . $output;
				$self->warn;
			}
		}
	} ## end foreach my $item ( sort( keys...))

	if ( $self->{testing} ) {
		$self->{frontend_obj}->{test_data} = \@commands;
	}

	$self->{banned} = {};
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
    20 triggerInvalid
    23 initFailed
    24 checkFailed
    25 flushFailed
    26 portsNotSupported
    27 protocolsNotSupported
    30 zoneInvalid
    31 keyfileInvalid

=head1 AUTHOR

Zane C. Bowers-Hadley, C<< <vvelox at vvelox.ent> >>

=head1 LICENSE AND COPYRIGHT

This software is Copyright (c) 2023 by Zane C. Bowers-Hadley.

This is free software, licensed under:

  The GNU Lesser General Public License, Version 2.1, February 1999

=cut

1;    # End of Net::Firewall::BlockerHelper::backends::dns_rpz
