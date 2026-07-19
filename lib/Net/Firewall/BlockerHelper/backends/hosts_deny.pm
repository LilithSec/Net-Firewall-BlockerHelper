package Net::Firewall::BlockerHelper::backends::hosts_deny;

use 5.006;
use strict;
use warnings;
use base 'Error::Helper';
use Regexp::IPv4 qw($IPv4_re);
use Regexp::IPv6 qw($IPv6_re);

=head1 NAME

Net::Firewall::BlockerHelper::backends::hosts_deny - TCP wrappers hosts.deny backend.

=head1 VERSION

Version 0.1.0

=cut

our $VERSION = '0.1.0';

=head1 SYNOPSIS

    use Net::Firewall::BlockerHelper;

    my $fw_helper = Net::Firewall::BlockerHelper->new(
        backend => 'hosts_deny',
        name    => 'sshd',
        options => { daemon => 'sshd' },
    );

    $fw_helper->init_backend;
    $fw_helper->ban( ban => '1.2.3.4' );
    $fw_helper->unban( ban => '1.2.3.4' );
    $fw_helper->teardown;

=head1 DESCRIPTION

Blocks IPs via TCP wrappers by maintaining a block of entries in
C</etc/hosts.deny>. Only libwrap aware daemons (those linked against
libwrap or launched via tcpd) honor this; it is not a packet filter.

The backend owns a single marked region of the file delimited by

    # BEGIN Net::Firewall::BlockerHelper <prefix>_<name>
    ...
    # END Net::Firewall::BlockerHelper <prefix>_<name>

Everything outside that region is preserved untouched, so hand maintained
rules and other instances (with a different prefix/name) coexist. Each ban
is rendered as a C<< <daemon> : <ip> >> line. No reload is needed as libwrap
reads the file on each connection.

=head1 METHODS

=head2 new

    - options :: A hash of options. See below.
    - name :: Required. Used, with prefix, to tag this instance's region.
    - prefix :: Defaults to 'kur'. Combined with name for the region tag.

The options hash accepts the following.

    - file :: Path to the hosts.deny file.
        - Default :: /etc/hosts.deny

    - daemon :: The daemon_list portion of each rule. 'ALL' blocks the IP for
            every libwrap daemon; a specific name (eg 'sshd') scopes it.
        - Default :: ALL

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
				7  => 'invalidName',
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
				31 => 'fileWriteFailed',
				32 => 'banCidrFailed',
				33 => 'unbanCidrFailed',
				34 => 'cidrItemNotCidr',
				35 => 'cidrNotSupported',
				36 => 'listCidrFailed',
			},
			fatal_flags      => {},
			perror_not_fatal => 0,
		},
		options      => {},
		ports        => [],
		protocols    => [],
		testing      => undef,
		test_data    => undef,
		test_outside => '',
		prefix       => 'kur',
		name         => undef,
		frontend_obj => undef,
		inited       => 0,
		banned       => {},
		cidr_supported => 0,
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

	if ( !defined( $opts{name} ) ) {
		$self->{perror}      = 1;
		$self->{error}       = 7;
		$self->{errorString} = 'name is undef';
		$self->warn;
	}
	$self->{name} = $opts{name};

	if ( defined( $opts{options} ) && ref( $opts{options} ) ne 'HASH' ) {
		$self->{perror}      = 1;
		$self->{error}       = 8;
		$self->{errorString} = 'ref for options is "' . ref( $opts{options} ) . '" and not HASH';
		$self->warn;
	} elsif ( defined( $opts{options} ) ) {
		$self->{options} = $opts{options};
	}

	$self->{options}{file}   = '/etc/hosts.deny' if ( !defined( $self->{options}{file} ) );
	$self->{options}{daemon} = 'ALL'             if ( !defined( $self->{options}{daemon} ) );

	return $self;
} ## end sub new

=head2 _markers

Internal helper. Returns the begin and end marker lines for this instance.

=cut

sub _markers {
	my ($self) = @_;

	my $tag = 'Net::Firewall::BlockerHelper ' . $self->{prefix} . '_' . $self->{name};
	return ( '# BEGIN ' . $tag, '# END ' . $tag );
}

=head2 _render_block

Internal helper. Builds this instance's marked region from the current ban
list. Returns an empty string when there is nothing banned so no stray
markers are left in the file.

=cut

sub _render_block {
	my ($self) = @_;

	my @ips = sort( keys( %{ $self->{banned} } ) );
	return '' if ( !@ips );

	my ( $begin, $end ) = $self->_markers;
	my @lines = ($begin);
	foreach my $ip (@ips) {
		push( @lines, $self->{options}{daemon} . ' : ' . $ip );
	}
	push( @lines, $end );

	return join( "\n", @lines ) . "\n";
} ## end sub _render_block

=head2 _strip_block

Internal helper. Given the full file contents, returns them with this
instance's marked region (and only this instance's) removed.

=cut

sub _strip_block {
	my ( $self, $content ) = @_;

	my ( $begin, $end ) = $self->_markers;
	# \Q..\E so the :: in the tag is treated literally rather than as regex
	$content =~ s/^\Q$begin\E\n.*?^\Q$end\E\n//ms;

	return $content;
} ## end sub _strip_block

=head2 _read

Internal helper. Returns the current file contents, or the simulated outside
content when testing, or '' when the file is absent.

=cut

sub _read {
	my ($self) = @_;

	return $self->{test_outside} if ( $self->{testing} );

	return '' if ( !-e $self->{options}{file} );

	my $fh;
	if ( !open( $fh, '<', $self->{options}{file} ) ) {
		return '';
	}
	local $/ = undef;
	my $content = <$fh>;
	close($fh);

	return defined($content) ? $content : '';
} ## end sub _read

=head2 _apply

Internal helper. Rewrites the file with this instance's region refreshed from
the current ban list, preserving all other content. In testing mode it
records the rendered file in test_data instead.

=cut

sub _apply {
	my ( $self, $error_flag ) = @_;

	my $outside = $self->_strip_block( $self->_read );
	my $block   = $self->_render_block;

	# keep a single trailing newline between preserved content and our block
	$outside =~ s/\n*\z/\n/ if ( $outside ne '' );
	my $content = $outside . $block;

	if ( $self->{testing} ) {
		$self->{frontend_obj}->{test_data} = {
			file    => $self->{options}{file},
			block   => $block,
			content => $content,
		};
		return;
	}

	my $fh;
	if ( !open( $fh, '>', $self->{options}{file} ) ) {
		$self->{error}       = 31;
		$self->{errorString} = 'could not open "' . $self->{options}{file} . '" for writing... ' . $!;
		$self->warn;
		return;
	}
	print( $fh $content );
	close($fh);

	return;
} ## end sub _apply

=head2 init

Initiates the backend. Removes any stale region for this instance and writes
a fresh (empty) one.

=cut

sub init {
	my ( $self, %opts ) = @_;

	$self->errorblank;

	if ( $self->{inited} ) {
		$self->{error}       = 18;
		$self->{errorString} = 'backend has already been inited';
		$self->warn;
	}

	$self->_apply(12);

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
	$self->_apply(13);
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
	$self->_apply(14);
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

Re-renders this instance's region from the retained ban list.

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

	$self->_apply(16);

	$self->{inited} = 1;
} ## end sub re_init

=head2 teardown

Removes this instance's region from the file, leaving everything else intact.

=cut

sub teardown {
	my ( $self, %opts ) = @_;

	$self->errorblank;

	$self->{inited} = 0;

	# empty the ban list so _apply strips our region and writes nothing back
	my %saved_banned = %{ $self->{banned} };
	$self->{banned} = {};
	$self->_apply(17);
	$self->{banned} = \%saved_banned;
} ## end sub teardown

=head2 stop

Alias for L</teardown>.

=cut

sub stop {
	my ( $self, %opts ) = @_;

	return $self->teardown(%opts);
}

=head2 check

Verifies our marked region is present with every banned IP. With nothing
banned there is nothing to verify and it reports healthy.

=cut

sub check {
	my ( $self, %opts ) = @_;

	$self->errorblank;

	if ( $self->{testing} ) {
		$self->{frontend_obj}->{test_data} = 'check';
		return 1;
	}

	my @ips = keys( %{ $self->{banned} } );
	return 1 if ( !@ips );

	my $content = $self->_read;
	my ( $begin, $end ) = $self->_markers;
	return 0 if ( index( $content, $begin ) < 0 );

	foreach my $ip (@ips) {
		return 0 if ( index( $content, $self->{options}{daemon} . ' : ' . $ip ) < 0 );
	}

	return 1;
} ## end sub check

=head2 flush

Removes all bans at once by clearing the ban list and rewriting the file.

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
	$self->_apply(25);
} ## end sub flush

=head2 _valid_cidr

Internal helper. Returns a true value if the passed scalar is a valid IPv4 or
IPv6 CIDR range, that is an address followed by C</> and a prefix length that
is within the range valid for its family (0 to 32 for IPv4, 0 to 128 for
IPv6). Returns false otherwise.

=cut

sub _valid_cidr {
	my ( $self, $cidr ) = @_;

	return 0 if ( !defined($cidr) || ref($cidr) ne '' );

	if ( $cidr =~ m!\A(.+)/([0-9]{1,3})\z! ) {
		my ( $addr, $prefix ) = ( $1, $2 );
		return 1 if ( $addr =~ /\A$IPv4_re\z/ && $prefix <= 32 );
		return 1 if ( $addr =~ /\A$IPv6_re\z/ && $prefix <= 128 );
	}

	return 0;
} ## end sub _valid_cidr

=head2 ban_cidr

CIDR bans are not supported by this backend; this always sets the
cidrNotSupported error.

    $backend->ban_cidr(ban => '1.2.3.0/24');

=cut

sub ban_cidr {
	my ( $self, %opts ) = @_;

	$self->errorblank;

	$self->{error}       = 35;
	$self->{errorString} = 'the ' . __PACKAGE__ . ' backend does not support CIDR bans';
	$self->warn;

	return;
} ## end sub ban_cidr

=head2 unban_cidr

CIDR bans are not supported by this backend; this always sets the
cidrNotSupported error.

    $backend->unban_cidr(ban => '1.2.3.0/24');

=cut

sub unban_cidr {
	my ( $self, %opts ) = @_;

	$self->errorblank;

	$self->{error}       = 35;
	$self->{errorString} = 'the ' . __PACKAGE__ . ' backend does not support CIDR bans';
	$self->warn;

	return;
} ## end sub unban_cidr

=head2 list_cidr

CIDR bans are not supported by this backend, so this always returns an empty
list.

    my @banned_cidrs = $backend->list_cidr;

=cut

sub list_cidr {
	my ( $self, %opts ) = @_;

	$self->errorblank;

	return ();
}

=head1 ERROR CODES / FLAGS

=head2 1, notInited

Backend has not been initted yet.

=head2 7, invalidName

The name is undef.

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

=head2 24, checkFailed

The backend check raised an error.

=head2 25, flushFailed

Failed to flush the bans.

=head2 31, fileWriteFailed

The hosts.deny file could not be opened for writing.

=head2 32, banCidrFailed

Failed to ban the CIDR range.

=head2 33, unbanCidrFailed

Failed to unban the CIDR range.

=head2 34, cidrItemNotCidr

The item to ban is not a CIDR range. Either wrong ref type or it is not an
IPv4 or IPv6 address followed by a prefix length valid for its family.

=head2 35, cidrNotSupported

The backend does not support CIDR bans.

=head2 36, listCidrFailed

Failed to get a list of CIDR bans.

=head1 AUTHOR

Zane C. Bowers-Hadley, C<< <vvelox at vvelox.ent> >>

=head1 LICENSE AND COPYRIGHT

This software is Copyright (c) 2023 by Zane C. Bowers-Hadley.

This is free software, licensed under:

  The GNU Lesser General Public License, Version 2.1, February 1999

=cut

1;    # End of Net::Firewall::BlockerHelper::backends::hosts_deny
