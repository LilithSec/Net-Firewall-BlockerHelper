package Net::Firewall::BlockerHelper::backends::iptables;

use 5.006;
use strict;
use warnings;
use base 'Error::Helper';
use Regexp::IPv4 qw($IPv4_re);
use Regexp::IPv6 qw($IPv6_re);

=head1 NAME

Net::Firewall::BlockerHelper::backends::iptables - iptables/ip6tables backend for Net::Firewall::BlockerHelper.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    use Net::Firewall::BlockerHelper::backends::iptables;

    my $backend1;
    my $backend2;
    eval {
        $backend1 = Net::Firewall::BlockerHelper::backends::iptables->new(
                name => 'all',
                options=>{ kill=>1 },
            );
        $backend2 = Net::Firewall::BlockerHelper::backends::iptables->new(
                ports => ['143'],
                protocols => ['tcp'],
                name => 'imap',
            );
    };
    if ($@) {
        print 'Error: '
            . $Error::Helper::error
            . "\nError String: "
            . $Error::Helper::errorString
            . "\nError Flag: "
            . $Error::Helper::errorFlag . "\n";
    }

    $backend1->init;
    $backend2->init;

    $backend1->ban(ban=>'1.2.3.4');
    $backend1->ban(ban=>'4.3.2.1');
    $backend2->ban(ban=>'4.3.2.1');

    use Data::Dumper;
    print Dumper($backend1->list);
    print Dumper($backend2->list);

    $backend1->unban(ban=>'4.3.2.1');

    $backend1->teardown;
    $backend2->teardown;

=head1 DESCRIPTION

This backend blocks IPs using L<ipset(8)> in combination with
L<iptables(8)> and L<ip6tables(8)>.

For each instance two ipsets are created, one for IPv4
(C<< <prefix>_<name>_4 >>) and one for IPv6 (C<< <prefix>_<name>_6 >>),
along with a dedicated chain (C<< <prefix>_<name> >>) in each of the
C<filter> tables. The chain is populated with the block rules and jumped
to from C<INPUT>. Banning an IP is then simply a matter of adding it to
the relevant ipset.

Requires C<ipset>, C<iptables>, and C<ip6tables> to be installed and in
the C<PATH> of the process, which must have sufficient privileges to run
them.

=head1 METHODS

=head2 new

Initiates the the object.

    - options :: Backend specific options that will be passed to the backend unchecked
            outside of making sure it is a hash ref if defined. See below for furhter info.
        - Default :: {}

    - ports :: A array of ports to block. Checked to make sure they are positive ints or a valid
            service name via getservbyname. All ports will be blocked if non are specified. If
            duplicates are removed.
        - Default :: []

    - protocols :: A array of protocols to block. By default will block all. This
            is checked against /etc/protocols via the function getprotobyname. Duplicates
            will be discarded.
        - Default :: []

    - prefix :: Prefix to use. Must match the regex /^[a-zA-Z0-9]+$/
        - default :: kur

    - name :: Name of this specific instance. This must be specified.
        - default :: undef

The options hash accepts the following.

    - type :: The drop method to use. Should either be 'drop' or 'reject'.
            'reject' sends an ICMP port-unreachable back. See iptables(8).
        - Default :: drop

    - kill :: Use conntrack(8) to drop existing connections for the banned IP.
        - Default :: 0

All errors are considered fatal, meaning if new fails it will die.

    my $backend;
    eval {
        $backend = Net::Firewall::BlockerHelper::backends::iptables->new(
                ports => ['22'],
                protocols => ['tcp'],
                name => 'ssh',
            );
    };
    if ($@) {
        print 'Error: '
            . $Error::Helper::error
            . "\nError String: "
            . $Error::Helper::errorString
            . "\nError Flag: "
            . $Error::Helper::errorFlag . "\n";
    }

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
			flags            => {
				1  => 'notInited',
				2  => 'invalidPortSpecified',
				3  => 'portsNotArray',
				4  => 'protocolsNotArray',
				5  => 'invalidPortSpecified',
				6  => 'invalidPrefixSpecified',
				7  => 'invalidName',
				8  => 'optionsNotHash',
				9  => 'noBanItem',
				10 => 'banItemNotIP',
				11 => 'invalidBackend',
				12 => 'backendInitError',
				13 => 'banFailed',
				14 => 'unbanFailed',
				15 => 'listFailed',
				16 => 'reInitFailed',
				17 => 'teardownFailed',
				18 => 'alreadyInited',
				20 => 'typeInvalid',
				23 => 'initFailed',
			},
			fatal_flags      => {},
			perror_not_fatal => 0,
		},
		options => {
			type => 'drop',
			kill => 0,
		},
		ports        => [],
		protocols    => [],
		testing      => undef,
		test_data    => undef,
		prefix       => 'kur',
		postfix      => undef,
		frontend_obj => undef,
		inited       => 0,
		banned       => {},
	};
	bless $self;

	if ( defined( $opts{ports} ) && ref( $opts{ports} ) ne 'ARRAY' ) {
		$self->{perror}      = 1;
		$self->{error}       = 3;
		$self->{errorString} = 'ports is defined and type is not array but "' . ref( $opts{ports} ) . '"';
		$self->warn;
	} elsif ( defined( $opts{ports} ) ) {
		my %ports;
		foreach my $item ( @{ $opts{ports} } ) {
			if ( $item =~ /^[0-9]+$/ && $item >= 1 ) {
				$ports{$item} = 1;
			} elsif ( $item =~ /^[0-9]+$/ && $item < 1 ) {
				$self->{perror} = 1;
				$self->{error}  = 2;
				$self->{errorString}
					= $item . ' is not a valid value for a port as it must be a int greater or equal to 1';
				$self->warn;
			} else {
				# just using tcp here as protocol must be specified
				my ( $name, $aliases, $port, $proto ) = getservbyname( $item, 'tcp' );
				if ( !defined($port) ) {
					$self->{perror} = 1;
					$self->{error}  = 2;
					$self->{errorString}
						= $item . ' could not be resolved to a port name via getservbyname("' . $item . '", "tcp")';
					$self->warn;
				}
				$ports{$port} = 1;
			} ## end else [ if ( $item =~ /^[0-9]+$/ && $item >= 1 ) ]
		} ## end foreach my $item ( @{ $opts{ports} } )
		my @port_keys = keys(%ports);
		@port_keys = sort { $a <=> $b } @port_keys;
		push( @{ $self->{ports} }, @port_keys );
	} ## end elsif ( defined( $opts{ports} ) )

	if ( defined( $opts{protocols} ) && ref( $opts{protocols} ) ne 'ARRAY' ) {
		$self->{perror}      = 1;
		$self->{error}       = 4;
		$self->{errorString} = 'protocols is defined and type is not array but "' . ref( $opts{protocols} ) . '"';
		$self->warn;
	} elsif ( defined( $opts{protocols} ) ) {
		my %protocols;
		foreach my $item ( @{ $opts{protocols} } ) {
			my ( $name, $aliases, $proto ) = getprotobyname($item);
			# if this is undef, it means it is not a known protocol
			if ( !defined($proto) ) {
				$self->{perror} = 1;
				$self->{error}  = 5;
				$self->{errorString}
					= $item . ' could not be resolved to a protocol via getprotobyname("' . $item . '")';
				$self->warn;
			}
			$protocols{$item} = 1;
		} ## end foreach my $item ( @{ $opts{protocols} } )
		my @protocols_keys = keys(%protocols);
		@protocols_keys = sort { $a cmp $b } @protocols_keys;
		push( @{ $self->{protocols} }, @protocols_keys );
	} ## end elsif ( defined( $opts{protocols} ) )

	# make sure prefix is sane if defiend
	if ( defined( $opts{prefix} ) && $opts{prefix} !~ /^[a-zA-Z0-9]+$/ ) {
		$self->{perror} = 1;
		$self->{error}  = 6;
		$self->{errorString}
			= '"' . $opts{prefix} . '" is not a valid prefix as it does not match the regex /^[a-zA-Z0-9]+$/';
		$self->warn;
	} elsif ( defined( $opts{prefix} ) ) {
		$self->{prefix} = $opts{prefix};
	}

	# make sure we have a name and that it is valid
	if ( !defined( $opts{name} ) ) {
		$self->{perror}      = 1;
		$self->{error}       = 7;
		$self->{errorString} = 'name is undef';
		$self->warn;
	} elsif ( $opts{name} !~ /^[a-zA-Z0-9\-]+$/ ) {
		$self->{perror}      = 1;
		$self->{error}       = 7;
		$self->{errorString} = 'name set to "' . $opts{name} . '" which does not match the regexp  /^[a-zA-Z0-9\-]+$/';
		$self->warn;
	}
	$self->{name} = $opts{name};

	# used internally for testing
	if ( defined( $opts{testing} ) ) {
		$self->{testing} = $opts{testing};
	}
	if ( defined( $opts{frontend_obj} ) ) {
		$self->{frontend_obj} = $opts{frontend_obj};
	}

	if ( defined( $opts{options} ) ) {
		if ( ref( $opts{options} ) ne 'HASH' ) {
			$self->{perror}      = 1;
			$self->{error}       = 8;
			$self->{errorString} = 'ref for options is "' . ref( $opts{options} ) . '" and not HASH';
			$self->warn;
		}
		$self->{options} = $opts{options};

		if ( !defined( $opts{options}{kill} ) ) {
			$self->{options}{kill} = 0;
		}

		if ( defined( $opts{options}{type} ) && ref( $opts{options}{type} ) ne '' ) {
			$self->{perror}      = 1;
			$self->{error}       = 20;
			$self->{errorString} = 'ref for $opts{options}{type} is "' . ref( $opts{options}{type} ) . '" and not ""';
			$self->warn;
		} elsif ( defined( $opts{options}{type} )
			&& $opts{options}{type} ne 'drop'
			&& $opts{options}{type} ne 'reject' )
		{
			$self->{perror} = 1;
			$self->{error}  = 20;
			$self->{errorString}
				= '$opts{options}{type} is "' . $opts{options}{type} . '" and not "drop" or "reject"';
			$self->warn;
		} elsif ( !defined( $opts{options}{type} ) ) {
			$self->{options}{type} = 'drop';
		}

	} ## end if ( defined( $opts{options} ) )

	return $self;
} ## end sub new

=head2 _set_names

Internal helper. Returns the IPv4 ipset name, IPv6 ipset name, and chain
name for this instance.

=cut

sub _set_names {
	my ($self) = @_;

	my $chain = $self->{prefix} . '_' . $self->{name};
	return ( $chain . '_4', $chain . '_6', $chain );
}

=head2 _rule_commands

Internal helper. Returns the list of commands that populate the chain
with the block rules, based on the configured protocols and ports.

=cut

sub _rule_commands {
	my ($self) = @_;

	my ( $set4, $set6, $chain ) = $self->_set_names;

	my @ports    = @{ $self->{ports} };
	my @protos   = @{ $self->{protocols} };
	my $port_str = join( ',', @ports );

	# work out the target for each family
	my $t4 = 'DROP';
	my $t6 = 'DROP';
	if ( $self->{options}{type} eq 'reject' ) {
		$t4 = 'REJECT --reject-with icmp-port-unreachable';
		$t6 = 'REJECT --reject-with icmp6-port-unreachable';
	}

	my @families = (
		{ cmd => 'iptables',  set => $set4, tgt => $t4, family => 4 },
		{ cmd => 'ip6tables', set => $set6, tgt => $t6, family => 6 },
	);

	my @commands;
	foreach my $fam (@families) {
		my $base = $fam->{cmd} . ' -A ' . $chain . ' -m set --match-set ' . $fam->{set} . ' src';

		if ( !@protos && !@ports ) {
			# block everything sourced from the set
			push( @commands, $base . ' -j ' . $fam->{tgt} );
		} elsif ( !@protos && @ports ) {
			# ports require a protocol, default to tcp and udp
			foreach my $proto ( 'tcp', 'udp' ) {
				push( @commands,
					$base . ' -p ' . $proto . ' -m multiport --dports ' . $port_str . ' -j ' . $fam->{tgt} );
			}
		} else {
			foreach my $proto (@protos) {
				# skip protocols that do not belong to this family
				if ( $fam->{family} == 6 ) {
					next if ( $proto eq 'icmp' );
				} else {
					next if ( $proto eq 'ipv6-icmp' );
				}

				my $rule = $base . ' -p ' . $proto;
				if ( @ports && ( $proto eq 'tcp' || $proto eq 'udp' ) ) {
					$rule .= ' -m multiport --dports ' . $port_str;
				}
				$rule .= ' -j ' . $fam->{tgt};
				push( @commands, $rule );
			} ## end foreach my $proto (@protos)
		} ## end else [ if ( !@protos && !@ports ) ]
	} ## end foreach my $fam (@families)

	return @commands;
} ## end sub _rule_commands

=head2 init

Initiates the backend. This will attempt to drop the chain and ipsets
prior to re-adding them.

No arguments are taken.

May called a second time, it will error.

    $backend->init;

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
		$self->{frontend_obj}->{test_data} = {};
	}

	my ( $set4, $set6, $chain ) = $self->_set_names;

	# these are cleanup commands for any stale state and are allowed to fail
	my @fail_okay_commands;
	push( @fail_okay_commands, 'iptables -D INPUT -j ' . $chain );
	push( @fail_okay_commands, 'ip6tables -D INPUT -j ' . $chain );
	push( @fail_okay_commands, 'iptables -F ' . $chain );
	push( @fail_okay_commands, 'ip6tables -F ' . $chain );
	push( @fail_okay_commands, 'iptables -X ' . $chain );
	push( @fail_okay_commands, 'ip6tables -X ' . $chain );
	push( @fail_okay_commands, 'ipset destroy ' . $set4 );
	push( @fail_okay_commands, 'ipset destroy ' . $set6 );

	if ( $self->{testing} ) {
		$self->{frontend_obj}->{test_data}{fail_okay_commands} = \@fail_okay_commands;
	} else {
		foreach my $item (@fail_okay_commands) {
			my $output = `$item 2>&1`;
		}
	}

	my @commands;
	# create the ipsets and the chain
	push( @commands, 'ipset create ' . $set4 . ' hash:ip family inet' );
	push( @commands, 'ipset create ' . $set6 . ' hash:ip family inet6' );
	push( @commands, 'iptables -N ' . $chain );
	push( @commands, 'ip6tables -N ' . $chain );

	# add the block rules to the chain
	push( @commands, $self->_rule_commands );

	# jump to the chain from INPUT
	push( @commands, 'iptables -A INPUT -j ' . $chain );
	push( @commands, 'ip6tables -A INPUT -j ' . $chain );

	if ( $self->{testing} ) {
		$self->{frontend_obj}->{test_data}{commands} = \@commands;
	} else {
		foreach my $item (@commands) {
			my $output = `$item 2>&1`;
			if ( $? != 0 ) {
				$self->{error} = 23;
				$self->{errorString}
					= 'init failed. non-zero exit code for the command... "' . $item . '"... output... ' . $output;
				$self->warn;
			}
		}
	} ## end else [ if ( $self->{testing} ) ]

	$self->{inited} = 1;
} ## end sub init

=head2 ban

Bans the IP.

    $backend->ban(ban => $ip);

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

	if ( $self->{banned}{ $opts{ban} } ) {
		$self->{frontend_obj}->{test_data} = 'already banned';
		return;
	}

	my ( $set4, $set6 ) = $self->_set_names;
	my $set = ( $opts{ban} =~ /\A$IPv4_re\z/ ) ? $set4 : $set6;

	my $command = 'ipset add ' . $set . ' ' . $opts{ban};

	if ( $self->{testing} ) {
		$self->{frontend_obj}->{test_data} = [$command];
	} else {
		my $output = `$command 2>&1`;
		if ( $? != 0 ) {
			$self->{error} = 13;
			$self->{errorString}
				= 'ban failed. non-zero exit code for the command... "' . $command . '"... output... ' . $output;
			$self->warn;
		}
	}

	if ( $self->{options}{kill} ) {
		# conntrack returns non-zero when there is nothing to delete, so its
		# exit code is intentionally ignored.
		$command = 'conntrack -D -s ' . $opts{ban};
		if ( $self->{testing} ) {
			push( @{ $self->{frontend_obj}->{test_data} }, $command );
		} else {
			my $output = `$command 2>&1`;
		}
	} ## end if ( $self->{options}{kill} )

	$self->{banned}{ $opts{ban} } = 1;
} ## end sub ban

=head2 unban

Unbans the an IP.

    $backend->unban(ban => $ip);

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

	if ( !$self->{banned}{ $opts{ban} } ) {
		$self->{frontend_obj}->{test_data} = 'not banned';
		return;
	}

	my ( $set4, $set6 ) = $self->_set_names;
	my $set = ( $opts{ban} =~ /\A$IPv4_re\z/ ) ? $set4 : $set6;

	my $command = 'ipset del ' . $set . ' ' . $opts{ban};

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

    my @banned = $backend->list;

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

Tells the backend to re-init it's self.

This will call teardown and init again. After that it will
re-added all previously added bans.

    $backend->re_init;

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

	$self->teardown;
	$self->init;

	my ( $set4, $set6 ) = $self->_set_names;

	my @to_ban = keys( %{ $self->{banned} } );

	my @re_init_test_data;
	foreach my $item (@to_ban) {
		my $set = ( $item =~ /\A$IPv4_re\z/ ) ? $set4 : $set6;
		my $command = 'ipset add ' . $set . ' ' . $item;

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
	} ## end foreach my $item (@to_ban)

	if ( $self->{testing} ) {
		$self->{frontend_obj}->{test_data} = \@re_init_test_data;
	}

	$self->{inited} = 1;
} ## end sub re_init

=head2 teardown

Tears down the setup for the backend.

This will remove the chain, the jump from INPUT, and the ipsets.

If called prior to calling init, this will error. It won't check if it has been
inited or not.

    $backend->teardown;

=cut

sub teardown {
	my ( $self, %opts ) = @_;

	$self->errorblank;

	$self->{inited} = 0;

	$self->{frontend_obj}->{test_data} = {};

	my ( $set4, $set6, $chain ) = $self->_set_names;

	my @commands;
	push( @commands, 'iptables -D INPUT -j ' . $chain );
	push( @commands, 'ip6tables -D INPUT -j ' . $chain );
	push( @commands, 'iptables -F ' . $chain );
	push( @commands, 'ip6tables -F ' . $chain );
	push( @commands, 'iptables -X ' . $chain );
	push( @commands, 'ip6tables -X ' . $chain );
	push( @commands, 'ipset destroy ' . $set4 );
	push( @commands, 'ipset destroy ' . $set6 );

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

=head1 ERROR CODES / FLAGS

Error handling is provided by L<Error::Helper>. All
errors are considered fatal.

=head2 1, notInited

Backend has not been initted yet.

=head2 2, invalidPortSpecified

Port is either not a positive int or a name that can be resolved by getservbyname.

=head2 3, portsNotArray

The data passed to new for ports is not an array.

=head2 4, protocolsNotArray

The data passed to new for protocols is not an array.

=head2 5, invalidPortSpecified

Port is either not a positive int or a name that can be resolved by getservbyname.

=head2 6, invalidPrefixSpecified

The specified prefix did not match /^[a-zA-Z0-9]+$/.

=head2 7, invalidName

The name is either undef or does not match /^[a-zA-Z0-9\-]+$/.

=head2 8, optionsNotHash

The item passed to new for options is not a hash.

=head2 9, noBanItem

No IP specified to ban.

=head2 10, banItemNotIP

The item to ban is not an IP. Either wrong ref type or regexp
test using L<Regexp::IPv4> and L<Regexp::IPv6> failed.

=head2 11, invalidBackend

The specified backend failed to pass a basic sanity check of making sure it
matches the regexp /^[a-zA-Z0-9\_]+$/.

=head2 12, backendInitError

Failed to init the backend.

=head2 13, banFailed

Failed to ban the item.

=head2 14, unbanFailed

Failed to unban the item.

=head2 15, listFailed

Failed get a list of bans.

=head2 16, reInitFailed

Failed to re_init the backend.

=head2 17, teardownFailed

Failed to teardown the backend.

=head2 18, alreadyInited

Backend has already been initiated.

=head2 20, typeInvalid

The value for type is not valid. Should be 'drop' or 'reject'.

=head2 23, initFailed

One of the required commands for init failed.

=head1 AUTHOR

Zane C. Bowers-Hadley, C<< <vvelox at vvelox.ent> >>

=head1 BUGS

Please report any bugs or feature requests to C<bug-net-firewall-blockerhelper at rt.cpan.org>, or through
the web interface at L<https://rt.cpan.org/NoAuth/ReportBug.html?Queue=Net-Firewall-BlockerHelper>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.




=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc Net::Firewall::BlockerHelper


You can also look for information at:

=over 4

=item * RT: CPAN's request tracker (report bugs here)

L<https://rt.cpan.org/NoAuth/Bugs.html?Dist=Net-Firewall-BlockerHelper>

=item * Search CPAN

L<https://metacpan.org/release/Net-Firewall-BlockerHelper>

=back


=head1 ACKNOWLEDGEMENTS


=head1 LICENSE AND COPYRIGHT

This software is Copyright (c) 2023 by Zane C. Bowers-Hadley.

This is free software, licensed under:

  The GNU Lesser General Public License, Version 2.1, February 1999


=cut

1;    # End of Net::Firewall::BlockerHelper
