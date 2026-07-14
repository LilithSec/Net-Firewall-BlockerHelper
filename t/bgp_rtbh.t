#!perl
use 5.006;
use strict;
use warnings;
use Test::More;

BEGIN {
	use_ok('Net::Firewall::BlockerHelper') || print "Bail out!\n";
}

# announce/withdraw blackhole routes, family-correct next-hop and mask
{
	my $fw = Net::Firewall::BlockerHelper->new(
		backend => 'bgp_rtbh',
		name    => 'rtbh',
		testing => 1,
		options => { next_hop => '192.0.2.1', next_hop6 => '100::1' },
	);
	$fw->init_backend;

	$fw->ban( ban => '1.2.3.4' );
	is( $fw->{test_data},
		'exabgpcli announce route 1.2.3.4/32 next-hop 192.0.2.1 community [65535:666]',
		'IPv4 ban announces a /32 with the default BLACKHOLE community' );

	$fw->ban( ban => 'dead::1' );
	is( $fw->{test_data},
		'exabgpcli announce route dead::1/128 next-hop 100::1 community [65535:666]',
		'IPv6 ban announces a /128 with the v6 next-hop' );

	$fw->unban( ban => '1.2.3.4' );
	is( $fw->{test_data},
		'exabgpcli withdraw route 1.2.3.4/32 next-hop 192.0.2.1 community [65535:666]',
		'unban withdraws the same route' );

	# re-banning is a no-op
	$fw->ban( ban => 'dead::1' );
	is( $fw->{test_data}, 'already banned', 're-banning reports already banned' );

	is_deeply( [ $fw->list ], ['dead::1'], 'list reflects the remaining ban' );
}

# custom community, mask, and extra attributes
{
	my $fw = Net::Firewall::BlockerHelper->new(
		backend => 'bgp_rtbh',
		name    => 'rtbh',
		testing => 1,
		options => {
			exabgpcli_cmd => '/usr/bin/exabgpcli',
			community     => '64500:100',
			next_hop      => '10.0.0.1',
			mask4         => 24,
			extra         => 'local-preference 50',
		},
	);
	$fw->init_backend;
	$fw->ban( ban => '203.0.113.0' );
	is( $fw->{test_data},
		'/usr/bin/exabgpcli announce route 203.0.113.0/24 next-hop 10.0.0.1 community [64500:100] local-preference 50',
		'options drive command, community, mask, and extra attributes' );
}

# gobgp driver emits gobgp global rib syntax
{
	my $fw = Net::Firewall::BlockerHelper->new(
		backend => 'bgp_rtbh',
		name    => 'rtbh',
		testing => 1,
		options => { driver => 'gobgp', next_hop => '10.0.0.1' },
	);
	$fw->init_backend;

	$fw->ban( ban => '1.2.3.4' );
	is( $fw->{test_data},
		'gobgp global rib add 1.2.3.4/32 nexthop 10.0.0.1 community 65535:666 -a ipv4',
		'gobgp IPv4 ban adds to the global rib with the community' );

	$fw->ban( ban => 'dead::1' );
	is( $fw->{test_data},
		'gobgp global rib add dead::1/128 nexthop 100::1 community 65535:666 -a ipv6',
		'gobgp IPv6 ban uses the ipv6 afi and v6 next-hop' );

	$fw->unban( ban => '1.2.3.4' );
	is( $fw->{test_data}, 'gobgp global rib del 1.2.3.4/32 -a ipv4',
		'gobgp withdraw matches on prefix and afi only' );

	is( $fw->check ? $fw->{test_data} : 'x', 'gobgp neighbor', 'gobgp check uses gobgp neighbor' );
}

# an invalid driver is fatal
{
	my $died = 0;
	eval {
		my $fw = Net::Firewall::BlockerHelper->new(
			backend => 'bgp_rtbh', name => 'rtbh', testing => 1, options => { driver => 'bird' },
		);
		$fw->init_backend;
	};
	$died = 1 if ($@);
	ok( $died, 'invalid driver is fatal' );
}

# teardown withdraws all announced routes
{
	my $fw = Net::Firewall::BlockerHelper->new(
		backend => 'bgp_rtbh', name => 'rtbh', testing => 1, options => {},
	);
	$fw->init_backend;
	$fw->ban( ban => '1.1.1.1' );
	$fw->ban( ban => '2.2.2.2' );
	$fw->teardown;
	is_deeply(
		[ sort @{ $fw->{test_data} } ],
		[
			'exabgpcli withdraw route 1.1.1.1/32 next-hop 192.0.2.1 community [65535:666]',
			'exabgpcli withdraw route 2.2.2.2/32 next-hop 192.0.2.1 community [65535:666]',
		],
		'teardown withdraws every announced route'
	);
}

done_testing();
