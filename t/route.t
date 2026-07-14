#!perl
use 5.006;
use strict;
use warnings;
use Test::More;

BEGIN {
	use_ok('Net::Firewall::BlockerHelper')                  || print "Bail out!\n";
	use_ok('Net::Firewall::BlockerHelper::backends::route') || print "Bail out!\n";
}

my $fw = Net::Firewall::BlockerHelper->new(
	backend => 'route',
	name    => 'ssh',
	testing => 1,
);
$fw->init_backend;
is( $fw->{test_data}, 'inited', 'init needs no commands' );

$fw->ban( ban => '1.2.3.4' );
is_deeply( $fw->{test_data}, ['ip route add unreachable 1.2.3.4'], 'IPv4 ban adds a null route' );

$fw->ban( ban => 'dead::1' );
is_deeply( $fw->{test_data}, ['ip -6 route add unreachable dead::1'], 'IPv6 ban uses ip -6' );

$fw->ban( ban => '1.2.3.4' );
is( $fw->{test_data}, 'already banned', 'double ban short-circuits' );

is( $fw->check, 1, 'check reports healthy in testing mode' );
is_deeply(
	$fw->{test_data},
	[ 'ip route show unreachable 1.2.3.4', 'ip -6 route show unreachable dead::1' ],
	'check probes the route for each banned IP'
);

$fw->unban( ban => '1.2.3.4' );
is( $fw->{test_data}, 'ip route del unreachable 1.2.3.4', 'unban deletes the route' );

$fw->re_init;
is_deeply( $fw->{test_data}, ['ip -6 route add unreachable dead::1'], 're_init re-adds the remaining ban' );

$fw->teardown;
is_deeply( $fw->{test_data}, ['ip -6 route del unreachable dead::1'], 'teardown deletes the routes' );
is( scalar( $fw->list ), 1, 'teardown keeps the ban list for re_init' );

# re-arm the same backend object so the kept ban list is exercised
$fw->{backend_obj}->init;
$fw->flush;
is_deeply( $fw->{test_data}, ['ip -6 route del unreachable dead::1'], 'flush deletes the routes' );
is( scalar( $fw->list ), 0, 'flush empties the ban list' );

# --- blocktype option ----------------------------------------------------------
{
	my $fw2 = Net::Firewall::BlockerHelper->new(
		backend => 'route',
		name    => 'ssh',
		options => { blocktype => 'blackhole' },
		testing => 1,
	);
	$fw2->init_backend;
	$fw2->ban( ban => '1.2.3.4' );
	is_deeply( $fw2->{test_data}, ['ip route add blackhole 1.2.3.4'], 'blocktype=blackhole is used' );
}

# --- validation, on the backend directly as that is where these are checked ------
{
	local $@;
	eval { Net::Firewall::BlockerHelper::backends::route->new( name => 'ssh', ports => ['22'] ); };
	ok( $@, 'ports error as unsupported' );
	is( $Error::Helper::error, 26, 'ports raise error 26' );

	eval { Net::Firewall::BlockerHelper::backends::route->new( name => 'ssh', protocols => ['tcp'] ); };
	ok( $@, 'protocols error as unsupported' );
	is( $Error::Helper::error, 27, 'protocols raise error 27' );

	eval { Net::Firewall::BlockerHelper::backends::route->new( name => 'ssh', options => { blocktype => 'derp' } ); };
	ok( $@, 'an invalid blocktype errors' );
}

done_testing();
