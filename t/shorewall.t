#!perl
use 5.006;
use strict;
use warnings;
use Test::More;

BEGIN {
	use_ok('Net::Firewall::BlockerHelper') || print "Bail out!\n";
}

# ban/unban route to shorewall (IPv4) and shorewall6 (IPv6) with the type verb
{
	my $fw = Net::Firewall::BlockerHelper->new(
		backend => 'shorewall',
		name    => 'ssh',
		testing => 1,
		options => { type => 'drop' },
	);
	$fw->init_backend;

	$fw->ban( ban => '1.2.3.4' );
	is( $fw->{test_data}, 'shorewall drop 1.2.3.4', 'IPv4 ban uses shorewall drop' );

	$fw->ban( ban => 'dead::1' );
	is( $fw->{test_data}, 'shorewall6 drop dead::1', 'IPv6 ban uses shorewall6 drop' );

	is_deeply( [ sort $fw->list ], [ '1.2.3.4', 'dead::1' ], 'list holds both bans' );

	$fw->unban( ban => '1.2.3.4' );
	is( $fw->{test_data}, 'shorewall allow 1.2.3.4', 'unban uses shorewall allow' );

	is_deeply( [ sort $fw->list ], ['dead::1'], 'list drops the unbanned ip' );
}

# type reject maps to the reject verb
{
	my $fw = Net::Firewall::BlockerHelper->new(
		backend => 'shorewall', name => 'ssh', testing => 1,
		options => { type => 'reject' },
	);
	$fw->init_backend;
	$fw->ban( ban => '9.9.9.9' );
	is( $fw->{test_data}, 'shorewall reject 9.9.9.9', 'type reject uses the reject verb' );
}

# an invalid type is fatal
{
	my $died = 0;
	eval {
		my $fw = Net::Firewall::BlockerHelper->new(
			backend => 'shorewall', name => 'ssh', testing => 1,
			options => { type => 'bogus' },
		);
		$fw->init_backend;
	};
	$died = 1 if ($@);
	ok( $died, 'invalid type is fatal' );
}

done_testing();
