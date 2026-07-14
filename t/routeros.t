#!perl
use 5.006;
use strict;
use warnings;
use Test::More;

BEGIN {
	use_ok('Net::Firewall::BlockerHelper') || print "Bail out!\n";
}

# ban/unban emit RouterOS address-list commands over ssh, split by family
{
	my $fw = Net::Firewall::BlockerHelper->new(
		backend => 'routeros',
		name    => 'ssh',
		prefix  => 'kur',
		testing => 1,
		options => { host => '10.0.0.1', user => 'admin' },
	);
	$fw->init_backend;

	like( $fw->{test_data}[0], qr{/ip firewall filter add .*src-address-list=kur_ssh action=drop},
		'init adds the IPv4 filter rule referencing the address-list' );
	like( $fw->{test_data}[1], qr{/ipv6 firewall filter add .*src-address-list=kur_ssh},
		'init adds the IPv6 filter rule' );

	$fw->ban( ban => '1.2.3.4' );
	is( $fw->{test_data},
		"ssh admin\@10.0.0.1 '/ip firewall address-list add list=kur_ssh address=1.2.3.4'",
		'IPv4 ban adds to /ip address-list' );

	$fw->ban( ban => 'dead::1' );
	like( $fw->{test_data}, qr{/ipv6 firewall address-list add list=kur_ssh address=dead::1},
		'IPv6 ban adds to /ipv6 address-list' );

	$fw->unban( ban => '1.2.3.4' );
	like( $fw->{test_data}, qr{/ip firewall address-list remove \[find where list=kur_ssh address=1\.2\.3\.4\]},
		'unban removes the matching address-list entry' );
}

# host is required
{
	my $died = 0;
	eval {
		my $fw = Net::Firewall::BlockerHelper->new(
			backend => 'routeros', name => 'ssh', testing => 1, options => {},
		);
		$fw->init_backend;
	};
	$died = 1 if ($@);
	ok( $died, 'missing host is fatal' );
}

done_testing();
