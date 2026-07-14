#!perl
use 5.006;
use strict;
use warnings;
use Test::More;

BEGIN {
	use_ok('Net::Firewall::BlockerHelper') || print "Bail out!\n";
}

# ban/unban render the network group's literals from state and PUT it
{
	my $fw = Net::Firewall::BlockerHelper->new(
		backend => 'cisco_fmc',
		name    => 'ssh',
		prefix  => 'kur',
		testing => 1,
		options => { host => 'fmc.ex', user => 'u', password => 'p', group_id => 'GID' },
	);
	$fw->init_backend;

	is( $fw->{test_data}[0]{method}, 'POST', 'init authenticates' );
	like( $fw->{test_data}[0]{url}, qr{/api/fmc_platform/v1/auth/generatetoken$}, 'init hits generatetoken' );
	ok( !defined( $fw->{test_data}[0]{content} ), 'init records no body (no credentials leaked)' );

	$fw->ban( ban => '1.2.3.4' );
	is( $fw->{test_data}[0]{method}, 'PUT', 'ban PUTs the group' );
	is( $fw->{test_data}[0]{url},
		'https://fmc.ex/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/networkgroups/GID',
		'ban targets the network group object' );
	is( $fw->{test_data}[0]{content}, '{"id":"GID","literals":[{"type":"Host","value":"1.2.3.4"}],"name":"kur_ssh"}',
		'group is rendered with the IP as a Host literal' );

	$fw->ban( ban => '5.6.7.8' );
	like( $fw->{test_data}[0]{content}, qr/"value":"1\.2\.3\.4".*"value":"5\.6\.7\.8"/,
		'second ban renders both literals' );

	$fw->unban( ban => '1.2.3.4' );
	unlike( $fw->{test_data}[0]{content}, qr/1\.2\.3\.4/, 'unban drops that literal' );
}

# host/user/password/group_id are all required
for my $missing (qw(host user password group_id)) {
	my %opts = ( host => 'h', user => 'u', password => 'p', group_id => 'g' );
	delete $opts{$missing};
	my $died = 0;
	eval {
		my $fw = Net::Firewall::BlockerHelper->new(
			backend => 'cisco_fmc', name => 'ssh', testing => 1, options => \%opts,
		);
		$fw->init_backend;
	};
	$died = 1 if ($@);
	ok( $died, "missing $missing is fatal" );
}

done_testing();
