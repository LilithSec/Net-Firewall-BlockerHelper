#!perl
use 5.006;
use strict;
use warnings;
use Test::More;

BEGIN {
	use_ok('Net::Firewall::BlockerHelper') || print "Bail out!\n";
}

# ban creates an ACL entry via POST, unban does a GET-then-DELETE
{
	my $fw = Net::Firewall::BlockerHelper->new(
		backend => 'fastly',
		name    => 'ssh',
		prefix  => 'kur',
		testing => 1,
		options => { token => 'TOK', service => 'SID', acl => 'AID' },
	);
	$fw->init_backend;

	is( $fw->{test_data}[0]{method}, 'GET', 'init probes the entries with a GET' );
	is( $fw->{test_data}[0]{url},
		'https://api.fastly.com/service/SID/acl/AID/entries?per_page=1',
		'init fetches a single ACL entry' );

	$fw->ban( ban => '1.2.3.4' );
	is( scalar( @{ $fw->{test_data} } ), 1, 'ban is a single request' );
	is( $fw->{test_data}[0]{method}, 'POST', 'ban does a POST' );
	is( $fw->{test_data}[0]{url}, 'https://api.fastly.com/service/SID/acl/AID/entry',
		'ban posts to the entry endpoint' );
	is( $fw->{test_data}[0]{content}, '{"ip":"1.2.3.4","subnet":32}',
		'IPv4 ban body has the ip and a /32 subnet' );

	$fw->ban( ban => 'dead::1' );
	is( $fw->{test_data}[0]{method}, 'POST', 'IPv6 ban does a POST' );
	is( $fw->{test_data}[0]{content}, '{"ip":"dead::1","subnet":128}',
		'IPv6 ban body uses subnet 128' );

	$fw->unban( ban => '1.2.3.4' );
	is( scalar( @{ $fw->{test_data} } ), 2, 'unban is two requests' );
	is( $fw->{test_data}[0]{method}, 'GET', 'unban first looks up the entries with a GET' );
	is( $fw->{test_data}[0]{url}, 'https://api.fastly.com/service/SID/acl/AID/entries',
		'unban GET hits the entries endpoint' );
	is( $fw->{test_data}[1]{method}, 'DELETE', 'unban then deletes' );
	is( $fw->{test_data}[1]{url}, 'https://api.fastly.com/service/SID/acl/AID/entry/<id>',
		'unban DELETE targets the entry by id' );
}

# token, service, and acl are each required
for my $missing (qw(token service acl)) {
	my %opts = ( token => 'TOK', service => 'SID', acl => 'AID' );
	delete $opts{$missing};
	my $died = 0;
	eval {
		my $fw = Net::Firewall::BlockerHelper->new(
			backend => 'fastly', name => 'ssh', testing => 1, options => \%opts,
		);
		$fw->init_backend;
	};
	$died = 1 if ($@);
	ok( $died, "missing $missing is fatal" );
}

done_testing();
