#!perl
use 5.006;
use strict;
use warnings;
use Test::More;

BEGIN {
	use_ok('Net::Firewall::BlockerHelper')                     || print "Bail out!\n";
	use_ok('Net::Firewall::BlockerHelper::backends::nsupdate') || print "Bail out!\n";
}

my $fw = Net::Firewall::BlockerHelper->new(
	backend => 'nsupdate',
	name    => 'ssh',
	options => { domain => 'rbl.foo.bar', keyfile => '/etc/nsupdate.key' },
	testing => 1,
);
$fw->init_backend;
is( $fw->{test_data}, 'inited', 'init needs no commands in testing mode' );

$fw->ban( ban => '1.2.3.4' );
is_deeply(
	$fw->{test_data},
	[
		      "printf 'prereq nxrrset 4.3.2.1.rbl.foo.bar TXT\\n"
			. 'update add 4.3.2.1.rbl.foo.bar 60 IN TXT "banned"' . "\\n"
			. "send\\n' | nsupdate -k '/etc/nsupdate.key'"
	],
	'ban adds a TXT record at the reversed-octet name'
);

$fw->ban( ban => '1.2.3.4' );
is( $fw->{test_data}, 'already banned', 'double ban short-circuits' );

$fw->unban( ban => '1.2.3.4' );
is( $fw->{test_data},
	"printf 'update delete 4.3.2.1.rbl.foo.bar TXT\\nsend\\n' | nsupdate -k '/etc/nsupdate.key'",
	'unban deletes the TXT record' );

is( $fw->check, 1, 'check always reports healthy' );

$fw->ban( ban => '5.6.7.8' );
$fw->re_init;
like( $fw->{test_data}[0], qr/8\.7\.6\.5\.rbl\.foo\.bar/, 're_init re-adds the remaining ban' );

$fw->teardown;
like( $fw->{test_data}[0], qr/^printf 'update delete 8\.7\.6\.5\.rbl\.foo\.bar TXT/, 'teardown deletes the records' );
is( scalar( $fw->list ), 1, 'teardown keeps the ban list for re_init' );

# re-arm the same backend object so the kept ban list is exercised
$fw->{backend_obj}->init;
$fw->flush;
is( scalar( $fw->list ), 0, 'flush empties the ban list' );

# --- IPv6 is rejected --------------------------------------------------------------
{
	my $fw2 = Net::Firewall::BlockerHelper->new(
		backend => 'nsupdate',
		name    => 'ssh',
		options => { domain => 'rbl.foo.bar', keyfile => '/etc/nsupdate.key' },
		testing => 1,
	);
	$fw2->init_backend;
	local $@;
	eval { $fw2->ban( ban => 'dead::1' ); };
	ok( $@, 'banning an IPv6 IP errors' );
	is( $fw2->error, 13, 'the frontend wraps it as banFailed' );
}

# --- options ------------------------------------------------------------------------
{
	my $fw2 = Net::Firewall::BlockerHelper->new(
		backend => 'nsupdate',
		name    => 'ssh',
		options => {
			domain   => 'rbl.foo.bar',
			keyfile  => '/etc/nsupdate.key',
			ttl      => 300,
			rdata    => 'go away',
			nsupdate => '/usr/local/bin/nsupdate',
		},
		testing => 1,
	);
	$fw2->init_backend;
	$fw2->ban( ban => '1.2.3.4' );
	like( $fw2->{test_data}[0], qr/300 IN TXT "go away"/,        'ttl and rdata options are used' );
	like( $fw2->{test_data}[0], qr/\| \/usr\/local\/bin\/nsupdate /, 'the nsupdate option is used' );
}

# --- validation, on the backend directly as that is where these are checked ---------
{
	local $@;
	eval { Net::Firewall::BlockerHelper::backends::nsupdate->new( name => 'ssh', options => { keyfile => '/etc/k' } ); };
	ok( $@, 'a missing domain errors' );
	is( $Error::Helper::error, 28, 'missing domain raises error 28' );

	eval {
		Net::Firewall::BlockerHelper::backends::nsupdate->new(
			name    => 'ssh',
			options => { domain => 'rbl.foo.bar', keyfile => "/etc/bad'file" }
		);
	};
	ok( $@, 'a keyfile with a single quote errors' );

	eval {
		Net::Firewall::BlockerHelper::backends::nsupdate->new(
			name    => 'ssh',
			ports   => ['22'],
			options => { domain => 'rbl.foo.bar', keyfile => '/etc/k' }
		);
	};
	ok( $@, 'ports error as unsupported' );
}

done_testing();
