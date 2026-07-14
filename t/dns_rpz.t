#!perl
use 5.006;
use strict;
use warnings;
use Test::More;

BEGIN {
	use_ok('Net::Firewall::BlockerHelper') || print "Bail out!\n";
}

# ban/unban run nsupdate adding/removing an rpz-client-ip record
{
	my $fw = Net::Firewall::BlockerHelper->new(
		backend => 'dns_rpz',
		name    => 'r',
		testing => 1,
		options => { zone => 'rpz.example.org', keyfile => '/etc/rpz.key' },
	);
	$fw->init_backend;

	$fw->ban( ban => '1.2.3.4' );
	like( $fw->{test_data},
		qr{update add 32\.4\.3\.2\.1\.rpz-client-ip\.rpz\.example\.org 60 IN CNAME \.},
		'IPv4 ban adds a reversed rpz-client-ip record' );
	like( $fw->{test_data}, qr{\| nsupdate -k '/etc/rpz\.key'}, 'piped into nsupdate with the keyfile' );

	$fw->ban( ban => '2001:db8::1' );
	like( $fw->{test_data},
		qr{update add 128\.1\.zz\.db8\.2001\.rpz-client-ip\.rpz\.example\.org},
		'IPv6 ban uses the RPZ IPv6 encoding with zz' );

	$fw->unban( ban => '1.2.3.4' );
	like( $fw->{test_data},
		qr{update delete 32\.4\.3\.2\.1\.rpz-client-ip\.rpz\.example\.org IN CNAME \.},
		'unban deletes the record' );
}

# the ip trigger and a server line
{
	my $fw = Net::Firewall::BlockerHelper->new(
		backend => 'dns_rpz', name => 'r', testing => 1,
		options => { zone => 'z', keyfile => '/k', trigger => 'ip', server => '10.0.0.1' },
	);
	$fw->init_backend;
	$fw->ban( ban => '1.2.3.4' );
	like( $fw->{test_data}, qr{32\.4\.3\.2\.1\.rpz-ip\.z}, 'trigger ip uses rpz-ip' );
	like( $fw->{test_data}, qr{printf 'server 10\.0\.0\.1\\nzone z}, 'server line prepended' );
}

# zone and keyfile are required
for my $missing (qw(zone keyfile)) {
	my %opts = ( zone => 'z', keyfile => '/k' );
	delete $opts{$missing};
	my $died = 0;
	eval {
		my $fw = Net::Firewall::BlockerHelper->new(
			backend => 'dns_rpz', name => 'r', testing => 1, options => \%opts,
		);
		$fw->init_backend;
	};
	$died = 1 if ($@);
	ok( $died, "missing $missing is fatal" );
}

# an invalid trigger is fatal
{
	my $died = 0;
	eval {
		my $fw = Net::Firewall::BlockerHelper->new(
			backend => 'dns_rpz', name => 'r', testing => 1,
			options => { zone => 'z', keyfile => '/k', trigger => 'nsip' },
		);
		$fw->init_backend;
	};
	$died = 1 if ($@);
	ok( $died, 'an invalid trigger is fatal' );
}

done_testing();
