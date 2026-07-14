#!perl
use 5.006;
use strict;
use warnings;
use Test::More;

BEGIN {
	use_ok('Net::Firewall::BlockerHelper') || print "Bail out!\n";
}

# ban/unban drive the OPNsense alias_util API via curl
{
	my $fw = Net::Firewall::BlockerHelper->new(
		backend => 'opnsense',
		name    => 'bl',
		prefix  => 'kur',
		testing => 1,
		options => { host => 'fw.example:8443', key => 'K', secret => 'S', insecure => 1 },
	);
	$fw->init_backend;

	like( $fw->{test_data}[0], qr{alias_util/list/kur_bl}, 'init verifies the alias via list' );
	like( $fw->{test_data}[0], qr{-u 'K:S'},               'credentials passed to curl' );
	like( $fw->{test_data}[0], qr{(?<!\S)-k(?!\S)},        'insecure adds -k' );

	$fw->ban( ban => '1.2.3.4' );
	like( $fw->{test_data}[0], qr{alias_util/add/kur_bl},          'ban posts to alias_util/add' );
	like( $fw->{test_data}[0], qr{-d '\{"address":"1\.2\.3\.4"\}'}, 'ban body carries the ip' );

	$fw->unban( ban => '1.2.3.4' );
	like( $fw->{test_data}[0], qr{alias_util/delete/kur_bl}, 'unban posts to alias_util/delete' );
}

# host/key/secret are all required
for my $missing (qw(host key secret)) {
	my %opts = ( host => 'h', key => 'k', secret => 's' );
	delete $opts{$missing};
	my $died = 0;
	eval {
		my $fw = Net::Firewall::BlockerHelper->new(
			backend => 'opnsense', name => 'bl', testing => 1, options => \%opts,
		);
		$fw->init_backend;
	};
	$died = 1 if ($@);
	ok( $died, "missing $missing is fatal" );
}

done_testing();
