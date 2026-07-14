#!perl
use 5.006;
use strict;
use warnings;
use Test::More;
use Data::Dumper;

BEGIN {
	use_ok('Net::Firewall::BlockerHelper') || print "Bail out!\n";
}

# --- testing mode: inspect the rendered file + reload without touching disk ---
{
	my $fw = Net::Firewall::BlockerHelper->new(
		backend => 'file_reload',
		name    => 'bl',
		testing => 1,
		options => {
			file   => '/etc/nginx/blocklist.conf',
			format => 'deny %%%BAN%%%;',
			reload => 'nginx -s reload',
		},
	);
	$fw->init_backend;

	is( $fw->{test_data}{file},    '/etc/nginx/blocklist.conf', 'init records the target file' );
	is( $fw->{test_data}{reload},  'nginx -s reload',           'init records the reload command' );
	is( $fw->{test_data}{content}, "\n", 'init renders an empty file' );

	$fw->ban( ban => '1.2.3.4' );
	is( $fw->{test_data}{content}, "deny 1.2.3.4;\n", 'ban renders the formatted line' );

	$fw->ban( ban => '5.6.7.8' );
	is( $fw->{test_data}{content}, "deny 1.2.3.4;\ndeny 5.6.7.8;\n", 'second ban renders both, sorted' );

	# re-banning is a no-op
	$fw->ban( ban => '1.2.3.4' );
	is( $fw->{test_data}, 'already banned', 're-banning reports already banned' );

	$fw->unban( ban => '1.2.3.4' );
	is( $fw->{test_data}{content}, "deny 5.6.7.8;\n", 'unban removes the line' );

	my @banned = $fw->list;
	is_deeply( [ sort @banned ], ['5.6.7.8'], 'list returns the remaining ban' );

	$fw->teardown;
	is( $fw->{test_data}{content}, undef, 'teardown signals file removal (content undef)' );
}

# --- header/footer wrapping ---
{
	my $fw = Net::Firewall::BlockerHelper->new(
		backend => 'file_reload',
		name    => 'bl',
		testing => 1,
		options => { file => '/tmp/x', header => '# managed', footer => '# end' },
	);
	$fw->init_backend;
	$fw->ban( ban => '9.9.9.9' );
	is( $fw->{test_data}{content}, "# managed\n9.9.9.9\n# end\n", 'header/footer wrap the ip list' );
}

# --- missing file option is fatal ---
{
	my $died = 0;
	eval {
		my $fw = Net::Firewall::BlockerHelper->new(
			backend => 'file_reload',
			name    => 'bl',
			testing => 1,
			options => {},
		);
		$fw->init_backend;
	};
	$died = 1 if ($@);
	ok( $died, 'a missing file option is fatal' );
}

done_testing();
