#!perl
use 5.006;
use strict;
use warnings;
use Test::More;
use Rex::CMDB;
use Rex -feature => [qw/1.4/];
use Data::Dumper;

# prevents Rex from printing out rex is exiting after the script ends
$::QUIET = 2;

BEGIN {
	use_ok('Net::Firewall::BlockerHelper') || print "Bail out!\n";
}

my $worked = 0;
eval {
	my $fw_helper = Net::Firewall::BlockerHelper->new(
		backend   => 'ipfw',
		ports     => [ '22', 'ssh' ],
		protocols => ['tcp'],
		prefix    => 'derp',
		name      => 'ssh',
	);

	eval {
		$fw_helper = Net::Firewall::BlockerHelper->new(
			backend   => 'ipfw',
			ports     => ['22'],
			protocols => [ 'tcp', 'thisisinvalid_derp' ],
			prefix    => 'derp',
			name      => 'ssh',
		);
	};
	if ( !$@ ) {
		die('new accepts invalid protocols names');
	}

	eval {
		$fw_helper = Net::Firewall::BlockerHelper->new(
			backend   => 'ipfw',
			ports     => ['22'],
			protocols => [ 'tcp', '' ],
			prefix    => 'derp',
			name      => 'ssh',
		);
	};
	if ( !$@ ) {
		die('new accepts blank names');
	}

	eval {
		$fw_helper = Net::Firewall::BlockerHelper->new(
			backend   => 'ipfw',
			ports     => [ '22', 'thisisinvalid' ],
			protocols => ['tcp'],
			prefix    => 'derp',
			name      => 'ssh',
		);
	};
	if ( !$@ ) {
		die('new accepts invalid ports names');
	}

	eval {
		$fw_helper = Net::Firewall::BlockerHelper->new(
			backend   => 'ipfw',
			ports     => [ '22', '' ],
			protocols => ['tcp'],
			prefix    => 'derp',
			name      => 'ssh',
		);
	};
	if ( !$@ ) {
		die('new accepts empty port names');
	}

	eval {
		$fw_helper = Net::Firewall::BlockerHelper->new(
			backend   => undef,
			ports     => ['22'],
			protocols => ['tcp'],
			prefix    => 'derp',
			name      => 'ssh',
		);
	};
	if ( !$@ ) {
		die('new accepts undef backend');
	}

	eval {
		$fw_helper = Net::Firewall::BlockerHelper->new(
			backend   => 'ipfw',
			ports     => ['22'],
			protocols => ['tcp'],
			prefix    => '',
			name      => 'ssh',
		);
	};
	if ( !$@ ) {
		die('new accepts prefix as being blank');
	}

	eval {
		$fw_helper = Net::Firewall::BlockerHelper->new(
			backend   => 'ipfw',
			ports     => ['22'],
			protocols => ['tcp'],
			prefix    => ' derp',
			name      => 'ssh',
		);
	};
	if ( !$@ ) {
		die('new accepts prefix as being invalid');
	}

	eval {
		$fw_helper = Net::Firewall::BlockerHelper->new(
			backend   => 'ipfw',
			ports     => ['22'],
			protocols => ['tcp'],
			prefix    => 'derp',
			name      => '',
		);
	};
	if ( !$@ ) {
		die('new accepts name as being blank');
	}

	eval {
		$fw_helper = Net::Firewall::BlockerHelper->new(
			backend   => 'ipfw',
			ports     => ['22'],
			protocols => ['tcp'],
			prefix    => 'derp',
			name      => ' ssh',
		);
	};
	if ( !$@ ) {
		die('new accepts name as being invalid');
	}

	eval {
		$fw_helper = Net::Firewall::BlockerHelper->new(
			backend   => 'ipfw',
			ports     => [],
			protocols => ['tcp'],
			prefix    => 'derp',
			name      => 'ssh',
		);
	};
	if ($@) {
		die( 'new dies with empty array for ports... ' . $@ );
	}

	eval {
		$fw_helper = Net::Firewall::BlockerHelper->new(
			backend   => 'ipfw',
			ports     => ['22'],
			protocols => [],
			prefix    => 'derp',
			name      => 'ssh',
		);
	};
	if ($@) {
		die( 'new dies with empty array for protocols... ' . $@ );
	}

	eval {
		$fw_helper = Net::Firewall::BlockerHelper->new(
			backend   => 'ipfw',
			ports     => ['22'],
			protocols => ['tcp'],
			prefix    => undef,
			name      => 'ssh',
		);
	};
	if ($@) {
		die( 'new dies when prefix is undef... ' . $@ );
	}

	eval {
		$fw_helper = Net::Firewall::BlockerHelper->new(
			backend   => 'ipfw',
			ports     => ['22'],
			protocols => ['tcp'],
			prefix    => 'derp',
			name      => undef,
		);
	};
	if ( !$@ ) {
		die( 'new does not die when name is undef... ' . $@ );
	}

	$worked = 1;
};
ok( $worked eq '1', 'new test' ) or diag( "new test died with ... " . $@ );

done_testing(2);
