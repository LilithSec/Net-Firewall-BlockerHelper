package Net::Firewall::BlockerHelper::Util;

use 5.006;
use strict;
use warnings;
use Regexp::IPv4 qw($IPv4_re);
use Regexp::IPv6 qw($IPv6_re);

=head1 NAME

Net::Firewall::BlockerHelper::Util - Shared internal helpers mixed into the frontend and backends.

=head1 VERSION

Version 0.1.0

=cut

our $VERSION = '0.1.0';

=head1 SYNOPSIS

This module is not used directly. It is a stateless mixin holding the internal
helpers that would otherwise be copy/pasted into every backend. Both
L<Net::Firewall::BlockerHelper> and each backend under
L<Net::Firewall::BlockerHelper>::backends inherit from it alongside
L<Error::Helper>.

    package Net::Firewall::BlockerHelper::backends::foo;

    use base qw( Error::Helper Net::Firewall::BlockerHelper::Util );

    # ...

    sub ban_cidr {
        my ( $self, %opts ) = @_;

        if ( !$self->_valid_cidr( $opts{ban} ) ) {
            # ... raise error 26 ...
        }
    }

=head1 DESCRIPTION

Everything here is an internal helper and carries a leading underscore. None of
it is part of the public API and none of it is expected to be called from
outside of the frontend or a backend. There is no constructor and no state is
kept; the methods only exist here so that a single definition is shared instead
of being duplicated per backend.

=cut

# Internal helper. Tests whether a scalar is a syntactically valid IPv4 or IPv6
# CIDR range. This is the validation used by ban_cidr, unban_cidr, and the
# frontend before a range is handed to a backend, so that a malformed range is
# rejected with an error rather than being pasted into a firewall command.
#
# A valid range is an address, a literal "/", and a decimal prefix length that
# is within the range allowed for the address family. The address is matched
# against $IPv4_re from Regexp::IPv4 and $IPv6_re from Regexp::IPv6, anchored,
# so a bare address with no "/" is not valid and neither is a range with any
# leading or trailing whitespace. The prefix length must be one to three digits
# and be 0 to 32 for IPv4 or 0 to 128 for IPv6. The prefix is not required to
# be the canonical network address for the range, so "10.0.0.1/8" is accepted
# as valid; masking off the host bits, if wanted, is left to the backend.
#
# Args:
#
#     cidr - The scalar to test. Any value may be passed. Undef, a reference of
#            any kind, and a string that does not match the format above are
#            all simply not valid rather than fatal.
#
# Returns 1 if the scalar is a valid IPv4 or IPv6 CIDR range and 0 if it is
# not. The return is always one of those two values and is never undef, so it
# is safe to use directly in a boolean test or to store as a flag.
#
#     $self->_valid_cidr('10.0.0.0/8');           # 1
#     $self->_valid_cidr('2001:db8::/32');        # 1
#     $self->_valid_cidr('10.0.0.1/8');           # 1, host bits are allowed
#
#     $self->_valid_cidr('10.0.0.0/33');          # 0, prefix too large for v4
#     $self->_valid_cidr('2001:db8::/129');       # 0, prefix too large for v6
#     $self->_valid_cidr('10.0.0.0');             # 0, no prefix
#     $self->_valid_cidr('not an address/8');     # 0, address does not match
#     $self->_valid_cidr( [ '10.0.0.0/8' ] );     # 0, a reference
#     $self->_valid_cidr(undef);                  # 0
sub _valid_cidr {
	my ( $self, $cidr ) = @_;

	return 0 if ( !defined($cidr) || ref($cidr) ne '' );

	if ( $cidr =~ m!\A(.+)/([0-9]{1,3})\z! ) {
		my ( $addr, $prefix ) = ( $1, $2 );
		return 1 if ( $addr =~ /\A$IPv4_re\z/ && $prefix <= 32 );
		return 1 if ( $addr =~ /\A$IPv6_re\z/ && $prefix <= 128 );
	}

	return 0;
} ## end sub _valid_cidr

=head1 AUTHOR

Zane C. Bowers-Hadley, C<< <vvelox at vvelox.ent> >>

=head1 BUGS

Please report any bugs or feature requests to C<bug-net-firewall-blockerhelper at rt.cpan.org>, or through
the web interface at L<https://rt.cpan.org/NoAuth/ReportBug.html?Queue=Net-Firewall-BlockerHelper>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.




=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc Net::Firewall::BlockerHelper


You can also look for information at:

=over 4

=item * RT: CPAN's request tracker (report bugs here)

L<https://rt.cpan.org/NoAuth/Bugs.html?Dist=Net-Firewall-BlockerHelper>

=item * Search CPAN

L<https://metacpan.org/release/Net-Firewall-BlockerHelper>

=back


=head1 ACKNOWLEDGEMENTS


=head1 LICENSE AND COPYRIGHT

This software is Copyright (c) 2023 by Zane C. Bowers-Hadley.

This is free software, licensed under:

  The GNU Lesser General Public License, Version 2.1, February 1999


=cut

1;    # End of Net::Firewall::BlockerHelper::Util
