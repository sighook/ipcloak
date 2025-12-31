#!/usr/bin/perl
use strict;
use warnings;
use Socket;

# --- Parse arguments ---
my ($ip, $prefix, $postfix) = @ARGV;
die "Usage: $0 <ip> [prefix] [postfix]\n" unless $ip;

# --- Validate and unpack IP ---
my $packed = inet_aton($ip) or die "Invalid IP address\n";
my $dword  = unpack("N", $packed);
my @octets = unpack("C4", $packed);

# --- Collapsed forms ---

# last two octets
my $u16 = ($octets[2] << 8) | $octets[3];
# last three octets
my $u24 = ($octets[1] << 16) | ($octets[2] << 8) | $octets[3];

# --- Format registry ---
my @formats = (
	# Whole-address integer forms
	sub { sprintf "%u", $dword },
	sub { sprintf "0x%X", $dword },
	sub { sprintf "0%o", $dword },

	# Octet forms
	sub { sprintf "0x%02X.0x%02X.0x%02X.0x%02X", @octets },
	sub { sprintf "%04o.%04o.%04o.%04o", @octets },
	sub { sprintf "0x%010X.0x%010X.0x%010X.0x%010X", @octets },
	sub { sprintf "%010o.%010o.%010o.%010o", @octets },

	# Mixed hex/dec hybrids
	sub { sprintf "0x%02X.0x%02X.0x%02X.%i",
		$octets[0], $octets[1], $octets[2], $octets[3] },
	sub { sprintf "0x%02X.0x%02X.%i.%i",
		$octets[0], $octets[1], $octets[2], $octets[3] },
	sub { sprintf "0x%02X.%i.%i.%i",
		$octets[0], $octets[1], $octets[2], $octets[3] },

	# Mixed oct/dec hybrids
	sub { sprintf "%04o.%04o.%04o.%i",
		$octets[0], $octets[1], $octets[2], $octets[3] },
	sub { sprintf "%04o.%04o.%i.%i",
		$octets[0], $octets[1], $octets[2], $octets[3] },
	sub { sprintf "%04o.%i.%i.%i",
		$octets[0], $octets[1], $octets[2], $octets[3] },

	# Two-octet prefix + last two collapsed (u16)
	sub { sprintf "0x%02X.0x%02X.%i",
		$octets[0], $octets[1], $u16 },
	sub { sprintf "%04o.%04o.%i",
		$octets[0], $octets[1], $u16 },
	sub { sprintf "0x%02X.%04o.%i",
		$octets[0], $octets[1], $u16 },

	# One-octet prefix + last three collapsed (u24)
	sub { sprintf "0x%02X.%i",
		$octets[0], $u24 },
	sub { sprintf "%04o.%i",
		$octets[0], $u24 },

	# Mixed padded hybrids
	sub { sprintf "0x%02X.0x%02X.%04o.%04o",
		$octets[0], $octets[1], $octets[2], $octets[3] },
	sub { sprintf "0x%02X.%04o.%04o.%04o",
		$octets[0], $octets[1], $octets[2], $octets[3] },
	sub { sprintf "0x%02X.%04o.%i",
		$octets[0], $octets[1], $u16 },
);

# --- Print all formats ---
foreach my $fmt (@formats) {
	print($prefix // "");
	print $fmt->();
	print($postfix // "");
	print "\n";
}

__END__

=head1 NAME

ipcloak - cloak IPv4 addresses in alternate forms

=head1 SYNOPSIS

B<ipcloak> <ip> [prefix] [postfix]

=head1 DESCRIPTION

ipcloak takes an IPv4 address and cloaks it in multiple alternate
representations: decimal, hexadecimal, octal, and hybrid forms.
These disguises demonstrate how legacy parsers accept non-canonical
encodings, useful for penetration testing, demonstrations, and
filter-evasion research.

=head1 OPTIONS

=over 4

=item B<prefix>

Optional string printed before each cloaked output.

=item B<postfix>

Optional string printed after each cloaked output.

=back

=head1 FORMATS

Implemented forms:

=over 2

=item * Decimal integer

Whole 32-bit address as a single decimal number.

Example: 2130706433

=item * Hex integer

Whole 32-bit address as a single hexadecimal number.

Example: 0x7F000001

=item * Octal integer

Whole 32-bit address as a single octal number.

Example: 017700000001

=item * Per-octet hex/octal

Each octet rendered individually in hex or octal.

Example: 0x7F.0x00.0x00.0x01, 0177.0000.0000.0001

=item * Padded hybrids

Octets padded with leading zeros in hex or octal.

Example: 0x000000007F.0x0000000000.0x0000000000.0x0000000001

=item * Collapsed hybrids

Last two or three octets collapsed into a single integer (u16/u24).

Example: 0x7F.0x00.256, 0x7F.65536

=item * Mixed hybrids

Combinations of hex, octal, and decimal across octets.

Example: 0x7F.0x00.1, 0177.0.0.1

=back

=head1 FUTURE CLOAKS

Beyond the current forms, additional cloaks can be added to
improve bypassing and filter evasion.
These are not yet implemented, but documented here for roadmap
clarity:

=over 2

=item * IPv6-mapped IPv4

Represent IPv4 inside IPv6 notation.

Example: ::ffff:127.0.0.1

Many stacks normalize IPv6-mapped addresses back to IPv4, bypassing
filters that only check dotted-quad notation.

=item * Mixed-case hex

Accept both lowercase and uppercase hex prefixes.

Example: 0X7F000001

Case-insensitive parsers accept both, but regex filters often only
match lowercase "0x".

=item * Split dword forms

Break the 32-bit integer into two or more hex parts.

Example: 0x7F.0x00000001

Some parsers treat split integers as valid, confusing filters
expecting a single token.

=item * Whitespace padding

Addresses with trailing or leading spaces.

Example: "127.0.0.1 "

Lenient parsers trim whitespace, but filters may fail to normalize,
allowing bypass.

=item * Comment injection

Addresses with inline comments.

Example: 127.0.0.1/*foo*/

Regex-based filters often ignore comments, while parsers still resolve
the address.

=item * XOR-encoded cloaks

Obfuscate the dword with a key, then print the encoded integer.

Example (XOR key 0xFF): 2147483646

Used in shellcode obfuscation to reduce entropy and evade
signature-based detection.

=item * Array cloaks

Represent the IP as a sequence of smaller IPs or integers.

Example: [127.0.0.1, 0.0.0.0]

Payload formed as multiple IPs can slip past filters expecting a
single canonical address.

=item * IPv6 short forms

Compressed IPv6 notation that still resolves to IPv4.

Example: ::7f00:1

IPv6 compression rules allow multiple equivalent encodings, confusing
simplistic validators.

=item * Overlong padded hex

Addresses padded with excessive leading zeros.

Example: 0x0000000000000000007F000001

Parsers accept padded hex, but filters may not normalize, enabling
bypass.

=back

=head1 EXTENDING

To add new cloaks, define a subroutine that returns a string
representation of the IP, then register it in @formats.

=head1 COLLAPSED FORMS

Some cloaks collapse octets into larger integers:

=over 2

=item * u16 = (octet3 << 8) | octet4

=item * u24 = (octet2 << 16) | (octet3 << 8) | octet4

=back

These match the original C program's "collapsed hybrid" outputs.

=head1 EXAMPLES

  ipcloak 127.0.0.1
  ipcloak 192.168.100.1 "[" "]"

=head1 SEE ALSO

inet_aton(3), inet_pton(3), RFC 791.

=head1 BUGS

Only IPv4 addresses are supported.
IPv6 cloaking is not implemented.

=head1 HISTORY

Derived from IPObfuscator by Osanda Malith Jayathissa.
Original repository: L<https://github.com/OsandaMalith/IPObfuscator>

=head1 AUTHOR

C implementation by Osanda Malith and 1lastBr3ath.
Perl refactor by Alexandr Savca.

=head1 COPYRIGHT AND LICENSE

This work is based on IPObfuscator by Osanda Malith Jayathissa
(http://osandamalith.wordpress.com).

Licensed under the Creative Commons Attribution-NonCommercial-ShareAlike
4.0 International License (CC BY-NC-SA 4.0).
See: L<http://creativecommons.org/licenses/by-nc-sa/4.0/>

ipcloak is distributed under the same license.
You may share and adapt under the following conditions:

=over

=item - Provide attribution to the original author(s).

=item - NonCommercial use only.

=item - ShareAlike: distribute adaptations under the same license.

=back

=cut
