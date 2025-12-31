#!/usr/bin/env perl
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

# End of file.
