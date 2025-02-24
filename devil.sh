#!/bin/bash
# TODO For Hardening
# Shellc to convert this to a binary
# Static build of osslsigncode packaged with this binary
# Static build of busybox for POSIX shell tampering protection
# Static build of perl or refactor to bash/c for the extract-module-script
set -u
# String list of the GPUs the system is supposed to have
EXPECTED_GPUS=
# works on debian 12
function secure_boot_check() {
    # 2 methods, kernel log & EFI vars
    # same on all distros
    secure_boot_var_file=/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c
    secureboot_efivar=$(od --address-radix=n --format=u1 $secure_boot_var_file | cut -c20-)
    if [[ $secureboot_efivar -ne 1 ]]; then
       echo "Test Failed Secure Boot not enabled"
    fi
    
    if ! dmesg | grep "Secure Boot"; then
       echo "Test Failed: System not booted with secure-boot capable kernel"
    fi

}
# modinfo isn't used here because busybox modinfo doesn't support signature signing :(
function kernel_mod_sig_check() {
    for module in $(lsmod | awk 'NR>1 {print $1}'); do
        # using find for later because modinfo is comically easy to compromise
        file_path=$(find /lib/modules/$(uname -r)/ -name "$module.ko")
        if [[ $file_path == "" ]]; then
            echo "Error module not found most likely tampering"
            return 1
        fi
        if ! dpkg -S "$file_path"; then
            echo "Module not from dpkg"
            return 1
        fi
        # might want to refactor this script later
        perl /tmp/extract-kernel-sig.pl -s $file_path > /tmp/$module-sig.bin
        perl /tmp/extract-kernel-sig.pl -0 $file_path > /tmp/$module-unsigned.ko
        openssl cms -verify -in /tmp/$module-sig.bin -content /tmp/$module-unsigned.ko -inform PEM -CAfile /tmp/debian-uefi.pem
     
    done
     
      
   
}
function kernel_image_sig_check() {
	if ! osslsigncode verify -in /boot/$(uname -r) -CAfile /tmp/debian-uefi.pem; then
		echo "Kernel image failed signature check"
		return 1
	fi

}
function vbios_check() {
    # not here for now because if they can fake the pci-id they are already faking the vbios.
    return
}
function pciid_check() { 
    # This is how most software detects what GPU is in use
    vga_ids=$(lspci -ns  $(lspci | grep VGA | awk '{print $1}') | awk '{print $3}')
    # get what gpu we expect from the ids
    for id in "$vga_ids"; do
        ID_LINE=$(echo "$GLOBAL_IDS" | grep $id)
        if ! echo "$GLOBAL_IDS" | grep $id; then
            echo "ID $id not recognized"
            return 1
        fi
        NAME=$(awk '{print $2}' <<< $ID_LINE)
        EXPECTED_GPUS+="$NAME "
    done
}

function vm_check() {
  # Check for hypervisor output in kernel log
	if dmesg | grep -q "hypervisor" || dmesg | grep -q "KVM" || dmesg | grep -q "Xen" || dmesg | grep -q "VMware"; then
    	echo "Hypervisor signatures found in kernel log."
    	return 1
  	fi

  # Check for VFIO kernel module
  	if lsmod | grep -q "vfio"; then
    	echo "VFIO kernel module loaded."
    	return 1
  	fi

	# CPU Frequency Check
	# VMs (especially qemu) cannot emulate CPU frequency scaling (i.e Turbo Boost)
	# since it has been a feature on all processors post 2005, we can check for 
	# it to see if the user is using a VM.
	cpu_freq_start=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq)
	# need to build a statically linked copy of this or find some other way to stress the system
	stress --cpu 1 --dry-run &
	stress_pid=$!
	sleep 1

	cpu_freq_end=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq)

	if [[ -z "$cpu_freq_start" || -z "$cpu_freq_end" ]]; then
		echo "Could not read CPU frequency."
		return 1 # Treat as potential VM as we cannot check
	fi


	freq_diff=$(( (cpu_freq_end - cpu_freq_start) * 100 / cpu_freq_start ))

	if (( freq_diff > 5 || freq_diff < -5 )); then
		return 0  # Not a VM frequency changed significantly
	else
		echo "CPU frequency change within acceptable range ($freq_diff%). This suggests a potential VM."
		return 1  # Is a vm
	fi
}

#Remove any that exist
rm -f /tmp/debian-uefi.pem

# Temp files
# from https://wiki.debian.org/SecureBoot

cat > /tmp/debian-uefi.pem << EOF
-----BEGIN CERTIFICATE-----
MIIDnjCCAoagAwIBAgIRAO1UodWvh0iUjZ+JMu6cfDQwDQYJKoZIhvcNAQELBQAw
IDEeMBwGA1UEAxMVRGViaWFuIFNlY3VyZSBCb290IENBMB4XDTE2MDgxNjE4MDkx
OFoXDTQ2MDgwOTE4MDkxOFowIDEeMBwGA1UEAxMVRGViaWFuIFNlY3VyZSBCb290
IENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnZXUi5vaEKwuyoI3
waTLSsMbQpPCeinTbt1kr4Cv6maiG2GcgwzFa7k1Jf/F++gpQ97OSz3GEk2x7yZD
lWjNBBH+wiSb3hTYhlHoOEO9sZoV5Qhr+FRQi7NLX/wU5DVQfAux4gOEqDZI5IDo
6p/6v8UYe17OHL4sgHhJNRXAIc/vZtWKlggrZi9IF7Hn7IKPB+bK4F9xJDlQCo7R
cihQpZ0h9ONhugkDZsjfTiY2CxUPYx8rr6vEKKJWZIWNplVBrjyIld3Qbdkp29jE
aLX89FeJaxTb4O/uQA1iH+pY1KPYugOmly7FaxOkkXemta0jp+sKSRRGfHbpnjK0
ia9XeQIDAQABo4HSMIHPMEEGCCsGAQUFBwEBBDUwMzAxBggrBgEFBQcwAoYlaHR0
cHM6Ly9kc2EuZGViaWFuLm9yZy9zZWN1cmUtYm9vdC1jYTAfBgNVHSMEGDAWgBRs
zs5+TGwNH2FJ890n38xcu0GeoTAUBglghkgBhvhCAQEBAf8EBAMCAPcwEwYDVR0l
BAwwCgYIKwYBBQUHAwMwDgYDVR0PAQH/BAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8w
HQYDVR0OBBYEFGzOzn5MbA0fYUnz3SffzFy7QZ6hMA0GCSqGSIb3DQEBCwUAA4IB
AQB3lj5Hyc4Jz4uJzlntJg4mC7mtqSu9oeuIeQL/Md7+9WoH72ETEXAev5xOZmzh
YhKXAVdlR91Kxvf03qjxE2LMg1esPKaRFa9VJnJpLhTN3U2z0WAkLTJPGWwRXvKj
8qFfYg8wrq3xSGZkfTZEDQY0PS6vjp3DrcKR2Dfg7npfgjtnjgCKxKTfNRbCcitM
UdeTk566CA1Zl/LiKaBETeru+D4CYMoVz06aJZGEP7dax+68a4Cj2f2ybXoeYxTr
7/GwQCXV6A6B62v3y//lIQAiLC6aNWASS1tfOEaEDAacz3KTYhjuXJjWs30GJTmV
305gdrAGewiwbuNknyFWrTkP
-----END CERTIFICATE-----
EOF
#Remove if exists
rm -f /tmp/extract-mod-sig.pl
# from https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/scripts/extract-module-sig.pl?id=d01c3289e7d68162e32bc08c2b65dd1a216a7ef8
cat > /tmp/extract-mod-sig.pl << 'EOF'
#!/usr/bin/env perl
# SPDX-License-Identifier: GPL-2.0
#
# extract-mod-sig <part> <module-file>
#
# Reads the module file and writes out some or all of the signature
# section to stdout.  Part is the bit to be written and is one of:
#
#  -0: The unsigned module, no signature data at all
#  -a: All of the signature data, including magic number
#  -d: Just the descriptor values as a sequence of numbers
#  -n: Just the signer's name
#  -k: Just the key ID
#  -s: Just the crypto signature or PKCS#7 message
#
use warnings;
use strict;

die "Format: $0 -[0adnks] module-file >out\n"
    if ($#ARGV != 1);

my $part = $ARGV[0];
my $modfile = $ARGV[1];

my $magic_number = "~Module signature appended~\n";

#
# Read the module contents
#
open FD, "<$modfile" || die $modfile;
binmode(FD);
my @st = stat(FD);
die "$modfile" unless (@st);
my $buf = "";
my $len = sysread(FD, $buf, $st[7]);
die "$modfile" unless (defined($len));
die "Short read on $modfile\n" unless ($len == $st[7]);
close(FD) || die $modfile;

print STDERR "Read ", $len, " bytes from module file\n";

die "The file is too short to have a sig magic number and descriptor\n"
    if ($len < 12 + length($magic_number));

#
# Check for the magic number and extract the information block
#
my $p = $len - length($magic_number);
my $raw_magic = substr($buf, $p);

die "Magic number not found at $len\n"
    if ($raw_magic ne $magic_number);
print STDERR "Found magic number at $len\n";

$p -= 12;
my $raw_info = substr($buf, $p, 12);

my @info = unpack("CCCCCxxxN", $raw_info);
my ($algo, $hash, $id_type, $name_len, $kid_len, $sig_len) = @info;

if ($id_type == 0) {
    print STDERR "Found PGP key identifier\n";
} elsif ($id_type == 1) {
    print STDERR "Found X.509 cert identifier\n";
} elsif ($id_type == 2) {
    print STDERR "Found PKCS#7/CMS encapsulation\n";
} else {
    print STDERR "Found unsupported identifier type $id_type\n";
}

#
# Extract the three pieces of info data
#
die "Insufficient name+kid+sig data in file\n"
    unless ($p >= $name_len + $kid_len + $sig_len);

$p -= $sig_len;
my $raw_sig = substr($buf, $p, $sig_len);
$p -= $kid_len;
my $raw_kid = substr($buf, $p, $kid_len);
$p -= $name_len;
my $raw_name = substr($buf, $p, $name_len);

my $module_len = $p;

if ($sig_len > 0) {
    print STDERR "Found $sig_len bytes of signature [";
    my $n = $sig_len > 16 ? 16 : $sig_len;
    foreach my $i (unpack("C" x $n, substr($raw_sig, 0, $n))) {
	printf STDERR "%02x", $i;
    }
    print STDERR "]\n";
}

if ($kid_len > 0) {
    print STDERR "Found $kid_len bytes of key identifier [";
    my $n = $kid_len > 16 ? 16 : $kid_len;
    foreach my $i (unpack("C" x $n, substr($raw_kid, 0, $n))) {
	printf STDERR "%02x", $i;
    }
    print STDERR "]\n";
}

if ($name_len > 0) {
    print STDERR "Found $name_len bytes of signer's name [$raw_name]\n";
}

#
# Produce the requested output
#
if ($part eq "-0") {
    # The unsigned module, no signature data at all
    binmode(STDOUT);
    print substr($buf, 0, $module_len);
} elsif ($part eq "-a") {
    # All of the signature data, including magic number
    binmode(STDOUT);
    print substr($buf, $module_len);
} elsif ($part eq "-d") {
    # Just the descriptor values as a sequence of numbers
    print join(" ", @info), "\n";
} elsif ($part eq "-n") {
    # Just the signer's name
    print STDERR "No signer's name for PKCS#7 message type sig\n"
	if ($id_type == 2);
    binmode(STDOUT);
    print $raw_name;
} elsif ($part eq "-k") {
    # Just the key identifier
    print STDERR "No key ID for PKCS#7 message type sig\n"
	if ($id_type == 2);
    binmode(STDOUT);
    print $raw_kid;
} elsif ($part eq "-s") {
    # Just the crypto signature or PKCS#7 message
    binmode(STDOUT);
    print $raw_sig;
}

EOF

GLOBAL_IDS="
10de:1e02 Titan RTX
10de:1e03 2080Ti
10de:1e04 2080Ti
10de:1e07 2080Ti
10de:1e09 CMP 50HX
10de:1e2d 2080Ti
10de:1e2e 2080Ti
10de:1e30 Quadro RTX 6000
10de:1e35 Tesla T10
10de:1e36 Quadro RTX 6000
10de:1e37 Tesla T10
10de:1e38 Tesla T40
10de:1e78 Quadro RTX 6000
10de:1e81 2080S
10de:1e82 2080
10de:1e84 2070S
10de:1e87 2080
10de:1e89 2060
10de:1e90 2080M
10de:1e91 2070S M
10de:1e93 2080S M
10de:1eae 2080M
10de:1eb0 Quadro RTX 5000
10de:1eb1 Quadro RTX 4000
10de:1eb4 T4G
10de:1eb5 Quadro RTX 5000M
10de:1eb6 Quadro RTX 4000M
10de:1eb8 Tesla T4
10de:1ef5 Quadro RTX 5000M
10de:1f02 2070
10de:1f03 2060
10de:1f06 2060S
10de:1f07 2070
10de:1f08 2060
10de:1f09 1660S
10de:1f0a 1650
10de:1f0b CMP 40HX
10de:1f10 2070M
10de:1f11 2060M
10de:1f12 2060M
10de:1f14 2070M
10de:1f15 2060M
10de:1f36 Quadro RTX 3000M
10de:1f42 2060S
10de:1f47 2060S
10de:1f50 2070M
10de:1f51 2060M
10de:1f54 2070M
10de:1f55 2060M
10de:1f76 Quadro RTX 3000M
10de:1f82 1650
10de:1f83 1630
10de:1f91 1650M
10de:1f92 1650M
10de:1f94 1650M
10de:1f95 1650Ti M
10de:1f96 1650M
10de:1f97 MX450
10de:1f98 MX450
10de:1f99 1650M
10de:1f9c MX450
10de:1f9d 1650M
10de:1f9f MX550
10de:1fa0 MX550
10de:1fb0 Quadro T1000M
10de:1fb1 T600
10de:1fb2 Quadro T400M
10de:1fb6 T600M
10de:1fb7 T550M
10de:1fb8 Quadro T2000M
10de:1fb9 Quadro T1000M
10de:1fba T600M
10de:1fbb Quadro T500M
10de:1fbc T1200M
10de:1ff0 T1000
10de:1ff2 T400
10de:1ff9 Quadro T1000M
10de:2080 A100
10de:2081 A100
10de:2082 CMP 170HX
10de:20b0 A100
10de:20b1 A100
10de:20b2 A100
10de:20b3 A100
10de:20b5 A100
10de:20b7 A30
10de:20b8 A100X
10de:20b9 A30X
10de:20bb DRIVE A100
10de:20bd A800
10de:20be GRID A100A
10de:20bf GRID A100B
10de:20c2 CMP 170HX
10de:20f0 A100
10de:20f1 A100
10de:20f2 A100
10de:20f3 A800
10de:20f5 A800
10de:20f6 A800
10de:20fd AX800
10de:2182 1660Ti
10de:2184 1660
10de:2187 1650S
10de:2188 1650
10de:2189 CMP 30HX
10de:2191 1660Ti M
10de:2192 1650Ti M
10de:21c4 1660S
10de:21d1 1660Ti M
10de:2200 3090Ti
10de:2203 3090Ti
10de:2204 3090
10de:2205 3080Ti
10de:2206 3080
10de:2207 3070Ti
10de:2208 3080Ti
10de:220a 3080
10de:220d CMP 90HX
10de:2216 3080
10de:222b 3090
10de:222f 3080
10de:2230 RTX A6000
10de:2231 RTX A5000
10de:2232 RTX A4500
10de:2233 RTX A5500
10de:2235 A40
10de:2236 A10
10de:2237 A10G
10de:2238 A10M
10de:2414 3060Ti
10de:2420 3080Ti M
10de:2438 RTX A5500 M
10de:2460 3080Ti M
10de:2482 3070Ti
10de:2484 3070
10de:2486 3060Ti
10de:2487 3060
10de:2488 3070
10de:2489 3060Ti
10de:248a CMP 70HX
10de:248c 3070Ti
10de:248d 3070
10de:248e 3060Ti
10de:249c 3080M
10de:249d 3070M
10de:24a0 3070Ti M
10de:24b0 RTX A4000
10de:24b1 RTX A4000H
10de:24b6 RTX A5000 M
10de:24b7 RTX A4000 M
10de:24b8 RTX A3000 M
10de:24b9 RTX A3000 M
10de:24ba RTX A4500 M
10de:24bb RTX A3000 M
10de:24c7 3060
10de:24c8 3070
10de:24c9 3060Ti
10de:24dc 3080M
10de:24dd 3070M
10de:24e0 3070Ti M
10de:24fa RTX A4500
10de:2501 3060
10de:2503 3060
10de:2504 3060
10de:2507 3050
10de:2508 3050
10de:2509 3060
10de:2520 3060M
10de:2521 3060M
10de:2523 3050Ti M
10de:2531 RTX A2000
10de:2544 3060
10de:2560 3060M
10de:2561 3060M
10de:2563 3050Ti M
10de:2571 RTX A2000
10de:2582 3050
10de:2583 3050
10de:2584 3050
10de:25a0 3050Ti M
10de:25a2 3050 M
10de:25a5 3050 M
10de:25a6 MX570
10de:25a7 MX570
10de:25a9 RTX 2050
10de:25aa MX570 A
10de:25ab 3050 M
10de:25ac 3050 M
10de:25ad RTX 2050
10de:25b0 RTX A1000
10de:25b2 RTX A400
10de:25b5 RTX A4 M
10de:25b6 A2/A16
10de:25b8 RTX A2000 M
10de:25b9 RTX A1000 M
10de:25ba RTX A2000 M
10de:25bb RTX A500 M
10de:25bc RTX A1000 M
10de:25bd RTX A500 M
10de:25e0 3050Ti M
10de:25e2 3050 M
10de:25e5 3050 M
10de:25ec 3050 M
10de:25ed RTX 2050
10de:25f9 RTX A1000
10de:25fa RTX A2000
10de:25fb RTX A500
10de:2681 RTX TITAN Ada
10de:2684 4090
10de:2685 4090 D
10de:2689 4070Ti
10de:26b1 RTX 6000 Ada
10de:26b2 RTX 5000 Ada
10de:26b3 RTX 5880 Ada
10de:26b5 L40
10de:26b7 L20
10de:26b8 L40G
10de:26b9 L40S
10de:26ba L20
10de:26bb L30
10de:2704 4080
10de:2705 4070Ti
10de:2709 4070
10de:2717 4090 M
10de:2730 RTX 5000 Ada M
10de:2757 4090 M
10de:2770 RTX 5000 Ada
10de:2782 4070Ti
10de:2783 4070
10de:2786 4070
10de:2788 4060Ti
10de:27a0 4080 M
10de:27b0 RTX 4000 SFF Ada
10de:27b1 RTX 4500 Ada
10de:27b2 RTX 4000 Ada
10de:27b6 L2
10de:27b7 L16
10de:27b8 L4
10de:27ba RTX 4000 Ada M
10de:27bb RTX 3500 Ada M
10de:27e0 4080 M
10de:27fa RTX 4000 Ada
10de:27fb RTX 3500 Ada
10de:2803 4060Ti
10de:2805 4060Ti
10de:2808 4060
10de:2820 4070 M
10de:2822 3050A M
10de:2838 RTX 3000 Ada M
10de:2860 4070 M
10de:2901 B200
10de:2920 TS4
10de:2941 GB200
10de:29bc B100
10de:2b85 5090
10de:2b87 5090 D
10de:2c02 5080
10de:2c18 5090 M
10de:2c19 5080 M
10de:2c2c GB6-256
10de:2c58 5090 M
10de:2c59 5080 M
10de:2d18 5070 M
10de:2d19 5060 M
10de:2d2c GB6-128
10de:2d58 5070 M
10de:2d59 5060 M
10de:2d98 5050 M
10de:2dd8 5050 M
10de:2f18 5070Ti M
10de:2f58 5070Ti M
"


function run_tests() {
	sudo apt-get install -y stress 
    sudo apt-get -y install osslsigncode
    vm_check
	echo "vm check done"
    pciid_check
	echo "pciid check done"
    secure_boot_check
	echo "secureboot check done"
    kernel_image_sig_check
	echo "kernel image check done"
    kernel_mod_sig_check
    echo "GPU Verification Successful"
    echo "$EXPECTED_GPUS"
}

run_tests