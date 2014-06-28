#!/usr/bin/perl

use strict;
use warnings;
use 5.010;
use Term::ANSIColor;

#
# Rapid Bunker Beta : Version 0.70
#

#
# If you find this software useful please let me know: brianmwilcox.com/contact-me/
#

# Copyright (c) 2013, Brian M Wilcox, www.brianmwilcox.com
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# Redistributions of source code must retain the above copyright notice,
# this list of conditions and the following disclaimer. Redistributions
# in binary form must reproduce the above copyright notice, this list
# of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
#
# Neither the name of the www.brianmwilcox.com nor the names of its
# contributors may be used to endorse or promote products derived from
# this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
# TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
# OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
# OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.



# Function map is a hash that contains references to each function in our code. 
# Avoids ugly if statements and allows easy additions to the code.
my %functionmap = 
(	
	connections 	=>	\&connections,
	fw_rules 	=>	\&fw_rules,
	proc 		=>	\&proc,
	list_open 	=>	\&list_open,
	fw_bunker 	=>	\&fw_bunker,
	users 		=>	\&users,
	last 		=>	\&last_login,
	snitch 		=>	\&snitch,
	help 		=>	\&help,
	exit 		=>	\&exit_now,
	fw_custom	=>	\&fw_custom,
	all_users	=>	\&all_users,
	kill_proc	=>	\&kill_proc,
	failed_logins	=>	\&failed,
	install_sec	=>	\&sec_list_install,
	scan		=>	\&scanner,
);


#These common security packages appear to be in both debian and cent os repositories as of Oct 31 2013
my @sec_packages = ('fail2ban', 'chkrootkit', 'logwatch', 'nmap');

sub scanner
{
	#Is nmap installed?
	my $scanner = "nmap";
	my $scanner_check = 'which $scanner';
	my $in = '';	
	if((length($scanner_check)) < 1)
	{
		
		&colored_say("bold red", "It appears nmap is not installed, please install it manually or with the install_sec command.");
		
	} else {
                &colored_say("bold green", "Would you like to exit Rapid Bunker and manually run nmap? (y for yes, n for no)");
	        chomp($in = <stdin>);
		if($in eq "y")
		{
			exec("sudo nmap");
		}
		$in = '';

		&colored_say("bold green", "Enter ip or range you'd like to scan:");
		my $ip = '';
		chomp($ip = <stdin>);

		&colored_say("bold green", "Would you like to spoof your IP address? (type y for yes, n for no) :");
                chomp($in = <stdin>);
		if(lc($in) eq "y")
		{
                        &colored_say("bold green", "Enter IP to spoof to :");
			my $spoofed_ip = '';
                        chomp($spoofed_ip = <stdin>);
			&colored_say("bold green", "Below is the output of ifconfig, use it to answer the next prompt.");
			system("ifconfig");

			&colored_say("bold green", "Because you are spoofing you need to tell Nmap an interface to scan on (such as eth0, eth1, wlan0)\nWhat interface would you like to scan from? :");
			my $interface = '';
			chomp($interface = <stdin>);

                        &colored_say("bold green", "Would you like to do a deep (all ports) or fast scan? (type deep for deep, fast for fast) :");
                        chomp($in = <stdin>);
                        if((lc($in)) eq "deep")
                        {
                                system("sudo nmap $ip -p1-65535 -O -sV -S $spoofed_ip -e $interface -Pn");
                        } else {
                                system("sudo nmap $ip -F -O -sV -S $spoofed_ip -e $interface -Pn")
                        }
		
		} else {
			&colored_say("bold green", "Would you like to do a deep (all ports) or fast scan? (type deep for deep, fast for fast) :");
			chomp($in = <stdin>);
			if((lc($in)) eq "deep")
			{
				system("sudo nmap $ip -p1-65535 -O -sV");
			} else {
				system("sudo nmap $ip -F -O -sV")
			}
		}
	}
        &colored_say("bold green",   "\nYou may enter an additional command");
}

# Custom Firewall function. Configures IP tables to user specifications.
sub fw_custom
{
	system("sudo iptables -F");
	system("sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT");
	&enable_ping();
	#Enable local host
	system("sudo iptables -A INPUT -i lo -j ACCEPT");
	system("sudo iptables -A OUTPUT -o lo -j ACCEPT");
	my $in = '';
	&colored_say
	("bold green",  "Type a tcp port you want open, then click enter. Once you have entered as many tcp ports as you want, enter 0 to continue.");
	my @tcp_ports;
	my @udp_ports;

	#Loops over user input, pushes valid integers in the range of possible tcp ports to an array
	do
	{
	chomp($in = <stdin>);
	{no warnings 'uninitialized';
			if ($in =~ /\D/) #Verify port is numeric only
			{		    
				&colored_say("bold red",  $in . " is not a valid port!"); 
			}
			else
			{
			if((0 < $in)&&($in < 65536)) #Verify port is in valid range
				{ 
					push(@tcp_ports, $in); 
				}
			}
		}
	
	} until($in eq 0);
	
	&colored_say
	("bold green",  "Type a udp port you want open, then click enter. Once you have entered as many tcp ports as you want, enter 0 to continue.");

	#Loops over user input, pushes valid integers in the range of possible udp ports to an array
	do
	{
	chomp($in = <stdin>);
		{no warnings 'uninitialized';
			if ($in =~ /\D/) #Verify port is numeric only 
			{		    
				&colored_say("bold red",  $in . " is not a valid port!"); 
			}
			else
			{
				if((0 < $in)&&($in < 65536)) #Verify port is in valid range
				{ 
					push(@tcp_ports, $in); 
				}
			}
		}
	} until($in eq 0);

	&iptables_tcp(@tcp_ports);
	&iptables_udp(@udp_ports);
	system("sudo iptables -A INPUT -j DROP");
	system("sudo iptables --list");
	&colored_say("bold green",   "\nYou may enter an additional command");
}

#Sub function that takes an array of tcp port numbers and creates permissive firewall rules
sub iptables_tcp
{
	my $port1;
	for $port1 (@_) 
	{
		system("sudo iptables -A INPUT -p tcp --dport $port1 -j ACCEPT");
	}
}

#Sub function that takes an array of udp port numbers and creates permissive firewall rules
sub iptables_udp
{
	my $port2;
	for $port2 (@_)
	{
		system("sudo iptables -A INPUT -p udp --dport $port2 -j ACCEPT");
	}
}

#Enable Ping
sub enable_ping
{
	&colored_say("bold green",  "Would you like to enable ping responses from this machine? Type y for yes, n for no.");
	chomp(my $yn = <STDIN>);
	if(($yn eq 'y') || ($yn eq 'Y'))
	{
		&colored_say("bold green",  "The output of a command listing your interfaces and IPs is listed below:");
		system("ifconfig -a");
		&colored_say("bold green",  "Please carefully type the IP address of the interface you would like to allow incoming and outgoing ping from.");

		chomp(my $ip = <STDIN>);
		system("sudo iptables -A INPUT -p icmp --icmp-type 8 -s 0/0 -d $ip -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT");
		system("sudo iptables -A OUTPUT -p icmp --icmp-type 0 -s $ip -d 0/0 -m state --state ESTABLISHED,RELATED -j ACCEPT");
		system("sudo iptables -A OUTPUT -p icmp --icmp-type 8 -s $ip -d 0/0 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT");
		system("sudo iptables -A INPUT -p icmp --icmp-type 0 -s 0/0 -d $ip -m state --state ESTABLISHED,RELATED -j ACCEPT");
	}
}

#Exits the program with exit code 0
sub exit_now
{
	&colored_say("bold green",  "Exiting now!");
	exit 0;
}

#Lists active or listening connections by utilizing netstat
sub connections
{
	&colored_say("bold green",   "Listing all active or listening connections.");
	system("netstat --inet -a");
	&colored_say("bold green",   "Connections have completed being listed");
	&colored_say("bold green",   "\nYou may enter an additional command.");
}

#Lists iptable rules
sub fw_rules
{
	&colored_say("bold green",   "Listing all filewall rules.");
	system("sudo iptables --list");
	&colored_say("bold green",   "Firewall rules have been listed");
	&colored_say("bold green",   "\nYou may enter an additional command");
}

#Utilizes ps to list processes running on the machine.
sub proc
{
	system("ps -face");
	&colored_say("bold green",   "\nYou may enter an additional command");
}

#Utilizes lsof to list open files on the machine
sub list_open
{
	&colored_say("bold green",   "This will list all the files currently open.");
	system("lsof");
	&colored_say("bold green",   "\nYou may enter an additional command");
}

#Configures iptables to be restrictive
sub fw_bunker
{
	&colored_say("bold green",   "Implementing restrictive firewall rules.");
	system("sudo iptables -F");
        system("sudo iptables -A INPUT -i lo -j ACCEPT");
        system("sudo iptables -A OUTPUT -o lo -j ACCEPT");
	system("sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT");
	#Give user the option of enabling ping even with auto lock down.
	&enable_ping(); 
	system("sudo iptables -A INPUT -j DROP");
	system("sudo iptables --list");
	&colored_say("bold green",   "\nYou may enter an additional command");
}

#Lists logged in users
sub users
{
	&colored_say("bold green", "Listing all logged in users.");
	system("w");
	&colored_say("bold green", "\nYou may enter an additional command");
}

#Lists recent user logins
sub last_login
{
	&colored_say("bold green",   "Listing last logins");
	system("last");
	&colored_say("bold green",   "\nYou may enter an additional command");
}

#Lists programs currently opening network connections
sub snitch
{
	&colored_say("bold green",   "Listing all processes connecting to the network...");
	system("lsof -i");
	&colored_say("bold green",   "\nYou may enter an additional command");
}

#Prints out list of valid commands that the user may type
sub help
{
	&colored_say("bold green",   "\nUse any of the following commands:");
	&colored_say("bold green",   "\nhelp : relists these commands");
	&colored_say("bold green",   "\nconnections : lists open or listening connections");
	&colored_say("bold green",   "\nsnitch : lists all processes connecting to the network");
        &colored_say("bold green",   "\nscan : user friendly interface to ipv4 port scanning or drop into nmap for advanced port scanning");
	&colored_say("bold green",   "\nfw_rules : lists firewall rules");
	&colored_say("bold green",   "\nfw_bunker : implements restrictive firewall rules,");
	&colored_say("bold green",   "    closing all ports, and only allowing connections that");
	&colored_say("bold green",   "    the host initiates.");
	&colored_say("bold green",   "\nfw_custom : allows the user to open specific ports and set firewall rules.");
	&colored_say("bold green",   "\nlast : list the logins to the machine");
	&colored_say("bold green",   "\nusers : list currently logged in users");
	&colored_say("bold green",   "\nall_users : list all users on the machine");
	&colored_say("bold green",   "\nfailed_logins : list all failed login attempts to the machine");
	&colored_say("bold green",   "\nproc : list processes for all users");
	&colored_say("bold green",   "\nkill_proc : kill a process by either name or process id (PID)");	
	&colored_say("bold green",   "\ninstall_sec : install common security applications ('fail2ban', 'chkrootkit', 'logwatch', 'nmap').");
	&colored_say("bold green",   "\nlist_open : (Warning large amounts of output) Lists all open files");
	&colored_say("bold green",   "\nexit : terminates the program.\n");
}

#Colors print in a way that allows for colored output, and appends lines with a new line character.
sub colored_say($$)
{
	my ($color, $out) = (shift, shift);
	print color $color;
	print $out . "\n";
	print color 'reset'; 
}

#Allows a user to kill a process by name or PID by calling a sub functions killall or killpid
sub kill_proc
{
	&colored_say("bold green",   "Enter (without quotes) '1' to kill a process by name, or enter '2' to kill a process by process id (PID).");
	chomp(my $choice = <STDIN>);

	if($choice eq 1)
	{
		&killall();
	} 

	elsif($choice eq 2)
	{
		&killpid();
	}

	else
	{
		&colored_say("bold red",   "It appears you have entered invalid input, aborting kill_proc!");	
	}
	
}

#Allows a user to kill a process using the killall command
sub killall
{
	&colored_say("bold green",   "Suggested usage: run proc first to list process names");	

	&colored_say("bold green",   "\nType process name to kill all instances of (example: firefox):");	
	chomp(my $proc = <STDIN>);
	system("sudo killall $proc");
	&colored_say("bold green",   "\nYou may enter an additional command");
}

#Allows a user to kill a process by PID 
sub killpid
{
	&colored_say("bold green",   "Suggested usage: run proc first to list process names");	

	&colored_say("bold green",   "\nType process ID (PID) to run 'kill' against (example: 1234):");	
	chomp(my $pid = <STDIN>);
	system("sudo kill $pid");
	&colored_say("bold green",   "\nYou may enter an additional command");
}

#Install security applications
sub sec_list_install
{
	my $apt = '/usr/bin/apt-get';
	my $yum = '/usr/bin/yum';
	my $pac = '/usr/bin/pacman';
	if(-e $apt)
	{
		deb_install(@sec_packages);	
	}
	#Not tested
	elsif(-e $yum)
	{
		yum_install(@sec_packages);
	}
	#Not tested
	elsif(-e $pac)
	{
		pac_install(@sec_packages);
	}
} 


#Debian / Ubuntu / Variant bulk package installation
sub deb_install
{
	system("sudo apt-get update");
	my $packages;
	for $packages(@_)
	{
		system("sudo apt-get install $packages");
	}
}

#CentOS / Fedora / Variant bulk package install
sub yum_install
{
	my $packages;
	for $packages(@_)
	{
		system("sudo yum install $packages");
	}
} 

#Install packages on a system running pacman (like archlinux)
sub pac_install
{
	my $packages;
	for $packages(@_)
	{
		system("sudo pacman -S $packages");
	}
}

#Update all packages on a system running apt-get
sub deb_update
{
	system("sudo apt-get update && sudo apt-get upgrade");
}

#Update all packages on a system running yum package manager
sub yum_update
{
	system("sudo yum update");
}

#Update all packages on a system running pacman package manager
sub pack_update
{
	system("sudo pacman -Syu");
}

#Prints all users in /etc/passwd
sub all_users
{
	&colored_say("bold green",   "\nListing all users on the machine:");	
	#Command sourced from stackoverflow.com/q/12539272
	system("grep -o '^[^:]*' /etc/passwd");
	&colored_say("bold green",   "\nYou may enter an additional command");
}

#Lists failed login attempts
sub failed
{
	&colored_say("bold green",   "\nListing all failed login attempts on the machine:");
	system("sudo faillog --all");
	&colored_say("bold green",   "\nYou may enter an additional command");
}

#Main function body, loops until exit command is given. Takes user input and sends it to the function hash, as well as checks for errors.
sub main
{
	&colored_say("bold green",   "\nWelcome to Rapid Bunker!");
	&colored_say("bold red", "\nRapid bunker comes with ABSOLUTELY NO WARRANTY, use at your own risk!");
	&help();
	
	while("1" == "1")
	{
		chomp(my $input = <STDIN>);  
		{no warnings 'uninitialized'; eval{ $functionmap{$input}(); } or do { &colored_say("red", "Invalid Input!\n"); }; }
	}
}

#Start Program Body
&main();
#End Program Body
