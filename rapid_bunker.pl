#!/usr/bin/perl

use strict;
use warnings;
use 5.010;
use Term::ANSIColor;

# Rapid Bunker Beta : Version 0.5

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
);

# Custom Firewall function. Configures IP tables to user specifications.
sub fw_custom
{
	system("sudo iptables -F");
	system("sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT");
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
	system("sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT");
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
	&colored_say("bold green",   "\nfw_rules : lists firewall rules");
	&colored_say("bold green",   "\nfw_bunker : implements restrictive firewall rules,");
	&colored_say("bold green",   "    closing all ports, and only allowing connections that");
	&colored_say("bold green",   "    the host initiates. Side effect: Will block ICMP (Ping).");
	&colored_say("bold green",   "\nfw_custom : allows the user to open specific ports and set firewall rules.");
	&colored_say("bold green",   "\nlast : list the logins to the machine");
	&colored_say("bold green",   "\nusers : list currently logged in users");
	&colored_say("bold green",   "\nall_users : list all users on the machine");
	&colored_say("bold green",   "\nproc : list processes for all users");
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

#Prints all users in /etc/passwd
sub all_users
{
	&colored_say("bold green",   "\nListing all users on the machine:");	
	#Command sourced from stackoverflow.com/q/12539272
	system("grep -o '^[^:]*' /etc/passwd");
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
