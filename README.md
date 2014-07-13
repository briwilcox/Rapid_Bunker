Rapid_Bunker
============

A Perl utility that allows for the rapid deployment of iptables, and provides a common simple interface to security, system administration, and forensics related Linux utilities.

# Commands / Usage

General:

	help : relists these commands

	exit : terminates the program

Network Related:

	connections : lists open or listening connections

	snitch : lists all processes connecting to the network

	scan : user friendly interface to ipv4 port scanning (common or all ports, ability to spoof IP address easily) or drop into nmap for more control

	fw_rules : lists firewall rules

	fw_bunker : implements restrictive firewall rules, closing all ports, and only allowing connections that the host initiates. User may allow or deny ICMP (ping).

	fw_custom : allows the user to open specific ports and set firewall rules. User may allow or deny ICMP (ping).

User Related:

	last : list the logins to the machine

	users : list currently logged in users

	all_users : list all users on the machine

	failed_logins : list all failed login attempts on the machine, and to which accounts

	Process Related:

	proc : list processes for all users

	kill_proc : kills a proccess by name or by PID

	list_open : (Warning large amounts of output) Lists all open files

Misc:

	install_sec : install common security applications (‘fail2ban’, ‘chkrootkit’, ‘logwatch’, ‘nmap’).

# Why write this utility?

My original goal was to provide an easy portable interface to IP tables. This expanded to building a common interface to different utilities / commands, useful for systems administration, security, or forensics. My goal is for someone new to Linux who may be unfamiliar with these commands or syntax to be able to quickly gain valuable information about the system they are on, and begin securing it. This tool is also great for saving time for more experienced Linux users, as it is unnecessary to look at man pages or search the web for a specific combination of command arguments.

# Why Perl?

Perl was chosen due to portability. Perl is installed by default on most popular Linux distributions, both desktop and server. Perl also allows me as a programmer to easily call system utilities, and integrates well with Linux. As an interpreted language Perl does not need to be compiled against different processor architectures, and does not need additional software installed assuming that like most Linux systems the one it is being executed on comes with Perl pre-installed. I also try to avoid the use of obscure perl modules that may not be installed by default.

# Installation

Getting and executing the code should be as simple as:

    wget https://raw.github.com/briwilcox/Rapid_Bunker/master/rapid_bunker.pl

    chmod +x rapid_bunker

    ./rapid_bunker.pl


# License

Licensed under the BSD license included on the Rapid Bunker github repository.

# Misc

To contact the author : http://brianmwilcox.com

FAQ / Usage : http://brianmwilcox.com/rapid-bunker-faq/
