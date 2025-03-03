# TP1 : Linux basiiiecs

## Part I : Filtrey des paqueys

### 1. Intro

### 2. Conf

🌞 **Proposer une configuration restrictive de firewalld**

```
[axel@TP1-Secu-SE ~]$ sudo firewall-cmd --list-all
drop (active)
  target: DROP
  icmp-block-inversion: no
  interfaces: enp0s3 enp0s8
  sources: 10.1.1.0/24
  services: 
  ports: 22/tcp
  protocols: 
  forward: yes
  masquerade: no
  forward-ports: 
  source-ports: 
  icmp-blocks: 
  rich rules: 
```


## Part II : PAM

🌞 **Proposer une configuration de politique de mot de passe**

```
[axel@TP1-Secu-SE ~]$ cat /etc/security/pwquality.conf | grep -E "^#" -v
minlen = 14
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
enforcing = 1
enforce_for_root
```

## Part III : OpenSSH

### 1. Intro

### 2. Conf

🌞 **Proposer une configuration du serveur OpenSSH**

Le fichier de conf est [ICI](/TP_1/sshd_config)

🌞 **Une fois en place, tu m'appelles en cours pour que je me connecte**

Tu m'as dis que tout est bon :)

```
Feb 20 16:29:07 TP1-Secu-SE sshd[1594]: Accepted key ED25519 SHA256:d+GFmHd++mXOMEUEY90r5Ak3EfKvMlgI1IMOTWViZAM found at /home/it4/.ssh/authorized_keys:1
Feb 20 16:29:07 TP1-Secu-SE sshd[1594]: Postponed publickey for it4 from 10.0.2.2 port 38350 ssh2 [preauth]
Feb 20 16:29:07 TP1-Secu-SE sshd[1594]: Accepted key ED25519 SHA256:d+GFmHd++mXOMEUEY90r5Ak3EfKvMlgI1IMOTWViZAM found at /home/it4/.ssh/authorized_keys:1
Feb 20 16:29:07 TP1-Secu-SE sshd[1594]: Accepted publickey for it4 from 10.0.2.2 port 38350 ssh2: ED25519 SHA256:d+GFmHd++mXOMEUEY90r5Ak3EfKvMlgI1IMOTWViZAM
Feb 20 16:29:07 TP1-Secu-SE systemd-logind[754]: New session 3 of user it4.
Feb 20 16:29:07 TP1-Secu-SE systemd[1600]: pam_unix(systemd-user:session): session opened for user it4(uid=1001) by it4(uid=0)
Feb 20 16:29:07 TP1-Secu-SE systemd[1]: Started Session 3 of User it4.
Feb 20 16:29:07 TP1-Secu-SE sshd[1594]: pam_unix(sshd:session): session opened for user it4(uid=1001) by it4(uid=0)
Feb 20 16:29:07 TP1-Secu-SE sshd[1611]: Starting session: shell on pts/1 for it4 from 10.0.2.2 port 38350 id 0
```

## Part IV : Gestion d'utilisateurs

### 1. Gestion d'utilisateurs

🌞 **Gestion d'utilisateurs**

Commande pour gérer un mot de passe fort :
```
tr -dc 'A-Za-z0-9!@#$%^&*()_+{}[]<>?-' < /dev/urandom | head -c 20; echo
```

Comme il y a beaucoup d'utilisateurs, je me suis dis que j'allais faire un script qui s'occupe de créer tous les utilisateurs, leur mettre un mot de passe et les ajouter aux groupes voulus. Le script est trouvable [ICI](./script_user_groups_creatation.sh)

Contenu de /etc/group :
```
axel:x:1000:
it4:x:1001:
managers:x:1002:suha,noah
admins:x:1003:suha,daniel,liam
sysadmins:x:1004:daniel
artists:x:1005:noah,alysha,rose
devs:x:1006:rose,sadia,jakub,lev
rh:x:1007:grace,lucia,oliver
suha:x:1008:
daniel:x:1009:
liam:x:1010:
noah:x:1011:
alysha:x:1012:
rose:x:1013:
sadia:x:1014:
jakub:x:1015:
lev:x:1016:
grace:x:1017:
lucia:x:1018:
oliver:x:1019:
nginx:x:1020:
```

### 2. Gestion de permissions

🌞 **Gestion de permissions**

```
[root@TP1-Secu-SE ~]# ls -alR /data/
/data/:
total 0
drwxr-----+  4 root root  34 Mar  1 21:42 .
dr-xr-xr-x. 19 root root 247 Mar  2 00:46 ..
drwxrw----+  2 root root  23 Mar  1 21:42 conf
drwxrw-r--+  6 root root  89 Mar  1 21:42 projects

/data/conf:
total 0
drwxrw----+ 2 root root 23 Mar  1 21:42 .
drwxr-----+ 4 root root 34 Mar  1 21:42 ..
-rwxrw----+ 1 root root  0 Mar  1 21:42 test.conf

/data/projects:
total 4
drwxrw-r--+ 6 root root 89 Mar  1 21:42 .
drwxr-----+ 4 root root 34 Mar  1 21:42 ..
drwxrw----+ 4 root root 36 Mar  1 21:42 client_data
-rwxr--r--. 1 root root  0 Mar  1 21:42 README.docx
drwxrw----+ 2 root root 24 Mar  1 21:42 the_zoo
drwxrw----+ 2 root root 24 Mar  1 21:42 website
drwxrw----+ 2 root root 21 Mar  1 21:42 zoo_app

/data/projects/client_data:
total 0
drwxrw----+ 4 root root 36 Mar  1 21:42 .
drwxrw-r--+ 6 root root 89 Mar  1 21:42 ..
drwxrw----+ 2 root root 23 Mar  1 21:42 client1
drwxrw----+ 2 root root 23 Mar  1 21:42 client2

/data/projects/client_data/client1:
total 0
drwxrw----+ 2 root root 23 Mar  1 21:42 .
drwxrw----+ 4 root root 36 Mar  1 21:42 ..
-rwxrw----+ 1 root root  0 Mar  1 21:42 data.docx

/data/projects/client_data/client2:
total 0
drwxrw----+ 2 root root 23 Mar  1 21:42 .
drwxrw----+ 4 root root 36 Mar  1 21:42 ..
-rwxrw----+ 1 root root  0 Mar  1 21:42 data.docx

/data/projects/the_zoo:
total 4
drwxrw----+ 2 root root 24 Mar  1 21:42 .
drwxrw-r--+ 6 root root 89 Mar  1 21:42 ..
-rwxrw----+ 1 root root  0 Mar  1 21:42 ideas.docx

/data/projects/website:
total 0
drwxrw----+ 2 root root 24 Mar  1 21:42 .
drwxrw-r--+ 6 root root 89 Mar  1 21:42 ..
-rwxrw----+ 1 root root  0 Mar  1 21:42 index.html

/data/projects/zoo_app:
total 0
drwxrw----+ 2 root  root 21 Mar  1 21:42 .
drwxrw-r--+ 6 root  root 89 Mar  1 21:42 ..
-rwsrwx---+ 1 sadia root  0 Mar  1 21:42 zoo_app
```

```
[root@TP1-Secu-SE ~]# lsattr /data/projects/README.docx
----i----------------- /data/projects/README.docx
```

```
[root@TP1-Secu-SE ~]# getfacl -R /data/
getfacl: Removing leading '/' from absolute path names
# file: data/
# owner: root
# group: root
user::rwx
group::r--
group:managers:r-x
group:admins:r-x
group:sysadmins:r-x
group:artists:r-x
group:devs:r-x
group:rh:r-x
mask::r-x
other::---

# file: data//projects
# owner: root
# group: root
user::rwx
group::r--
group:managers:rwx
group:admins:r-x
group:sysadmins:r-x
group:artists:r-x
group:devs:r-x
group:rh:r-x
mask::rwx
other::r--

# file: data//projects/the_zoo
# owner: root
# group: root
user::rwx
user:suha:rwx
group::r--
group:managers:r-x
group:artists:rwx
group:devs:rwx
mask::rwx
other::---
default:user::rwx
default:user:suha:rw-
default:group::r--
default:group:managers:r--
default:group:artists:rw-
default:group:devs:rw-
default:mask::rw-
default:other::---

# file: data//projects/the_zoo/ideas.docx
# owner: root
# group: root
user::rwx
user:suha:rwx
group::r--
group:managers:r-x
group:artists:rwx
group:devs:r-x
mask::rwx
other::---

# file: data//projects/website
# owner: root
# group: root
user::rwx
user:daniel:rwx
user:alysha:rwx
user:rose:rwx
user:nginx:r-x
group::r--
group:managers:r-x
group:artists:r-x
group:devs:rwx
mask::rwx
other::---

# file: data//projects/website/index.html
# owner: root
# group: root
user::rwx
user:daniel:rwx
user:alysha:rwx
user:nginx:r-x
group::r--
group:managers:r-x
group:artists:r-x
group:devs:rwx
mask::rwx
other::---

# file: data//projects/client_data
# owner: root
# group: root
user::rwx
user:suha:rwx
group::r--
group:managers:r-x
group:artists:r-x
group:devs:r-x
group:rh:rwx
mask::rwx
other::---

# file: data//projects/client_data/client1
# owner: root
# group: root
user::rwx
user:noah:rwx
user:grace:rwx
user:lucia:rwx
user:oliver:rwx
group::r--
group:managers:r-x
group:rh:r-x
mask::rwx
other::---

# file: data//projects/client_data/client1/data.docx
# owner: root
# group: root
user::rwx
user:grace:rwx
user:lucia:rwx
user:oliver:rwx
group::r--
group:managers:r-x
group:rh:r-x
mask::rwx
other::---

# file: data//projects/client_data/client2
# owner: root
# group: root
user::rwx
user:noah:rw-
user:grace:rw-
user:lucia:rw-
group::r--
group:managers:r--
group:rh:r--
mask::rw-
other::---

# file: data//projects/client_data/client2/data.docx
# owner: root
# group: root
user::rwx
user:grace:rw-
user:lucia:rw-
group::r--
group:managers:r--
group:rh:r--
mask::rw-
other::---

# file: data//projects/zoo_app
# owner: root
# group: root
user::rwx
user:suha:rwx
user:sadia:rwx
user:jakub:r-x
group::r--
mask::rwx
other::---

# file: data//projects/zoo_app/zoo_app
# owner: sadia
# group: root
# flags: s--
user::rwx
user:suha:rwx
user:jakub:r-x
group::r--
mask::rwx
other::---

# file: data//projects/README.docx
# owner: root
# group: root
user::rwx
group::r--
other::r--

# file: data//conf
# owner: root
# group: root
user::rwx
user:daniel:rwx
user:rose:r-x
group::r--
group:admins:rwx
group:sysadmins:rwx
mask::rwx
other::---

# file: data//conf/test.conf
# owner: root
# group: root
user::rwx
user:daniel:rwx
user:rose:r-x
group::r--
group:admins:rwx
group:sysadmins:rwx
mask::rwx
other::---
```

### 3. Sudo sudo sudo

🌞 **Gestion de sudo**

Voici ce que j'ai ajouté :
```
[root@TP1-Secu-SE ~]# cat /etc/sudoers | grep -E "^#" -v
%sysadmins      ALL=(root) NOPASSWD: ALL
%artists        ALL=(sadia) NOPASSWD: /usr/bin/ls /data/*,\
                                    /usr/bin/cat /data/*,\
                                    /usr/bin/vi /data/*,\
                                    /usr/bin/file /data/*
alysha          ALL=(suha) NOPASSWD: /usr/bin/cat /data/projects/the_zoo/ideas.docx
%devs           ALL=(root) NOPASSWD: /usr/bin/dnf install *
jakub           ALL=(liam) NOPASSWD: /usr/bin/python*
%admins         ALL=(daniel) NOPASSWD: /usr/bin/free,\
                                    /usr/bin/top,\
                                    /usr/bin/df,\
                                    /usr/bin/du,\
                                    /usr/bin/ps,\
                                    /usr/sbin/ip
lev             ALL=(daniel) NOPASSWD: /usr/bin/openssl,\
                                    /usr/bin/dig,\
                                    /usr/bin/ping,\
                                    /usr/bin/curl
```

🌞 **Misconf ?**

## Part V : FTP

🌞 **Mettre en place un serveur FTP + TLS**

Toutes les commandes :
```
sudo dnf install vsftpd -y
sudo systemctl start vsftpd
sudo systemctl enable vsftpd
sudo mkdir /etc/ssl/private
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/ssl/private/vsftpd.key -out /etc/ssl/certs/vsftpd.crt
sudo firewall-cmd --add-port=21/tcp --permanent
sudo firewall-cmd --add-port=30000-31000/tcp --permanent
sudo firewall-cmd --reload
sudo vim /etc/vsftpd/vsftpd.conf
sudo vim /etc/vsftpd/user_list
su suha
cd
touch test.txt
```

Ajouter les users souhanté dans `/etc/vsftpd/user_list`, et voici la conf de `/etc/vsftpd/vsftpd.conf`
```
[axel@TP1-Secu-SE ~]$ sudo cat /etc/vsftpd/vsftpd.conf | grep -E "^#" -v
anonymous_enable=NO
local_enable=YES
write_enable=YES
local_umask=022
dirmessage_enable=YES
xferlog_enable=YES
connect_from_port_20=YES
xferlog_std_format=YES
chroot_local_user=YES
allow_writeable_chroot=YES
listen=NO
listen_ipv6=YES
pam_service_name=vsftpd
userlist_enable=YES
userlist_file=/etc/vsftpd/user_list
userlist_deny=NO
ssl_enable=YES
force_local_logins_ssl=YES
force_local_data_ssl=YES
allow_anon_ssl=NO
ssl_tlsv1=YES
ssl_tlsv1_1=YES
ssl_tlsv1_2=YES
ssl_sslv2=NO
ssl_sslv3=NO
require_ssl_reuse=NO
rsa_cert_file=/etc/ssl/certs/vsftpd.crt
rsa_private_key_file=/etc/ssl/private/vsftpd.key
ssl_ciphers=HIGH
pasv_min_port=30000
pasv_max_port=31000
```

Droit des clés :
```
[axel@TP1-Secu-SE ~]$ sudo ls -la /etc/ssl/private/vsftpd.key
-rw-------. 1 root root 1700 Mar  2 05:10 /etc/ssl/private/vsftpd.key
[axel@TP1-Secu-SE ~]$ sudo ls -la /etc/ssl/certs/vsftpd.crt
-rw-------. 1 root root 1237 Mar  2 05:10 /etc/ssl/certs/vsftpd.crt
```

Preuve que ça fonctionne :
```
axel@Dell-G15:~$ lftp -u suha,AxelBianca1234! -e "set ftp:ssl-force yes; set ftp:ssl-protect-data yes; set ssl:verify-certificate no" ftp://10.1.1.11
lftp suha@10.1.1.11:~> ls
-rw-r--r--    1 1002     1008            0 Mar 02 05:24 test.txt
lftp suha@10.1.1.11:/> 
```