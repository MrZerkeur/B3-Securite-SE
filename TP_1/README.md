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