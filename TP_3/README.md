# TP3 : SELinux

## Les consignes :

### 3.1 Installation du systèmes d'exploitations :

Installation d'une VM rocky 9 minimal, sans interface graphique.

Mise à jour :
```
sudo dnf update -y
```

### 3.2 Sécurisation de l'administration du serveur :

1. Le serveur sera administré via SSH, aussi vous devrez renforcer la configuration de ce serveur
conformément aux recommandations de l’ANSSI 2. L’administrateur système, devra être le seul à pouvoir
établir une session distante SSH via son compte utilisateur et une biclef sécurisée.

```
[axel@TP3-Secu-SE ~]$ sudo grep -vE '^\s*#|^\s*$' /etc/ssh/sshd_config
Include /etc/ssh/sshd_config.d/*.conf
StrictModes yes
Ciphers aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
PermitEmptyPasswords no
MaxAuthTries 3
LoginGraceTime 30
PermitRootLogin no
PrintLastLog yes
AllowUsers axel
PermitUserEnvironment no
AllowTcpForwarding no
X11Forwarding no
PasswordAuthentication no
Port 2222
AuthorizedKeysFile	.ssh/authorized_keys
Subsystem	sftp	/usr/libexec/openssh/sftp-server
```

Explication :

#### 1. **StrictModes yes**  
Active les vérifications strictes des permissions des fichiers et répertoires utilisés par SSH. Cela empêche l'utilisation de clés ou fichiers de configuration avec des permissions trop permissives, réduisant ainsi le risque d'attaques.  

#### 2. **Ciphers aes256-ctr,aes192-ctr,aes128-ctr**  
Restreint les algorithmes de chiffrement aux versions AES en mode CTR considérées comme sécurisées et efficaces.  

#### 3. **MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com**  
Limite les MAC (Message Authentication Codes) aux versions SHA-2 avec Encrypt-Then-MAC (ETM) garantissant une meilleure intégrité et résistance aux attaques.  

#### 4. **PermitEmptyPasswords no**  
Interdit les connexions SSH avec un mot de passe vide, empêchant une grave faille de sécurité.  

#### 5. **MaxAuthTries 3**  
Réduit le nombre de tentatives de connexion à 3 avant qu'une session ne soit coupée. Cela limite les attaques par bruteforce.  

#### 6. **LoginGraceTime 30**  
Fixe un temps limite de 30 secondes pour s'authentifier. Si l'utilisateur ne s'authentifie pas à temps, la connexion est fermée. Cela réduit la surface d'attaque.  

#### 7. **PermitRootLogin no**  
Désactive la connexion SSH directe avec l'utilisateur root. Cela empêche les attaques bruteforce sur le compte administrateur et force l'utilisation d'un compte utilisateur avec élévation de privilèges (`sudo`).  

#### 8. **PrintLastLog yes**  
Affiche la date et l'heure de la dernière connexion réussie, permettant à l'utilisateur de détecter une éventuelle intrusion.  

#### 9. **AllowUsers axel**  
Restreint les connexions SSH à l'utilisateur axel uniquement, empêchant tout autre utilisateur de tenter une connexion.  

#### 10. **PermitUserEnvironment no**  
Empêche l'utilisateur de modifier l'environnement SSH (`~/.ssh/environment`). Cela évite des attaques où un attaquant pourrait injecter des variables nuisibles.  

#### 11. **AllowTcpForwarding no**  
Désactive le **TCP forwarding**, empêchant SSH d’être utilisé comme proxy ou tunnel pour rediriger du trafic réseau non autorisé.  

#### 12. **X11Forwarding no**  
Désactive le transfert X11, évitant ainsi que des applications graphiques soient exécutées à distance via SSH, ce qui pourrait représenter un risque de sécurité.  

#### 13. **PasswordAuthentication no**  
Désactive l'authentification par mot de passe, obligeant l'utilisation de clés SSH. Cela protège contre les attaques par bruteforce sur les mots de passe.  

#### 14. **Port 2222**  
Change le port SSH de 22 à 2222, réduisant ainsi les attaques automatisées cherchant à se connecter sur le port standard.  

2. Les flux réseaux entrants et sortant du serveur devront être strictement filtrés, et seul le trafic utile
devra être autorisé.

```
[axel@TP3-Secu-SE ~]$ sudo firewall-cmd --list-all
public (active)
  target: DROP
  icmp-block-inversion: no
  interfaces: enp0s3 enp0s8
  sources: 
  services: 
  ports: 2222/tcp
  protocols: 
  forward: yes
  masquerade: no
  forward-ports: 
  source-ports: 
  icmp-blocks: 
  rich rules: 
```

### 3.3 Installation d’un serveur Web :

1. Dans un premier temps, installer un serveur web apache avec sa configuration par défaut. Puis
Tentez d’y accéder via votre navigateur web.

```
sudo dnf install httpd -y
sudo systemctl start httpd
sudo systemctl enable httpd
sudo firewall-cmd --add-port=80/tcp --permanent
sudo firewall-cmd --reload
```

Preuve :
```
axel@Dell-G15:~$ curl http://10.1.1.13
<!doctype html>
<html>
  <head>
    <meta charset='utf-8'>
    <meta name='viewport' content='width=device-width, initial-scale=1'>
    <title>HTTP Server Test Page powered by: Rocky Linux</title>
    <style type="text/css">
      /*<![CDATA[*/
      
      html {
        height: 100%;
        width: 100%;
...
```

2. Installer ensuite SELinux si celui-ci n’est pas déjà présent sur la machine

```
[axel@TP3-Secu-SE ~]$ sestatus
SELinux status:                 enabled
SELinuxfs mount:                /sys/fs/selinux
SELinux root directory:         /etc/selinux
Loaded policy name:             targeted
Current mode:                   permissive
Mode from config file:          permissive
Policy MLS status:              enabled
Policy deny_unknown status:     allowed
Memory protection checking:     actual (secure)
Max kernel policy version:      33
```

3. SELinux dispose de différents modes, quels sont-ils ? Est a quoi sert chaque mode ?

