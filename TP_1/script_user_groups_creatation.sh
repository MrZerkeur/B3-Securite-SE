#!/bin/bash

sudo groupadd managers 2>/dev/null
sudo groupadd admins 2>/dev/null
sudo groupadd sysadmins 2>/dev/null
sudo groupadd artists 2>/dev/null
sudo groupadd devs 2>/dev/null
sudo groupadd rh 2>/dev/null

USERS_AND_GROUPS=(
    "suha:managers,admins"
    "daniel:admins,sysadmins"
    "liam:admins"
    "noah:managers,artists"
    "alysha:artists"
    "rose:artists,devs"
    "sadia:devs"
    "jakub:devs"
    "lev:devs"
    "grace:rh"
    "lucia:rh"
    "oliver:rh"
    "nginx:"
)

for user_data in "${USERS_AND_GROUPS[@]}"; do
    username=$(echo "$user_data" | cut -d: -f1)
    groups=$(echo "$user_data" | cut -d: -f2)
    
    if [ -z "$groups" ]; then
        sudo useradd -m -s /bin/bash "$username"
    else
        sudo useradd -m -s /bin/bash -G "$groups" "$username"
    fi
    
    password=$(LC_ALL=C tr -dc 'A-Za-z0-9!@#$%^&*()_+{}[]<>?-' < /dev/urandom | head -c 20)
    
    echo "$username:$password" | sudo chpasswd
    
    echo "Utilisateur $username créé"
    echo "Mot de passe: $password"
    echo "--------------------------------------"
done