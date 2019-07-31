#!/bin/bash

chmod -R 777 home/foo/upload
chmod -R 777 home/user/upload

# cp -rf host/ssh_host_ed25519_key host/ssh_host_ed25519_key.pub host/ssh_host_rsa_key host/ssh_host_rsa_key.pub etc/ssh/
chown -R root /etc/ssh/ssh_host_ed25519_key
chmod 600 /etc/ssh/ssh_host_ed25519_key
chown -R root /etc/ssh/ssh_host_ed25519_key.pub
chmod 644 /etc/ssh/ssh_host_ed25519_key.pub
chown -R root /etc/ssh/ssh_host_rsa_key
chmod 600 /etc/ssh/ssh_host_rsa_key
chown -R root /etc/ssh/ssh_host_rsa_key.pub
chmod 644 /etc/ssh/ssh_host_rsa_key.pub 