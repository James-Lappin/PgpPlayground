FROM atmoz/sftp:latest

RUN apt-get update && apt-get install -y dos2unix

RUN mkdir -p /etc/ssh/

RUN mkdir -p /etc/ssh

COPY ssh_host_ed25519_key /etc/ssh
RUN chown -R root /etc/ssh/ssh_host_ed25519_key
RUN chmod 600 /etc/ssh/ssh_host_ed25519_key
RUN dos2unix /etc/ssh/ssh_host_ed25519_key

COPY ssh_host_rsa_key /etc/ssh
RUN chown -R root /etc/ssh/ssh_host_rsa_key
RUN chmod 600 /etc/ssh/ssh_host_rsa_key
RUN dos2unix /etc/ssh/ssh_host_rsa_key

COPY ssh_host_ed25519_key.pub /etc/ssh
RUN chown -R root /etc/ssh/ssh_host_ed25519_key.pub
RUN chmod 644 /etc/ssh/ssh_host_ed25519_key.pub
RUN dos2unix /etc/ssh/ssh_host_ed25519_key.pub

COPY ssh_host_rsa_key.pub /etc/ssh
RUN chown -R root /etc/ssh/ssh_host_rsa_key.pub
RUN chmod 644 /etc/ssh/ssh_host_rsa_key.pub
RUN dos2unix /etc/ssh/ssh_host_rsa_key.pub

COPY add-folders.sh /etc/sftp.d/
RUN chmod +x /etc/sftp.d/add-folders.sh
RUN dos2unix /etc/sftp.d/add-folders.sh