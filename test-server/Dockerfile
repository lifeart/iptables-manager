FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    openssh-server \
    iptables \
    ipset \
    iproute2 \
    procps \
    sudo \
    at \
    && rm -rf /var/lib/apt/lists/*

# Setup SSH
RUN mkdir /var/run/sshd
RUN echo 'root:testpassword' | chpasswd
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
RUN sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config

# Setup some sample iptables rules on start
RUN printf '#!/bin/bash\n\
iptables -P INPUT ACCEPT\n\
iptables -P FORWARD DROP\n\
iptables -P OUTPUT ACCEPT\n\
iptables -A INPUT -i lo -j ACCEPT\n\
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n\
iptables -A INPUT -p tcp --dport 22 -j ACCEPT\n\
iptables -A INPUT -p tcp --dport 80 -j ACCEPT\n\
iptables -A INPUT -p tcp --dport 443 -j ACCEPT\n\
iptables -A INPUT -p icmp -j ACCEPT\n\
iptables -A INPUT -j DROP\n' > /setup-rules.sh && chmod +x /setup-rules.sh

EXPOSE 22

CMD ["/bin/bash", "-c", "/setup-rules.sh; /usr/sbin/sshd -D"]
