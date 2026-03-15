FROM kalilinux/kali-rolling:latest
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl nmap nikto gobuster sqlmap dirb wfuzz netcat-traditional net-tools dnsutils wget jq && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*
WORKDIR /scripts
CMD ["sleep", "infinity"]

