FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies and Wine
RUN dpkg --add-architecture i386 && \
    apt-get update && \
    apt-get install -y wget unzip python3 python3-pip wine32 wine64 && \
    rm -rf /var/lib/apt/lists/*

# Install python deps
RUN pip3 install karton-core

# Setup Sysinternals
RUN mkdir -p /opt/sysinternals && \
    wget -O /tmp/Sigcheck.zip https://download.sysinternals.com/files/Sigcheck.zip && \
    unzip /tmp/Sigcheck.zip -d /opt/sysinternals && \
    rm /tmp/Sigcheck.zip && \
    chmod +x /opt/sysinternals/sigcheck.exe

WORKDIR /app
COPY karton_signature.py .

CMD ["python3", "karton_signature.py"]
