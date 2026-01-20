FROM ubuntu:20.04

# install 32-bit support and dependencies (from IOCTLance README)
RUN dpkg --add-architecture i386 && \
    DEBIAN_FRONTEND=noninteractive apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y tzdata git build-essential python3 python3-pip python3-dev \
    openjdk-8-jdk zlib1g:i386 libtinfo5:i386 libstdc++6:i386 libgcc1:i386 libc6:i386 libssl-dev nasm binutils-multiarch \
    qtdeclarative5-dev libpixman-1-dev libglib2.0-dev debian-archive-keyring debootstrap libtool libreadline-dev cmake \
    libffi-dev libxslt1-dev libxml2-dev && \
    rm -rf /var/lib/apt/lists/*

# Install python deps
RUN pip install angr==9.2.18 ipython==8.5.0 ipdb==0.13.9 capstone==5.0.1 karton-core

# Setup environment
RUN useradd -ms /bin/bash ioctlance
WORKDIR /home/ioctlance

# Copy IOCTLance source
COPY src/analysis /home/ioctlance/analysis/
# COPY src/evaluation /home/ioctlance/evaluation/
# COPY src/dataset /home/ioctlance/dataset/

# Copy Karton service
COPY karton_ioctlance.py .

CMD ["python3", "karton_ioctlance.py"]
