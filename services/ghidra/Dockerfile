FROM eclipse-temurin:17-jdk

# Install system dependencies
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    unzip \
    wget \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy and install Python dependencies
COPY requirements.txt .
RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt

# Setup Ghidra
COPY ghidra.zip .
RUN unzip ghidra.zip && \
    mv ghidra_* ghidra && \
    rm ghidra.zip

ENV GHIDRA_HOME=/app/ghidra

# Copy service scripts
COPY karton_ghidra.py .
COPY ExportDecompiled.py .

CMD ["python3", "karton_ghidra.py"]
