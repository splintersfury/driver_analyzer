FROM eclipse-temurin:21-jdk-jammy

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
RUN pip3 install --no-cache-dir -r requirements.txt

# Setup Ghidra
COPY ghidra.zip .
RUN unzip ghidra.zip && \
    mv ghidra_* ghidra && \
    rm ghidra.zip

ENV GHIDRA_HOME=/app/ghidra

# Copy service scripts
COPY patch_differ.py .
COPY ExportDecompiled.py .
COPY rule_engine.py .

# Rules directory will be mounted via docker-compose
ENV AUTOPIFF_RULES_DIR=/app/rules

CMD ["python3", "patch_differ.py"]
