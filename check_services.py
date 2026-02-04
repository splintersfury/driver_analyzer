import subprocess
import logging
import os
import sys

# Configure logging
LOG_FILE = "/home/splintersfury/Documents/driver_analyzer/service_monitor.log"
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)

PROJECT_DIR = "/home/splintersfury/Documents/driver_analyzer"

# Required service patterns (partial matching to handle container ID prefixes)
# These are the core infrastructure services that must be running
REQUIRED_SERVICES = [
    "mwdb-core",
    "mwdb-web",
    "karton-system",
    "karton-dashboard",
    "mwdb-postgres",
    "mwdb-redis",
    "karton-redis",
    "karton-rabbitmq",
    "minio"
]

def check_containers():
    try:
        # Get list of running container names
        result = subprocess.run(
            ["/usr/bin/docker", "ps", "--format", "{{.Names}}"],
            capture_output=True,
            text=True,
            check=True
        )
        running_containers = result.stdout.splitlines()

        missing = []
        for service in REQUIRED_SERVICES:
            # Use partial matching - container name must contain the service pattern
            # This handles prefixes like "01eaca0cbdf2_driver_analyzer-karton-rabbitmq-1"
            found = any(service in container for container in running_containers)
            if not found:
                missing.append(service)

        return missing
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to check docker status: {e}")
        return None

def restart_services():
    logging.info("Attempting to restart services...")
    try:
        # Use docker compose v2 (Go-based) instead of docker-compose v1 (Python-based)
        subprocess.run(
            ["/usr/bin/docker", "compose", "up", "-d"],
            cwd=PROJECT_DIR,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        logging.info("Services restart command issued successfully.")
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to restart services: {e.stderr.decode()}")

def main():
    logging.info("Starting service check...")
    missing = check_containers()
    
    if missing is None:
        sys.exit(1)
        
    if missing:
        logging.warning(f"The following containers are NOT running: {', '.join(missing)}")
        restart_services()
    else:
        logging.info("All core services are running.")

if __name__ == "__main__":
    main()
