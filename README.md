# Nessus Tool

A comprehensive tool for interacting with Tenable Nessus vulnerability scanners. This tool allows you to download scan results, convert .nessus files to Excel/CSV formats, and provides a user-friendly web interface for managing scans.

## Features

- Download Nessus scans from a Nessus server
- Convert .nessus files to Excel spreadsheets or CSV files 
- Combined mode to download and convert in one step
- User-friendly web interface with dashboard for scan management
- Create and manage scans directly through the interface
- Batch processing of multiple scans
- Dark/light mode interface
- Excel reports with color-coded severity highlighting
- Docker container support for easy deployment on any platform

## Installation

### Standard Installation

```bash
pip install -e .
```

### Docker Installation

1. Make sure you have Docker and Docker Compose installed on your system
2. Clone this repository
3. Build and run the Docker container:

```bash
# Create output directories
mkdir -p uploads nessus_scans nessus_csv

# Build the Docker image
docker-compose build

# Run the container with web interface (default)
docker-compose up
```

## Usage

### Web Interface

The web interface is the recommended way to use the Nessus Tool. It provides a user-friendly dashboard for managing your scans and exports.

```bash
# Start the web interface
nessus-tool web

# With custom host and port
nessus-tool web --host 127.0.0.1 --port 8080
```

Then open your browser and navigate to `http://localhost:5000` (or your custom host/port)

Features available in the web interface:
- Connect to your Nessus server
- Browse all available scans
- Export scans to various formats (Nessus, Excel, CSV)
- Batch process multiple scans at once
- Create new scans directly through the interface
- Dark/light mode toggle for comfortable viewing

### Command Line

The tool has three main modes of operation in the command line:

1. **Download Mode**: Downloads scan results from a Nessus server
2. **Convert Mode**: Converts .nessus files to Excel/CSV
3. **Combined Mode**: Downloads and converts in one step

```bash
# Download mode
nessus-tool download -u https://nessus-server:8834 -n username -p password -i

# Convert mode
nessus-tool convert nessus_file1.nessus nessus_file2.nessus -o output.xlsx

# Combined mode
nessus-tool combined -u https://nessus-server:8834 -n username -p password -i -o report.xlsx
```

### Docker Container

Run the container with environment variables to specify your Nessus server details:

```bash
# Run with web interface (default)
docker run -p 5000:5000 \
           -v $(pwd)/uploads:/app/uploads \
           -v $(pwd)/nessus_scans:/app/nessus_scans \
           -v $(pwd)/nessus_csv:/app/nessus_csv \
           nessus-tool

# Run with default combined mode
docker run -e NESSUS_URL=https://your-nessus-server:8834 \
           -e NESSUS_USERNAME=your-username \
           -e NESSUS_PASSWORD=your-password \
           -v $(pwd)/output:/app/output \
           nessus-tool

# Run with custom command
docker run -v $(pwd)/output:/app/output \
           nessus-tool download -u https://your-nessus-server:8834 -n your-username -p your-password -i -o /app/output
```

Using docker-compose:

```bash
# Edit docker-compose.yml to customize the command if needed
# Then run:
docker-compose up
```

## Environment Variables

When using Docker, you can configure the tool using these environment variables:

- `NESSUS_URL`: URL of your Nessus server (default: https://localhost:8834)
- `NESSUS_USERNAME`: Your Nessus username
- `NESSUS_PASSWORD`: Your Nessus password
- `SECRET_KEY`: Secret key for the web application session (default: randomly generated)

## Report Features

The Excel and CSV reports include:
- Summary sheet with vulnerability counts by severity
- Detailed vulnerability information including:
  - Host details (IP, FQDN, Operating System)
  - Vulnerability details (Plugin ID, Name, Severity)
  - CVSS base scores
  - CVE references
  - Remediation recommendations
- Color-coded severity highlighting
- Automatic column sizing for better readability

## Output

Output files will be stored in the following directories:
- Downloaded .nessus files: `nessus_scans` directory
- CSV exports: `nessus_csv` directory
- Web interface exports: `uploads` directory
- Or in the specified output directory when using the command line
