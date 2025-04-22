# Nessus Tool

A comprehensive tool for interacting with Tenable Nessus vulnerability scanners. This tool allows you to download scan results and convert .nessus files to Excel/CSV formats.

## Features

- Download Nessus scans from a Nessus server
- Convert .nessus files to Excel spreadsheets or CSV files
- Combined mode to download and convert in one step
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
# Create an output directory
mkdir -p output

# Build the Docker image
docker-compose build

# Run the container with your Nessus credentials
docker-compose run -e NESSUS_URL=https://your-nessus-server:8834 -e NESSUS_USERNAME=your-username -e NESSUS_PASSWORD=your-password nessus-tool
```

## Usage

### Command Line

The tool has three main modes of operation:

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

## Output

Output files will be stored in the `output` directory when using Docker, or in the specified output directory when using the command line.
