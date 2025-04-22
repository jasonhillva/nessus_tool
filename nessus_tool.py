#!/usr/bin/env python3
import argparse
import os
from nessus_downloader import run_download_scans
from nessus_converter import run_convert_nessus
from web_app import run_webapp

def main():
    """Main function to run the combined Nessus tool"""
    parser = argparse.ArgumentParser(
        description='Nessus Tool - Download scans, convert .nessus files, and web interface',
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    # Create subparsers for different modes
    subparsers = parser.add_subparsers(dest='mode', help='Operation mode')
    
    # Download mode
    download_parser = subparsers.add_parser('download', help='Download Nessus scans')
    download_parser.add_argument('-u', '--url', default='https://localhost:8834',
                            help='Nessus server URL (default: https://localhost:8834)')
    download_parser.add_argument('-n', '--username', required=True,
                            help='Nessus username')
    download_parser.add_argument('-p', '--password', 
                            help='Nessus password (if not provided, will prompt)')
    download_parser.add_argument('-o', '--output-dir', default='./nessus_scans',
                            help='Output directory for downloaded scans (default: ./nessus_scans)')
    download_parser.add_argument('-i', '--insecure', action='store_true',
                            help='Allow insecure connections (skip SSL verification)')
    download_parser.add_argument('-a', '--all-scans', action='store_true',
                            help='Download all available scans without prompting')
    download_parser.add_argument('-s', '--scan-ids', 
                            help='Comma-separated list of scan IDs to download')
    
    # Convert mode
    convert_parser = subparsers.add_parser('convert', help='Convert .nessus files to Excel/CSV')
    convert_parser.add_argument('nessus_files', nargs='+', help='Nessus files to parse')
    convert_parser.add_argument('-o', '--output-file', 
                           help='Output Excel file (for Excel output)')
    convert_parser.add_argument('-d', '--output-dir', default='./nessus_csv',
                           help='Output directory for CSV files (for CSV output)')
    convert_parser.add_argument('-f', '--output-format', choices=['excel', 'csv'], default='excel',
                           help='Output format: excel or csv (default: excel)')
    
    # Combined mode
    combined_parser = subparsers.add_parser('combined', help='Download and convert Nessus scans')
    combined_parser.add_argument('-u', '--url', default='https://localhost:8834',
                             help='Nessus server URL (default: https://localhost:8834)')
    combined_parser.add_argument('-n', '--username', required=True,
                             help='Nessus username')
    combined_parser.add_argument('-p', '--password', 
                             help='Nessus password (if not provided, will prompt)')
    combined_parser.add_argument('--download-dir', default='./nessus_scans',
                             help='Directory for downloaded scans (default: ./nessus_scans)')
    combined_parser.add_argument('-i', '--insecure', action='store_true',
                             help='Allow insecure connections (skip SSL verification)')
    combined_parser.add_argument('-a', '--all-scans', action='store_true',
                             help='Download all available scans without prompting')
    combined_parser.add_argument('-s', '--scan-ids', 
                             help='Comma-separated list of scan IDs to download')
    combined_parser.add_argument('-o', '--output-file', 
                             help='Output Excel file (for Excel output)')
    combined_parser.add_argument('-d', '--output-dir', default='./nessus_csv',
                             help='Output directory for CSV files (for CSV output)')
    combined_parser.add_argument('-f', '--output-format', choices=['excel', 'csv'], default='excel',
                             help='Output format: excel or csv (default: excel)')
    
    # Web mode (new)
    web_parser = subparsers.add_parser('web', help='Start the web interface')
    web_parser.add_argument('--host', default='0.0.0.0',
                         help='Host to bind to (default: 0.0.0.0, all interfaces)')
    web_parser.add_argument('-p', '--port', type=int, default=5000,
                         help='Port to bind to (default: 5000)')
    web_parser.add_argument('--debug', action='store_true',
                         help='Enable debug mode')
    web_parser.add_argument('--upload-folder', default='./uploads',
                         help='Folder to store uploaded and processed files (default: ./uploads)')
    
    args = parser.parse_args()
    
    # If no mode specified, print help and exit
    if not args.mode:
        parser.print_help()
        return
    
    # Execute the selected mode
    if args.mode == 'download':
        run_download_scans(args)
    
    elif args.mode == 'convert':
        run_convert_nessus(args)
    
    elif args.mode == 'combined':
        # Set up args for download
        download_args = argparse.Namespace(
            url=args.url,
            username=args.username,
            password=args.password,
            output_dir=args.download_dir,
            insecure=args.insecure,
            all_scans=args.all_scans,
            scan_ids=args.scan_ids
        )
        
        # Download scans
        downloaded_files = run_download_scans(download_args)
        
        if downloaded_files:
            # Set up args for convert
            convert_args = argparse.Namespace(
                nessus_files=downloaded_files,
                output_file=args.output_file,
                output_dir=args.output_dir,
                output_format=args.output_format
            )
            
            # Convert downloaded scans
            run_convert_nessus(convert_args)
        else:
            print("[WARNING] No scans were downloaded, skipping conversion step.")
    
    elif args.mode == 'web':
        # Set environment variables for Flask
        if args.upload_folder:
            os.environ['UPLOAD_FOLDER'] = args.upload_folder
            # Ensure upload directory exists
            os.makedirs(args.upload_folder, exist_ok=True)
        
        # Run the web application
        run_webapp(host=args.host, port=args.port, debug=args.debug)

if __name__ == "__main__":
    main()