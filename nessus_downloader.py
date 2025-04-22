#!/usr/bin/env python3
import os
import getpass
from nessus_client import NessusClient

class NessusDownloader:
    """Class to handle downloading scans from Nessus server"""
    
    def __init__(self, url, username, password, verify=False):
        """Initialize the downloader with connection details"""
        self.client = NessusClient(url, username, password, verify)
        
    def download_scan(self, scan_id, output_dir=".", filename=None):
        """
        Download a specific scan by ID
        
        Args:
            scan_id (int): The ID of the scan to download
            output_dir (str): Directory to save the scan to
            filename (str, optional): Custom filename for the downloaded scan
            
        Returns:
            str: Path to the downloaded file or None if download failed
        """
        # Ensure output directory exists
        if not os.path.exists(output_dir):
            try:
                os.makedirs(output_dir)
                print(f"[OK] Created output directory: {output_dir}")
            except Exception as e:
                print(f"[ERROR] Error creating directory: {str(e)}")
                return None
        
        # Login to Nessus
        if not self.client.token:
            if not self.client.login():
                print("[ERROR] Failed to log in to Nessus server")
                return None
        
        # Download the scan
        try:
            file_path = self.client.export_and_download(scan_id, output_dir, filename)
            return file_path
        except Exception as e:
            print(f"[ERROR] Error downloading scan: {str(e)}")
            return None
        finally:
            # No need to logout as the client will handle this
            pass

def parse_selection(selection, max_value):
    """
    Parse user input for scan selection
    Supports: 
    - Single numbers (1)
    - Comma-separated values (1,3,5)
    - Ranges (1-5)
    - Combinations (1,3-5,7)
    """
    indices = set()
    
    if selection.lower() == 'all':
        return list(range(1, max_value + 1))
    
    if selection.lower() in ['q', 'quit', 'exit']:
        return []
    
    parts = [p.strip() for p in selection.split(',')]
    
    for part in parts:
        if '-' in part:
            try:
                start, end = [int(x) for x in part.split('-', 1)]
                if 1 <= start <= end <= max_value:
                    indices.update(range(start, end + 1))
                else:
                    print(f"[WARNING] Range {part} is outside valid bounds (1-{max_value})")
            except ValueError:
                print(f"[WARNING] Invalid range: {part}")
        else:
            try:
                num = int(part)
                if 1 <= num <= max_value:
                    indices.add(num)
                else:
                    print(f"[WARNING] Value {num} is outside valid bounds (1-{max_value})")
            except ValueError:
                print(f"[WARNING] Invalid value: {part}")
    
    return sorted(list(indices))

def interactive_scan_selection(client, output_dir):
    """Interactive scan selection and download process"""
    # Get and display scans
    scans = client.display_scans()
    if not scans:
        return []
    
    # Start interactive selection
    print("\n=== Interactive Scan Selection ===")
    print("Enter scan numbers to download. Options:")
    print("- Individual scans (e.g., 1)")
    print("- Comma-separated list (e.g., 1,3,5)")
    print("- Range of scans (e.g., 1-5)")
    print("- Combination of above (e.g., 1,3-5,7)")
    print("- 'all' to select all scans")
    print("- 'q' to quit")
    
    successful_downloads = []
    
    while True:
        selection = input("\nEnter scan selection (or 'q' to finish): ").strip()
        selected = parse_selection(selection, len(scans))
        
        if not selected:
            if selection.lower() in ['q', 'quit', 'exit']:
                print("Finished scan selection.")
            else:
                print("No valid scans selected.")
            break
            
        # Process the selected scans
        for index in selected:
            scan = scans[index - 1]
            scan_id = scan.get('id')
            scan_name = scan.get('name', f"scan_{scan_id}")
            
            print(f"\n[>] Downloading scan: {scan_name} (ID: {scan_id})")
            
            # Create safe filename from scan name
            safe_name = "".join(c if c.isalnum() or c in ['-', '_', '.'] else '_' for c in scan_name)
            filename = f"{safe_name}.nessus"
            
            # Export and download
            file_path = client.export_and_download(scan_id, output_dir, filename)
            
            if file_path:
                successful_downloads.append(file_path)
                
        # Ask if user wants to continue selecting scans
        print("\nCurrent download status:")
        print(f"- Downloaded: {len(successful_downloads)}")
        print(f"- Remaining: {len(scans) - len(set([scans.index(scan) + 1 for scan in scans]) - set([s-1 for s in selected]))}")
    
    return successful_downloads

def run_download_scans(args):
    """Run the scan download functionality"""
    print("\n=== Nessus Scan Downloader ===")
    
    # Get password if not provided
    password = args.password
    if not password:
        password = getpass.getpass("Enter password: ")
    
    # Prepare output directory
    output_dir = args.output_dir
    if not os.path.exists(output_dir):
        try:
            os.makedirs(output_dir)
            print(f"[OK] Created output directory: {output_dir}")
        except Exception as e:
            print(f"[ERROR] Error creating directory: {str(e)}")
            output_dir = "."
    
    # Connect to Nessus server
    client = NessusClient(args.url, args.username, password, verify=not args.insecure)
    
    try:
        # Login
        if not client.login():
            return []
        
        # Handle direct scan ID list if provided
        if args.scan_ids:
            scan_ids = []
            try:
                for part in args.scan_ids.split(','):
                    part = part.strip()
                    if part:
                        scan_ids.append(int(part))
            except ValueError:
                print("[ERROR] Invalid scan ID format. Use comma-separated numbers.")
                return []
                
            if scan_ids:
                successful_downloads = []
                for scan_id in scan_ids:
                    print(f"\n[>] Downloading scan with ID: {scan_id}")
                    file_path = client.export_and_download(scan_id, output_dir)
                    if file_path:
                        successful_downloads.append(file_path)
                
                # Print summary
                if successful_downloads:
                    print("\n=== Download Summary ===")
                    for path in successful_downloads:
                        print(f"[OK] {path}")
                    print(f"\n[OK] Successfully downloaded {len(successful_downloads)} of {len(scan_ids)} scans.")
                else:
                    print("\n[ERROR] No scans were successfully downloaded.")
                return successful_downloads
        
        # Handle automatic download of all scans
        if args.all_scans:
            scans = client.display_scans()
            if not scans:
                return []
                
            successful_downloads = []
            for i, scan in enumerate(scans, 1):
                scan_id = scan.get('id')
                scan_name = scan.get('name', f"scan_{scan_id}")
                
                print(f"\n[>] Downloading scan {i}/{len(scans)}: {scan_name} (ID: {scan_id})")
                
                # Create safe filename from scan name
                safe_name = "".join(c if c.isalnum() or c in ['-', '_', '.'] else '_' for c in scan_name)
                filename = f"{safe_name}.nessus"
                
                # Export and download
                file_path = client.export_and_download(scan_id, output_dir, filename)
                
                if file_path:
                    successful_downloads.append(file_path)
            
            # Print summary
            if successful_downloads:
                print("\n=== Download Summary ===")
                for path in successful_downloads:
                    print(f"[OK] {path}")
                print(f"\n[OK] Successfully downloaded {len(successful_downloads)} of {len(scans)} scans.")
            else:
                print("\n[ERROR] No scans were successfully downloaded.")
            return successful_downloads
        
        # Interactive mode
        successful_downloads = interactive_scan_selection(client, output_dir)
        
        # Print final summary
        if successful_downloads:
            print("\n=== Final Download Summary ===")
            for path in successful_downloads:
                print(f"[OK] {path}")
            print(f"\n[OK] Successfully downloaded {len(successful_downloads)} scans.")
        else:
            print("\n[WARNING] No scans were downloaded.")
        
        return successful_downloads
    
    finally:
        # Logout
        client.logout()
        
    return []