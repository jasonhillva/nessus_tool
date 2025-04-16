#!/usr/bin/env python3
import os
import time
import json
import requests
from urllib3.exceptions import InsecureRequestWarning

# Suppress SSL warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class NessusClient:
    def __init__(self, url, username, password, verify=False):
        """Initialize Nessus API client"""
        self.url = url.rstrip('/')
        self.username = username
        self.password = password
        self.verify = verify
        self.token = None
        self.headers = {'Content-Type': 'application/json'}
        
    def login(self):
        """Login to Nessus server and get access token"""
        payload = {'username': self.username, 'password': self.password}
        
        try:
            response = requests.post(
                f"{self.url}/session",
                data=json.dumps(payload),
                headers=self.headers,
                verify=self.verify
            )
            
            if response.status_code == 200:
                self.token = response.json().get('token')
                self.headers['X-Cookie'] = f"token={self.token}"
                print("[OK] Successfully logged in to Nessus server")
                return True
            else:
                print(f"[ERROR] Login failed: {response.status_code} - {response.text}")
                return False
        except Exception as e:
            print(f"[ERROR] Connection error: {str(e)}")
            return False
            
    def logout(self):
        """Logout from Nessus server"""
        if not self.token:
            return
            
        try:
            response = requests.delete(
                f"{self.url}/session",
                headers=self.headers,
                verify=self.verify
            )
            
            if response.status_code == 200:
                print("[OK] Successfully logged out from Nessus server")
                self.token = None
            else:
                print(f"[ERROR] Logout failed: {response.status_code} - {response.text}")
        except Exception as e:
            print(f"[ERROR] Error during logout: {str(e)}")
    
    def get_scans(self):
        """Get list of available scans"""
        try:
            response = requests.get(
                f"{self.url}/scans",
                headers=self.headers,
                verify=self.verify
            )
            
            if response.status_code == 200:
                data = response.json()
                return data.get('scans', [])
            else:
                print(f"[ERROR] Failed to get scan list: {response.status_code} - {response.text}")
                return []
        except Exception as e:
            print(f"[ERROR] Error retrieving scans: {str(e)}")
            return []
    
    def display_scans(self):
        """Display available scans in a table format"""
        scans = self.get_scans()
        
        if not scans:
            print("No scans found on the server.")
            return []
        
        print("\n=== Available Scans ===")
        print(f"{'#':<5} {'ID':<10} {'Name':<50} {'Status':<15}")
        print("-" * 80)
        
        for i, scan in enumerate(scans, 1):
            # Format timestamp to readable date if available
            last_mod = scan.get('last_modification_date', 'N/A')
            if isinstance(last_mod, (int, float)) and last_mod > 0:
                last_mod = time.strftime("%Y-%m-%d %H:%M", time.localtime(last_mod))
                
            print(f"{i:<5} {scan.get('id', 'N/A'):<10} {scan.get('name', 'N/A')[:48]:<50} {scan.get('status', 'N/A'):<15}")
        
        return scans
    
    def export_scan(self, scan_id, format_id='nessus'):
        """Request a scan export"""
        payload = {'format': format_id}
        
        try:
            response = requests.post(
                f"{self.url}/scans/{scan_id}/export",
                headers=self.headers,
                data=json.dumps(payload),
                verify=self.verify
            )
            
            if response.status_code == 200:
                file_id = response.json().get('file')
                print(f"[OK] Export requested for scan {scan_id}, file ID: {file_id}")
                return file_id
            else:
                print(f"[ERROR] Export request failed: {response.status_code} - {response.text}")
                return None
        except Exception as e:
            print(f"[ERROR] Error requesting export: {str(e)}")
            return None
    
    def check_export_status(self, scan_id, file_id):
        """Check the status of an export"""
        try:
            response = requests.get(
                f"{self.url}/scans/{scan_id}/export/{file_id}/status",
                headers=self.headers,
                verify=self.verify
            )
            
            if response.status_code == 200:
                return response.json().get('status')
            else:
                print(f"[ERROR] Failed to check export status: {response.status_code} - {response.text}")
                return None
        except Exception as e:
            print(f"[ERROR] Error checking export status: {str(e)}")
            return None
    
    def download_export(self, scan_id, file_id, output_path, filename=None):
        """Download an export file"""
        try:
            response = requests.get(
                f"{self.url}/scans/{scan_id}/export/{file_id}/download",
                headers=self.headers,
                verify=self.verify,
                stream=True
            )
            
            if response.status_code == 200:
                # Determine filename
                if not filename:
                    # Try to get filename from Content-Disposition header
                    content_disposition = response.headers.get('Content-Disposition', '')
                    if 'filename=' in content_disposition:
                        filename = content_disposition.split('filename=')[1].strip('"')
                    else:
                        filename = f"scan_{scan_id}.nessus"
                
                # Ensure .nessus extension
                if not filename.lower().endswith('.nessus'):
                    filename += '.nessus'
                
                file_path = os.path.join(output_path, filename)
                
                # Download file
                with open(file_path, 'wb') as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        if chunk:
                            f.write(chunk)
                
                print(f"[OK] Downloaded to: {file_path}")
                return file_path
            else:
                print(f"[ERROR] Download failed: {response.status_code} - {response.text}")
                return None
        except Exception as e:
            print(f"[ERROR] Error downloading file: {str(e)}")
            return None
    
    def export_and_download(self, scan_id, output_path=".", filename=None, format_id="nessus", max_wait=300):
        """Export a scan and download when ready"""
        # Request export
        file_id = self.export_scan(scan_id, format_id)
        if not file_id:
            return None
        
        # Wait for export to be ready
        print(f"Waiting for export to complete...", end="", flush=True)
        start_time = time.time()
        dots = 0
        
        while True:
            if time.time() - start_time > max_wait:
                print("\n[ERROR] Export timed out after waiting too long")
                return None
            
            status = self.check_export_status(scan_id, file_id)
            
            if status == "ready":
                print("\n[OK] Export is ready!")
                break
            elif status == "error":
                print("\n[ERROR] Export failed on server")
                return None
            
            # Simple progress indicator
            dots = (dots + 1) % 4
            print(f"\rWaiting for export to complete{'.' * dots}{' ' * (3 - dots)}", end="", flush=True)
            time.sleep(3)
        
        # Download the export
        return self.download_export(scan_id, file_id, output_path, filename)