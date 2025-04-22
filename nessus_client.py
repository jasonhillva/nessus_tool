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
        # Ensure URL starts with https:// and has no trailing slash
        if not url.lower().startswith('http'):
            url = 'https://' + url
        
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
            print(f"[DEBUG] Attempting to connect to {self.url} with verify={self.verify}")
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
        except requests.exceptions.SSLError as e:
            print(f"[ERROR] SSL Certificate error: {str(e)}")
            print("[HINT] Your Nessus server likely uses a self-signed certificate. Try unchecking 'Verify SSL Certificate'")
            return False
        except requests.exceptions.ConnectionError as e:
            print(f"[ERROR] Connection error: {str(e)}")
            print("[HINT] Check if your Nessus server is running and the URL is correct")
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
    
    def list_scans(self):
        """Get list of available scans"""
        if not self.token:
            if not self.login():
                return {"error": "Failed to login to Nessus server"}
        
        try:
            response = requests.get(
                f"{self.url}/scans",
                headers=self.headers,
                verify=self.verify
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                print(f"[ERROR] Failed to get scan list: {response.status_code} - {response.text}")
                return {"error": f"Failed to get scan list: {response.status_code}"}
        except Exception as e:
            print(f"[ERROR] Error retrieving scans: {str(e)}")
            return {"error": f"Error retrieving scans: {str(e)}"}
    
    def create_scan(self, name, targets, template_uuid="731a8e52-3ea6-a291-ec0a-d2ff0619c19d", folder_id=None):
        """
        Create a new scan with the specified name and targets.
        
        Args:
            name (str): Name of the scan
            targets (str): Target IPs, hostnames, or ranges
            template_uuid (str): Template UUID to use (default is basic network scan)
            folder_id (int, optional): Folder ID to place the scan in
            
        Returns:
            dict: Response containing the created scan information
        """
        if not self.token:
            if not self.login():
                return {"error": "Failed to login to Nessus server"}
        
        scan_data = {
            "uuid": template_uuid,
            "settings": {
                "name": name,
                "text_targets": targets
            }
        }
        
        if folder_id:
            scan_data["settings"]["folder_id"] = folder_id
        
        try:
            response = requests.post(
                f"{self.url}/scans",
                headers=self.headers,
                data=json.dumps(scan_data),
                verify=self.verify
            )
            
            if response.status_code in [200, 201]:
                print(f"[OK] Scan '{name}' created successfully")
                return response.json()
            else:
                print(f"[ERROR] Failed to create scan: {response.status_code} - {response.text}")
                return {"error": f"Failed to create scan: {response.status_code}"}
        except Exception as e:
            print(f"[ERROR] Error creating scan: {str(e)}")
            return {"error": f"Error creating scan: {str(e)}"}
    
    def launch_scan(self, scan_id):
        """
        Launch a scan with the specified ID.
        
        Args:
            scan_id (int): ID of the scan to launch
            
        Returns:
            dict: Response containing the scan launch information
        """
        if not self.token:
            if not self.login():
                return {"error": "Failed to login to Nessus server"}
        
        try:
            response = requests.post(
                f"{self.url}/scans/{scan_id}/launch",
                headers=self.headers,
                verify=self.verify
            )
            
            if response.status_code == 200:
                print(f"[OK] Scan (ID: {scan_id}) launched successfully")
                return response.json()
            else:
                print(f"[ERROR] Failed to launch scan: {response.status_code} - {response.text}")
                return {"error": f"Failed to launch scan: {response.status_code}"}
        except Exception as e:
            print(f"[ERROR] Error launching scan: {str(e)}")
            return {"error": f"Error launching scan: {str(e)}"}
    
    def get_scan_details(self, scan_id):
        """
        Get details of a specific scan.
        
        Args:
            scan_id (int): ID of the scan
            
        Returns:
            dict: Response containing the scan details
        """
        if not self.token:
            if not self.login():
                return {"error": "Failed to login to Nessus server"}
        
        try:
            response = requests.get(
                f"{self.url}/scans/{scan_id}",
                headers=self.headers,
                verify=self.verify
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                print(f"[ERROR] Failed to get scan details: {response.status_code} - {response.text}")
                return {"error": f"Failed to get scan details: {response.status_code}"}
        except Exception as e:
            print(f"[ERROR] Error retrieving scan details: {str(e)}")
            return {"error": f"Error retrieving scan details: {str(e)}"}
    
    def get_scan_templates(self):
        """
        Get a list of available scan templates.
        
        Returns:
            dict: Response containing the template list
        """
        if not self.token:
            if not self.login():
                return {"error": "Failed to login to Nessus server"}
        
        try:
            response = requests.get(
                f"{self.url}/editor/scan/templates",
                headers=self.headers,
                verify=self.verify
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                print(f"[ERROR] Failed to get scan templates: {response.status_code} - {response.text}")
                return {"error": f"Failed to get scan templates: {response.status_code}"}
        except Exception as e:
            print(f"[ERROR] Error retrieving scan templates: {str(e)}")
            return {"error": f"Error retrieving scan templates: {str(e)}"}
    
    def get_folders(self):
        """
        Get a list of available folders.
        
        Returns:
            dict: Response containing the folder list
        """
        if not self.token:
            if not self.login():
                return {"error": "Failed to login to Nessus server"}
        
        try:
            response = requests.get(
                f"{self.url}/folders",
                headers=self.headers,
                verify=self.verify
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                print(f"[ERROR] Failed to get folders: {response.status_code} - {response.text}")
                return {"error": f"Failed to get folders: {response.status_code}"}
        except Exception as e:
            print(f"[ERROR] Error retrieving folders: {str(e)}")
            return {"error": f"Error retrieving folders: {str(e)}"}