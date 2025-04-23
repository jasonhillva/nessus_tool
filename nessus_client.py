#!/usr/bin/env python3
import os
import time
import json
import logging
import traceback
import requests
from urllib3.exceptions import InsecureRequestWarning
import http.client as http_client

# Set up detailed HTTP request logging
http_client.HTTPConnection.debuglevel = 1
requests_log = logging.getLogger("requests.packages.urllib3")
requests_log.setLevel(logging.DEBUG)
requests_log.propagate = True

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('nessus_client.log')
    ]
)
logger = logging.getLogger(__name__)

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
        
        logger.info(f"Initializing Nessus client for {self.url}")
        
    def login(self):
        """Login to Nessus server and get access token"""
        payload = {'username': self.username, 'password': self.password}
        
        try:
            logger.debug(f"Attempting to connect to {self.url} with verify={self.verify}")
            response = requests.post(
                f"{self.url}/session",
                data=json.dumps(payload),
                headers=self.headers,
                verify=self.verify
            )
            
            if response.status_code == 200:
                self.token = response.json().get('token')
                self.headers['X-Cookie'] = f"token={self.token}"
                logger.info("Successfully logged in to Nessus server")
                return True
            else:
                logger.error(f"Login failed: {response.status_code} - {response.text}")
                return False
        except requests.exceptions.SSLError as e:
            logger.error(f"SSL Certificate error: {str(e)}")
            logger.debug(traceback.format_exc())
            logger.info("Your Nessus server likely uses a self-signed certificate. Try unchecking 'Verify SSL Certificate'")
            return False
        except requests.exceptions.ConnectionError as e:
            logger.error(f"Connection error: {str(e)}")
            logger.debug(traceback.format_exc())
            logger.info("Check if your Nessus server is running and the URL is correct")
            return False
        except Exception as e:
            logger.error(f"Connection error: {str(e)}")
            logger.debug(traceback.format_exc())
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
                logger.info("Successfully logged out from Nessus server")
                self.token = None
            else:
                logger.error(f"Logout failed: {response.status_code} - {response.text}")
        except Exception as e:
            logger.error(f"Error during logout: {str(e)}")
            logger.debug(traceback.format_exc())
    
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
                logger.error(f"Failed to get scan list: {response.status_code} - {response.text}")
                return []
        except Exception as e:
            logger.error(f"Error retrieving scans: {str(e)}")
            logger.debug(traceback.format_exc())
            return []
    
    def display_scans(self):
        """Display available scans in a table format"""
        scans = self.get_scans()
        
        if not scans:
            logger.info("No scans found on the server.")
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
                logger.info(f"Export requested for scan {scan_id}, file ID: {file_id}")
                return file_id
            else:
                logger.error(f"Export request failed: {response.status_code} - {response.text}")
                return None
        except Exception as e:
            logger.error(f"Error requesting export: {str(e)}")
            logger.debug(traceback.format_exc())
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
                logger.error(f"Failed to check export status: {response.status_code} - {response.text}")
                return None
        except Exception as e:
            logger.error(f"Error checking export status: {str(e)}")
            logger.debug(traceback.format_exc())
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
                
                logger.info(f"Downloaded to: {file_path}")
                return file_path
            else:
                logger.error(f"Download failed: {response.status_code} - {response.text}")
                return None
        except Exception as e:
            logger.error(f"Error downloading file: {str(e)}")
            logger.debug(traceback.format_exc())
            return None
    
    def export_and_download(self, scan_id, output_path=".", filename=None, format_id="nessus", max_wait=300):
        """Export a scan and download when ready"""
        # Request export
        file_id = self.export_scan(scan_id, format_id)
        if not file_id:
            return None
        
        # Wait for export to be ready
        logger.info("Waiting for export to complete...")
        start_time = time.time()
        dots = 0
        
        while True:
            if time.time() - start_time > max_wait:
                logger.error("Export timed out after waiting too long")
                return None
            
            status = self.check_export_status(scan_id, file_id)
            
            if status == "ready":
                logger.info("Export is ready!")
                break
            elif status == "error":
                logger.error("Export failed on server")
                return None
            
            # Simple progress indicator
            dots = (dots + 1) % 4
            print(f"\rWaiting for export to complete{'.' * dots}{' ' * (3 - dots)}", end="", flush=True)
            time.sleep(3)
        
        # Download the export
        # If no filename is provided, try to get the scan name from scan details
        if not filename:
            try:
                scan_details = self.get_scan_details(scan_id)
                if 'info' in scan_details and 'name' in scan_details['info']:
                    scan_name = scan_details['info']['name']
                    # Create a safe filename from scan name that ALWAYS includes the scan ID
                    safe_name = "".join(c if c.isalnum() or c in ['-', '_', '.'] else '_' for c in scan_name)
                    filename = f"{safe_name}_ScanID{scan_id}.nessus"
                    logger.info(f"Using scan name from details: {filename}")
                else:
                    # Fallback with explicit ID in name
                    filename = f"scan_ScanID{scan_id}.nessus"
            except Exception as e:
                logger.error(f"Error getting scan name: {str(e)}")
                # Fallback with explicit ID in name
                filename = f"scan_ScanID{scan_id}.nessus"
        else:
            # If filename is provided but doesn't include scan ID, add it
            if not f"ScanID{scan_id}" in filename:
                name_part, ext = os.path.splitext(filename)
                filename = f"{name_part}_ScanID{scan_id}{ext}"
        
        logger.info(f"Downloading file for Scan ID: {scan_id} as {filename}")
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
                verify=self.verify,
                timeout=30  # Add timeout
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                logger.error(f"Failed to get scan list: {response.status_code} - {response.text}")
                return {"error": f"Failed to get scan list: {response.status_code}"}
        except requests.exceptions.Timeout:
            logger.error("Request timed out when retrieving scan list")
            return {"error": "Connection timed out. The Nessus server might be busy."}
        except requests.exceptions.ConnectionError as e:
            logger.error(f"Connection error when retrieving scan list: {str(e)}")
            logger.debug(traceback.format_exc())
            return {"error": f"Connection error: {str(e)}"}
        except Exception as e:
            logger.error(f"Error retrieving scans: {str(e)}")
            logger.debug(traceback.format_exc())
            return {"error": f"Error retrieving scans: {str(e)}"}
    
    def create_scan(self, name, targets, template_uuid="731a8e52-3ea6-a291-ec0a-d2ff0619c19d", folder_id=None, max_retries=3):
        """
        Create a new scan with the specified name and targets.
        
        Args:
            name (str): Name of the scan
            targets (str): Target IPs, hostnames, or ranges
            template_uuid (str): Template UUID to use (default is basic network scan)
            folder_id (int, optional): Folder ID to place the scan in
            max_retries (int, optional): Maximum number of retry attempts (default is 3)
            
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
        
        retry_count = 0
        last_error = None
        
        while retry_count < max_retries:
            try:
                logger.info(f"Creating scan attempt {retry_count + 1}/{max_retries}")
                
                response = requests.post(
                    f"{self.url}/scans",
                    headers=self.headers,
                    data=json.dumps(scan_data),
                    verify=self.verify,
                    timeout=30  # 30 second timeout
                )
                
                if response.status_code in [200, 201]:
                    logger.info(f"Scan '{name}' created successfully")
                    return response.json()
                else:
                    logger.error(f"Failed to create scan: {response.status_code} - {response.text}")
                    last_error = f"Failed to create scan: {response.status_code}"
                    
            except requests.exceptions.Timeout:
                logger.warning(f"Request timed out when creating scan (attempt {retry_count + 1}/{max_retries})")
                last_error = "Connection timed out. The Nessus server might be busy."
                
            except requests.exceptions.ConnectionError as e:
                logger.warning(f"Connection error when creating scan (attempt {retry_count + 1}/{max_retries}): {str(e)}")
                logger.debug(traceback.format_exc())
                last_error = f"Connection error: {str(e)}"
                
            except Exception as e:
                logger.error(f"Error creating scan: {str(e)}")
                logger.debug(traceback.format_exc())
                last_error = f"Error creating scan: {str(e)}"
                
            # Only retry for connection and timeout errors
            if isinstance(last_error, str) and ("Connection error" in last_error or "timed out" in last_error):
                retry_count += 1
                if retry_count < max_retries:
                    wait_time = 2 ** retry_count  # Exponential backoff: 2, 4, 8 seconds
                    logger.info(f"Retrying in {wait_time} seconds...")
                    time.sleep(wait_time)
                continue
            else:
                # For other types of errors, don't retry
                break
        
        return {"error": last_error or "Failed to create scan after multiple attempts"}
    
    def launch_scan(self, scan_id, max_retries=3):
        """
        Launch a scan with the specified ID.
        
        Args:
            scan_id (int): ID of the scan to launch
            max_retries (int, optional): Maximum number of retry attempts (default is 3)
            
        Returns:
            dict: Response containing the scan launch information
        """
        if not self.token:
            if not self.login():
                return {"error": "Failed to login to Nessus server"}
        
        retry_count = 0
        last_error = None
        
        while retry_count < max_retries:
            try:
                logger.info(f"Launching scan (ID: {scan_id}) attempt {retry_count + 1}/{max_retries}")
                
                response = requests.post(
                    f"{self.url}/scans/{scan_id}/launch",
                    headers=self.headers,
                    verify=self.verify,
                    timeout=30
                )
                
                if response.status_code == 200:
                    logger.info(f"Scan (ID: {scan_id}) launched successfully")
                    return response.json()
                else:
                    logger.error(f"Failed to launch scan: {response.status_code} - {response.text}")
                    last_error = f"Failed to launch scan: {response.status_code}"
                    
            except requests.exceptions.Timeout:
                logger.warning(f"Request timed out when launching scan (attempt {retry_count + 1}/{max_retries})")
                last_error = "Connection timed out. The Nessus server might be busy."
                
            except requests.exceptions.ConnectionError as e:
                logger.warning(f"Connection error when launching scan (attempt {retry_count + 1}/{max_retries}): {str(e)}")
                logger.debug(traceback.format_exc())
                last_error = f"Connection error: {str(e)}"
                
            except Exception as e:
                logger.error(f"Error launching scan: {str(e)}")
                logger.debug(traceback.format_exc())
                last_error = f"Error launching scan: {str(e)}"
                
            # Only retry for connection and timeout errors
            if isinstance(last_error, str) and ("Connection error" in last_error or "timed out" in last_error):
                retry_count += 1
                if retry_count < max_retries:
                    wait_time = 2 ** retry_count  # Exponential backoff: 2, 4, 8 seconds
                    logger.info(f"Retrying in {wait_time} seconds...")
                    time.sleep(wait_time)
                continue
            else:
                # For other types of errors, don't retry
                break
        
        return {"error": last_error or "Failed to launch scan after multiple attempts"}
    
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
                logger.error(f"Failed to get scan details: {response.status_code} - {response.text}")
                return {"error": f"Failed to get scan details: {response.status_code}"}
        except Exception as e:
            logger.error(f"Error retrieving scan details: {str(e)}")
            logger.debug(traceback.format_exc())
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
                verify=self.verify,
                timeout=30  # Add timeout
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                logger.error(f"Failed to get scan templates: {response.status_code} - {response.text}")
                return {"error": f"Failed to get scan templates: {response.status_code}"}
        except requests.exceptions.Timeout:
            logger.error("Request timed out when retrieving scan templates")
            return {"error": "Connection timed out. The Nessus server might be busy."}
        except requests.exceptions.ConnectionError as e:
            logger.error(f"Connection error when retrieving scan templates: {str(e)}")
            logger.debug(traceback.format_exc())
            return {"error": f"Connection error: {str(e)}"}
        except Exception as e:
            logger.error(f"Error retrieving scan templates: {str(e)}")
            logger.debug(traceback.format_exc())
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
                verify=self.verify,
                timeout=30  # Add timeout
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                logger.error(f"Failed to get folders: {response.status_code} - {response.text}")
                return {"error": f"Failed to get folders: {response.status_code}"}
        except requests.exceptions.Timeout:
            logger.error("Request timed out when retrieving folders")
            return {"error": "Connection timed out. The Nessus server might be busy."}
        except requests.exceptions.ConnectionError as e:
            logger.error(f"Connection error when retrieving folders: {str(e)}")
            logger.debug(traceback.format_exc())
            return {"error": f"Connection error: {str(e)}"}
        except Exception as e:
            logger.error(f"Error retrieving folders: {str(e)}")
            logger.debug(traceback.format_exc())
            return {"error": f"Error retrieving folders: {str(e)}"}