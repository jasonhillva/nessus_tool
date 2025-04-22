#!/usr/bin/env python3
import os
import pandas as pd
from datetime import datetime
from nessus_parser import NessusParser

class NessusConverter:
    """Class for converting parsed Nessus scan results to various formats"""
    
    def __init__(self):
        """Initialize the converter"""
        pass
    
    def to_excel(self, parsed_data, output_file):
        """
        Convert parsed Nessus data to Excel format
        
        Args:
            parsed_data (dict): Parsed Nessus data
            output_file (str): Path to output Excel file
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            if not parsed_data or not parsed_data.get('vulnerabilities'):
                print("[WARNING] No vulnerability data to convert")
                return False
            
            vulnerabilities = parsed_data['vulnerabilities']
            
            # Convert to DataFrame
            df = pd.DataFrame(vulnerabilities)
            
            # Write to Excel
            with pd.ExcelWriter(output_file) as writer:
                df.to_excel(writer, sheet_name='Vulnerabilities', index=False)
                
                # Add scan info sheet if available
                if 'scan_info' in parsed_data and parsed_data['scan_info']:
                    scan_info = pd.DataFrame([parsed_data['scan_info']])
                    scan_info.to_excel(writer, sheet_name='Scan Info', index=False)
            
            print(f"[OK] Excel report saved to: {output_file}")
            return True
        
        except Exception as e:
            print(f"[ERROR] Failed to convert to Excel: {str(e)}")
            return False
    
    def to_csv(self, parsed_data, output_dir):
        """
        Convert parsed Nessus data to CSV format
        
        Args:
            parsed_data (dict): Parsed Nessus data
            output_dir (str): Directory to save CSV files
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            if not parsed_data or not parsed_data.get('vulnerabilities'):
                print("[WARNING] No vulnerability data to convert")
                return False
            
            timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
            vulnerabilities = parsed_data['vulnerabilities']
            
            # Convert vulnerabilities to DataFrame and save as CSV
            df = pd.DataFrame(vulnerabilities)
            vuln_file = os.path.join(output_dir, f"vulnerabilities_{timestamp}.csv")
            df.to_csv(vuln_file, index=False)
            print(f"[OK] Vulnerabilities saved to: {vuln_file}")
            
            # Save scan info if available
            if 'scan_info' in parsed_data and parsed_data['scan_info']:
                scan_info = pd.DataFrame([parsed_data['scan_info']])
                info_file = os.path.join(output_dir, f"scan_info_{timestamp}.csv")
                scan_info.to_csv(info_file, index=False)
                print(f"[OK] Scan info saved to: {info_file}")
            
            return True
        
        except Exception as e:
            print(f"[ERROR] Failed to convert to CSV: {str(e)}")
            return False

def run_convert_nessus(args):
    """Run the nessus file conversion functionality"""
    print("\n=== Nessus Scan Converter ===")
    
    if not args.nessus_files:
        print("[ERROR] No .nessus files specified for conversion.")
        return False
    
    # Process nessus files based on output format
    if args.output_format == 'csv':
        # Create CSV output directory if not exists
        csv_dir = args.output_dir
        if not os.path.exists(csv_dir):
            try:
                os.makedirs(csv_dir)
                print(f"[OK] Created output directory: {csv_dir}")
            except Exception as e:
                print(f"[ERROR] Error creating directory: {str(e)}")
                csv_dir = "."
        
        NessusParser.export_to_csv(args.nessus_files, csv_dir)
    else:
        # Set default output file if not specified
        output_file = args.output_file
        if not output_file:
            output_file = 'nessus_report.xlsx'
            # Add date to filename if not already specified
            base, ext = os.path.splitext(output_file)
            output_file = f"{base}_{datetime.now().strftime('%Y%m%d')}{ext}"
        
        NessusParser.export_to_excel(args.nessus_files, output_file)
    
    return True