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
    
    def to_csv(self, parsed_data, output_file):
        """
        Convert parsed Nessus data to CSV format
        
        Args:
            parsed_data (dict): Parsed Nessus data
            output_file (str): Path to output CSV file
            
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
            
            # Write to CSV
            df.to_csv(output_file, index=False)
            
            print(f"[OK] CSV report saved to: {output_file}")
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
        # Set default output file if not specified
        output_file = args.output_file
        if not output_file:
            output_file = 'nessus_report.csv'
            # Add date to filename if not already specified
            base, ext = os.path.splitext(output_file)
            output_file = f"{base}_{datetime.now().strftime('%Y%m%d')}{ext}"
        
        NessusParser.export_to_csv(args.nessus_files, output_file)
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