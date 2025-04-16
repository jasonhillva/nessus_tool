#!/usr/bin/env python3
import os
from datetime import datetime
from nessus_parser import NessusParser

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