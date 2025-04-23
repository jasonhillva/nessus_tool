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
    
    def batch_to_excel(self, parsed_data_list, output_file):
        """
        Convert multiple parsed Nessus datasets to a combined Excel file
        
        Args:
            parsed_data_list (list): List of tuples (scan_id, scan_name, parsed_data)
            output_file (str): Path to output Excel file
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            if not parsed_data_list:
                print("[WARNING] No vulnerability data to convert")
                return False
            
            # Create a Pandas Excel writer using xlsxwriter as the engine
            writer = pd.ExcelWriter(output_file, engine='xlsxwriter')
            workbook = writer.book
            
            # Define severity levels and their colors - match the image exactly
            severity_levels = {
                'Critical': {'level': 4, 'color': '#E21D5E'},  # Bright Pink/Red for Critical
                'High': {'level': 3, 'color': '#FF6B6B'},      # Coral/Light Red for High
                'Medium': {'level': 2, 'color': '#FFA366'},    # Orange for Medium
                'Low': {'level': 1, 'color': '#FFFF00'},       # Yellow
                'Info': {'level': 0, 'color': '#00FF00'}       # Green
            }
            
            # First collect all scan data for summary
            summary_data = []
            all_vulnerabilities = []
            
            # Track all column names for proper mapping
            all_columns = set()
            
            # Track totals for each severity
            severity_totals = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0, 'Total Vulnerabilities': 0}
            
            # Process each scan's data
            for scan_id, scan_name, parsed_data in parsed_data_list:
                print(f"Processing scan: {scan_name} (ID: {scan_id})")
                vulnerabilities = parsed_data.get('vulnerabilities', [])
                if not vulnerabilities:
                    print(f"  No vulnerabilities found for scan {scan_name}")
                    continue
                
                # Count vulnerabilities by severity for summary
                severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}
                
                print(f"  Found {len(vulnerabilities)} vulnerabilities")
                # First pass - gather all column names
                for vuln in vulnerabilities:
                    all_columns.update(vuln.keys())
                    
                    # Add scan name to each vulnerability
                    vuln['Scan Name'] = scan_name
                    vuln['Scan ID'] = scan_id
                    
                    # Count by severity - use the Severity field from the parser
                    severity = vuln.get('Severity', 'Info')
                    if severity in severity_counts:
                        severity_counts[severity] += 1
                    
                    # Add to all vulnerabilities list
                    all_vulnerabilities.append(vuln)
                
                # Create summary row
                summary_row = {
                    'Scan ID': scan_id,
                    'Scan Name': scan_name,
                    'Total Vulnerabilities': len(vulnerabilities),
                    'Critical': severity_counts['Critical'],
                    'High': severity_counts['High'],
                    'Medium': severity_counts['Medium'],
                    'Low': severity_counts['Low'],
                    'Info': severity_counts['Info']
                }
                
                # Update totals
                severity_totals['Critical'] += severity_counts['Critical']
                severity_totals['High'] += severity_counts['High']
                severity_totals['Medium'] += severity_counts['Medium']
                severity_totals['Low'] += severity_counts['Low']
                severity_totals['Info'] += severity_counts['Info']
                severity_totals['Total Vulnerabilities'] += len(vulnerabilities)
                
                summary_data.append(summary_row)
                print(f"  Summary: {severity_counts}")
            
            if not all_vulnerabilities:
                print("[WARNING] No vulnerability data found in any scan")
                return False
            
            print(f"Total vulnerabilities across all scans: {len(all_vulnerabilities)}")
            print(f"Available columns: {all_columns}")
            
            # Convert to DataFrame
            df_all = pd.DataFrame(all_vulnerabilities)
            
            # Define the order of columns we want - check if they exist
            column_order = [
                'Scan Name', 'Scan ID', 'Host', 'IP Address', 'FQDN', 'Operating System', 
                'Port', 'Protocol', 'Plugin ID', 'Plugin Name', 'Severity', 'Risk Factor',
                'CVSS Base Score', 'CVSS3 Base Score', 'CVE', 'Description', 'Solution'
            ]
            
            # Filter to only include columns that actually exist in our data
            final_columns = [col for col in column_order if col in df_all.columns]
            
            # Add any remaining columns that weren't in our predefined order
            for col in df_all.columns:
                if col not in final_columns:
                    final_columns.append(col)
            
            # Create a copy with the final column order
            result_df = df_all[final_columns].copy()
            
            # 1. First create the Summary tab (will be the first/default tab when opening Excel)
            summary_df = pd.DataFrame(summary_data)
            
            # Add a totals row at the bottom
            totals_row = {
                'Scan ID': 'TOTALS',
                'Scan Name': f"All Scans ({len(summary_data)})",
                'Total Vulnerabilities': severity_totals['Total Vulnerabilities'],
                'Critical': severity_totals['Critical'],
                'High': severity_totals['High'],
                'Medium': severity_totals['Medium'],
                'Low': severity_totals['Low'],
                'Info': severity_totals['Info']
            }
            
            # Append the totals row to the DataFrame
            summary_df = pd.concat([summary_df, pd.DataFrame([totals_row])], ignore_index=True)
            
            summary_df.to_excel(writer, sheet_name='Summary', index=False)
            
            # Format Summary sheet
            summary_sheet = writer.sheets['Summary']
            
            # Set column widths
            summary_sheet.set_column(0, 0, 10)   # Scan ID
            summary_sheet.set_column(1, 1, 30)   # Scan Name
            summary_sheet.set_column(2, 2, 20)   # Total Vulnerabilities
            summary_sheet.set_column(3, 7, 15)   # Severity columns
            
            # Add header format
            header_format = workbook.add_format({
                'bold': True,
                'text_wrap': True,
                'valign': 'top',
                'fg_color': '#D7E4BC',
                'border': 1
            })
            
            # Totals row format
            totals_format = workbook.add_format({
                'bold': True,
                'border': 1,
                'bg_color': '#D0D0D0'  # Light gray background
            })
            
            # Apply header format to first row
            for col_num, value in enumerate(summary_df.columns.values):
                summary_sheet.write(0, col_num, value, header_format)
            
            # Apply totals format to the last row
            totals_row_index = len(summary_df)
            for col_num in range(len(summary_df.columns)):
                if col_num < 3:  # For Scan ID, Scan Name, and Total columns
                    summary_sheet.write(totals_row_index, col_num, summary_df.iloc[totals_row_index-1][summary_df.columns[col_num]], totals_format)
            
            # Apply severity colors to all severity columns regardless of values
            for severity, info in severity_levels.items():
                if severity in summary_df.columns:
                    col_idx = summary_df.columns.get_loc(severity)
                    
                    # Create the cell format for this severity level
                    cell_format = workbook.add_format({
                        'bg_color': info['color'],
                        'font_color': '#000000' if severity in ['Low', 'Info'] else '#FFFFFF'
                    })
                    
                    # Create the totals cell format for this severity level (bold text)
                    totals_cell_format = workbook.add_format({
                        'bg_color': info['color'],
                        'font_color': '#000000' if severity in ['Low', 'Info'] else '#FFFFFF',
                        'bold': True,
                        'border': 1
                    })
                    
                    # Apply to all regular cells
                    for row in range(len(summary_df) - 1):
                        summary_sheet.write(row + 1, col_idx, summary_df.iloc[row][severity], cell_format)
                    
                    # Apply special format to totals cell
                    summary_sheet.write(totals_row_index, col_idx, summary_df.iloc[totals_row_index-1][severity], totals_cell_format)
            
            # 2. Create the All Findings tab with all vulnerabilities
            
            # Create a severity order mapping for sorting
            severity_order = {
                'Critical': 0,
                'High': 1,
                'Medium': 2,
                'Low': 3,
                'Info': 4
            }
            
            # Add a numeric severity column for sorting purposes
            if 'Severity' in result_df.columns:
                result_df['_severity_order'] = result_df['Severity'].map(severity_order)
                # Sort by severity (most critical first)
                result_df = result_df.sort_values(by=['_severity_order'], ascending=True)
                # Remove the temporary sorting column
                result_df = result_df.drop('_severity_order', axis=1)
            
            result_df.to_excel(writer, sheet_name='All Findings', index=False)
            
            # Format All Findings sheet
            all_sheet = writer.sheets['All Findings']
            
            # Set column widths
            column_widths = {
                'Host': 15,
                'IP Address': 15,
                'FQDN': 15,
                'Operating System': 20,
                'Port': 10,
                'Protocol': 10,
                'Plugin ID': 10,
                'Plugin Name': 30,
                'Severity': 12,
                'Risk Factor': 12,
                'CVSS Base Score': 12,
                'CVSS3 Base Score': 12,
                'CVE': 15,
                'Description': 50,
                'Solution': 50,
                'Scan Name': 20,
                'Scan ID': 10
            }
            
            # Apply column widths
            for col_idx, col_name in enumerate(final_columns):
                if col_name in column_widths:
                    all_sheet.set_column(col_idx, col_idx, column_widths[col_name])
                else:
                    all_sheet.set_column(col_idx, col_idx, 15)  # default width
            
            # Format severity column
            if 'Severity' in result_df.columns:
                severity_col_idx = final_columns.index('Severity')
                
                for severity, info in severity_levels.items():
                    fmt = workbook.add_format({
                        'bg_color': info['color'],
                        'font_color': '#000000' if severity in ['Low', 'Info'] else '#FFFFFF'
                    })
                    
                    all_sheet.conditional_format(1, severity_col_idx, len(result_df) + 1, severity_col_idx, {
                        'type': 'cell',
                        'criteria': 'equal to',
                        'value': f'"{severity}"',  
                        'format': fmt
                    })
            
            # 3. Create individual sheets for each scan
            for scan_id, scan_name in [(item[0], item[1]) for item in parsed_data_list]:
                # Filter the vulnerabilities for this scan
                scan_df = result_df[(result_df['Scan ID'] == scan_id) | 
                                    (result_df['Scan Name'] == scan_name)]
                
                if len(scan_df) == 0:
                    continue
                
                # Create a valid sheet name
                sheet_name = str(scan_name)[:31].replace(':', '-').replace('/', '-').replace('\\', '-').replace('?', '-').replace('*', '-').replace('[', '-').replace(']', '-')
                
                # Write to Excel
                scan_df.to_excel(writer, sheet_name=sheet_name, index=False)
                
                # Format the sheet
                worksheet = writer.sheets[sheet_name]
                
                # Apply column widths
                for col_idx, col_name in enumerate(final_columns):
                    if col_name in column_widths:
                        worksheet.set_column(col_idx, col_idx, column_widths[col_name])
                    else:
                        worksheet.set_column(col_idx, col_idx, 15)  # default width
                
                # Format severity column
                if 'Severity' in scan_df.columns:
                    severity_col_idx = final_columns.index('Severity')
                    
                    for severity, info in severity_levels.items():
                        fmt = workbook.add_format({
                            'bg_color': info['color'],
                            'font_color': '#000000' if severity in ['Low', 'Info'] else '#FFFFFF'
                        })
                        
                        worksheet.conditional_format(1, severity_col_idx, len(scan_df) + 1, severity_col_idx, {
                            'type': 'cell',
                            'criteria': 'equal to',
                            'value': f'"{severity}"',
                            'format': fmt
                        })
            
            # Save the Excel file
            writer.close()
            print(f"[OK] Batch Excel report saved to: {output_file}")
            return True
        
        except Exception as e:
            print(f"[ERROR] Failed to convert batch to Excel: {str(e)}")
            import traceback
            print(traceback.format_exc())
            return False
    
    def batch_to_csv(self, parsed_data_list, output_file):
        """
        Convert multiple parsed Nessus datasets to a combined CSV file
        
        Args:
            parsed_data_list (list): List of tuples (scan_id, scan_name, parsed_data) 
            output_file (str): Path to output CSV file
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            if not parsed_data_list:
                print("[WARNING] No vulnerability data to convert")
                return False
            
            # Merge all vulnerabilities from all scans
            all_vulnerabilities = []
            
            for scan_id, scan_name, parsed_data in parsed_data_list:
                vulnerabilities = parsed_data.get('vulnerabilities', [])
                for vuln in vulnerabilities:
                    # Add scan info to each vulnerability
                    vuln['scan_id'] = scan_id
                    vuln['scan_name'] = scan_name
                    all_vulnerabilities.append(vuln)
            
            if not all_vulnerabilities:
                print("[WARNING] No vulnerability data found in any scan")
                return False
            
            # Convert to DataFrame and save as CSV
            df = pd.DataFrame(all_vulnerabilities)
            # Reorder columns to put scan_id and scan_name first
            if 'scan_id' in df.columns and 'scan_name' in df.columns:
                cols = ['scan_id', 'scan_name'] + [col for col in df.columns if col not in ['scan_id', 'scan_name']]
                df = df[cols]
            
            df.to_csv(output_file, index=False)
            print(f"[OK] Batch CSV report saved to: {output_file}")
            return True
        
        except Exception as e:
            print(f"[ERROR] Failed to convert batch to CSV: {str(e)}")
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