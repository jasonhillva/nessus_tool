#!/usr/bin/env python3
import zipfile
import socketio
import os
import json
import logging
import traceback
import threading
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_from_directory, send_file
from nessus_client import NessusClient
from nessus_downloader import NessusDownloader
from nessus_parser import NessusParser
from nessus_converter import NessusConverter

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('nessus_tool.log')
    ]
)
logger = logging.getLogger(__name__)

# Log startup message
logger.info("Nessus Tool starting up")

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24))
app.config['UPLOAD_FOLDER'] = os.environ.get('UPLOAD_FOLDER', 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max upload size

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Add template filter for timestamps
@app.template_filter('timestamp_to_datetime')
def timestamp_to_datetime(timestamp):
    """Convert Unix timestamp to formatted datetime string."""
    if not timestamp:
        return "Never"
    return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')

@app.route('/')
def index():
    """Render the main login page."""
    return render_template('index.html')

@app.route('/connect', methods=['POST'])
def connect():
    """Connect to a Nessus server."""
    url = request.form['url']
    username = request.form['username']
    password = request.form['password']
    verify_ssl = 'verify_ssl' in request.form
    
    try:
        # Store connection info in session
        session['nessus_url'] = url
        session['nessus_username'] = username
        session['nessus_password'] = password
        session['nessus_verify_ssl'] = verify_ssl
        
        # Test connection
        client = NessusClient(url, username, password, verify_ssl)
        if not client.login():
            # Check for common problems
            if "https://" not in url.lower():
                flash('URL must start with https://', 'warning')
            elif not verify_ssl:
                flash('Failed to connect to Nessus server. Check your credentials and make sure the server is running.', 'danger')
            else:
                flash('Failed to connect to Nessus server. If using a self-signed certificate, try unchecking "Verify SSL Certificate".', 'warning')
            return redirect(url_for('index'))
        
        flash('Successfully connected to Nessus server', 'success')
        return redirect(url_for('dashboard'))
    except Exception as e:
        logger.error(f'Connection failed: {str(e)}')
        logger.debug(traceback.format_exc())
        flash(f'Connection failed: {str(e)}', 'danger')
        return redirect(url_for('index'))

@app.route('/dashboard')
def dashboard():
    """Show the main dashboard with scan list and exported files."""
    if not _is_connected():
        flash('Please connect to a Nessus server first', 'warning')
        return redirect(url_for('index'))
    
    client = _get_client()
    try:
        # Get list of scans
        response = client.list_scans()
        scans = response.get('scans', [])
        
        # Get list of exported files
        exports = []
        if os.path.exists(app.config['UPLOAD_FOLDER']):
            for filename in os.listdir(app.config['UPLOAD_FOLDER']):
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                if os.path.isfile(file_path):
                    # Get file stats
                    stats = os.stat(file_path)
                    size_bytes = stats.st_size
                    modified_time = datetime.fromtimestamp(stats.st_mtime)
                    
                    # Determine file type
                    file_type = "Unknown"
                    if filename.lower().endswith('.xlsx'):
                        file_type = "Excel"
                    elif filename.lower().endswith('.csv'):
                        file_type = "CSV"
                    elif filename.lower().endswith('.nessus'):
                        file_type = "Nessus"
                    
                    # Format size
                    size_str = f"{size_bytes} bytes"
                    if size_bytes > 1024 * 1024:
                        size_str = f"{size_bytes / (1024 * 1024):.2f} MB"
                    elif size_bytes > 1024:
                        size_str = f"{size_bytes / 1024:.2f} KB"
                    
                    exports.append({
                        'filename': filename,
                        'type': file_type,
                        'size': size_str,
                        'date': modified_time.strftime('%Y-%m-%d %H:%M:%S')
                    })
            
            # Sort by most recent first
            exports.sort(key=lambda x: x['date'], reverse=True)
            
        return render_template('dashboard.html', scans=scans, exports=exports)
    except Exception as e:
        logger.error(f'Failed to get dashboard data: {str(e)}')
        logger.debug(traceback.format_exc())
        flash(f'Failed to get data: {str(e)}', 'danger')
        return redirect(url_for('index'))

@app.route('/create-scan', methods=['GET', 'POST'])
def create_scan():
    """Create a new scan."""
    if not _is_connected():
        flash('Please connect to a Nessus server first', 'warning')
        return redirect(url_for('index'))
    
    client = _get_client()
    
    if request.method == 'POST':
        name = request.form['name']
        targets = request.form['targets']
        template_uuid = request.form['template_uuid']
        folder_id = request.form.get('folder_id')
        
        if folder_id and folder_id.isdigit():
            folder_id = int(folder_id)
        else:
            folder_id = None
        
        try:
            response = client.create_scan(name, targets, template_uuid, folder_id)
            if 'error' in response:
                flash(f'Failed to create scan: {response["error"]}', 'danger')
            else:
                scan_id = response.get('scan', {}).get('id')
                if scan_id:
                    flash(f'Scan "{name}" created successfully', 'success')
                    return redirect(url_for('dashboard'))
                else:
                    flash('Failed to create scan: Invalid response from server', 'danger')
        except Exception as e:
            logger.error(f'Failed to create scan: {str(e)}')
            logger.debug(traceback.format_exc())
            flash(f'Failed to create scan: {str(e)}', 'danger')
        
        return redirect(url_for('create_scan'))
    
    # GET request - show form
    try:
        templates = client.get_scan_templates()
        folders = client.get_folders()
        return render_template('create_scan.html', 
                              templates=templates.get('templates', []), 
                              folders=folders.get('folders', []))
    except Exception as e:
        logger.error(f'Failed to get templates or folders: {str(e)}')
        logger.debug(traceback.format_exc())
        flash(f'Failed to get templates or folders: {str(e)}', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/launch-scan/<int:scan_id>', methods=['POST'])
def launch_scan(scan_id):
    """Launch a scan by ID."""
    if not _is_connected():
        return jsonify({'success': False, 'message': 'Not connected to server'})
    
    client = _get_client()
    try:
        response = client.launch_scan(scan_id)
        if 'error' in response:
            return jsonify({'success': False, 'message': response['error']})
        return jsonify({'success': True, 'scan_uuid': response.get('scan_uuid')})
    except Exception as e:
        logger.error(f'Failed to launch scan {scan_id}: {str(e)}')
        logger.debug(traceback.format_exc())
        return jsonify({'success': False, 'message': str(e)})

@app.route('/download-scan/<int:scan_id>')
def download_scan(scan_id):
    """Download a scan by ID and convert to the selected format."""
    if not _is_connected():
        if request.args.get('ajax') == '1':
            return jsonify({'success': False, 'message': 'Not connected to server'})
        flash('Please connect to a Nessus server first', 'warning')
        return redirect(url_for('index'))
    
    # Get the requested export format (default to xlsx)
    export_format = request.args.get('format', 'xlsx').lower()
    is_ajax = request.args.get('ajax') == '1'
    
    try:
        # Get connection parameters from session
        url = session['nessus_url']
        username = session['nessus_username']
        password = session['nessus_password']
        verify_ssl = session['nessus_verify_ssl']
        
        # First, download the Nessus scan file
        downloader = NessusDownloader(url, username, password, verify_ssl)
        nessus_file_path = downloader.download_scan(scan_id, app.config['UPLOAD_FOLDER'])
        
        if not nessus_file_path:
            if is_ajax:
                return jsonify({'success': False, 'message': f'Failed to download scan with ID {scan_id}'})
            flash(f'Failed to download scan with ID {scan_id}', 'danger')
            return redirect(url_for('dashboard'))
        
        # Create filename with timestamp
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        
        # If user requested the raw .nessus file, we're done
        if export_format == 'nessus':
            if is_ajax:
                return jsonify({
                    'success': True, 
                    'message': f'Scan downloaded successfully', 
                    'download_url': url_for('download_exported_file', filename=os.path.basename(nessus_file_path))
                })
            flash(f'Scan downloaded to: {os.path.basename(nessus_file_path)}', 'success')
            return redirect(url_for('dashboard'))
        
        # Parse the Nessus file
        parser = NessusParser(nessus_file_path)
        parsed_data = parser.parse()
        
        # Create converter for the appropriate format
        converter = NessusConverter()
        
        if export_format == 'csv':
            # Export to CSV
            output_filename = f'scan_{scan_id}_{timestamp}.csv'
            output_file = os.path.join(app.config['UPLOAD_FOLDER'], output_filename)
            converter.to_csv(parsed_data, output_file)
            if is_ajax:
                return jsonify({
                    'success': True, 
                    'message': 'Scan exported to CSV successfully', 
                    'download_url': url_for('download_exported_file', filename=output_filename)
                })
            flash(f'Scan downloaded and converted to CSV: {output_filename}', 'success')
        else:
            # Default to Excel
            output_filename = f'scan_{scan_id}_{timestamp}.xlsx'
            output_file = os.path.join(app.config['UPLOAD_FOLDER'], output_filename)
            converter.to_excel(parsed_data, output_file)
            if is_ajax:
                return jsonify({
                    'success': True, 
                    'message': 'Scan exported to Excel successfully', 
                    'download_url': url_for('download_exported_file', filename=output_filename)
                })
            flash(f'Scan downloaded and converted to Excel: {output_filename}', 'success')
        
        return redirect(url_for('dashboard'))
    except Exception as e:
        logger.error(f'Failed to download scan {scan_id}: {str(e)}')
        logger.debug(traceback.format_exc())
        if is_ajax:
            return jsonify({'success': False, 'message': str(e)})
        flash(f'Failed to download scan: {str(e)}', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/batch-download-scans', methods=['GET', 'POST'])
def batch_download_scans():
    """Download and combine multiple selected scans."""
    if not _is_connected():
        if request.method == 'POST' and request.form.get('ajax') == '1':
            return jsonify({'success': False, 'message': 'Not connected to server'})
        flash('Please connect to a Nessus server first', 'warning')
        return redirect(url_for('index'))
    
    # Get the scan IDs from the request
    if request.method == 'POST':
        # For AJAX requests, get scan_ids from form data
        scan_ids = request.form.getlist('scan_ids')
        export_format = request.form.get('format', 'xlsx').lower()
        is_ajax = request.form.get('ajax') == '1'
    else:
        # For regular form submissions, get from query parameters
        scan_ids = request.args.getlist('scan_ids')
        export_format = request.args.get('format', 'xlsx').lower()
        is_ajax = False
    
    logger.info(f"Batch export requested: format={export_format}, ajax={is_ajax}, scan_ids={scan_ids}")
    
    if not scan_ids:
        if is_ajax:
            return jsonify({'success': False, 'message': 'No scans selected for export'})
        flash('No scans selected for export', 'warning')
        return redirect(url_for('dashboard'))
    
    try:
        # Check if files are already in the uploads directory
        uploads_dir = app.config['UPLOAD_FOLDER']
        
        # Get uploaded nessus files
        nessus_files = []
        for scan_id in scan_ids:
            # Try to find matching files in uploads directory
            matching_files = []
            logger.info(f"Looking for files matching scan ID {scan_id}")
            
            for filename in os.listdir(uploads_dir):
                if not filename.endswith('.nessus'):
                    continue
                
                file_matched = False
                
                # Exact ID match check - look for the exact ID as a separate component
                # This helps avoid partial matches like ID 40 matching in "vlan140"
                filename_parts = os.path.splitext(filename)[0].replace('-', '_').split('_')
                
                # Check for exact ID match in any part of the filename
                if str(scan_id) in filename_parts:
                    logger.info(f"Found exact ID match for scan {scan_id} in filename {filename}")
                    matching_files.append(os.path.join(uploads_dir, filename))
                    file_matched = True
                    continue
                
                # Extract the scan ID from vlan pattern if present (vlanXXX, VlanXXX, VXXX)
                if not file_matched:
                    for part in filename_parts:
                        part_lower = part.lower()
                        
                        # Handle "vlanXXX" or "VlanXXX" pattern
                        if part_lower.startswith('vlan'):
                            try:
                                file_scan_id = part_lower.replace('vlan', '')
                                if file_scan_id.isdigit() and file_scan_id == str(scan_id):
                                    logger.info(f"Found vlan pattern match for scan {scan_id} in filename {filename}")
                                    matching_files.append(os.path.join(uploads_dir, filename))
                                    file_matched = True
                                    break
                            except:
                                pass
                        
                        # Handle "VXXX" pattern
                        elif part_lower.startswith('v') and len(part_lower) > 1:
                            try:
                                potential_id = part_lower[1:]
                                if potential_id.isdigit() and potential_id == str(scan_id):
                                    logger.info(f"Found V-pattern match for scan {scan_id} in filename {filename}")
                                    matching_files.append(os.path.join(uploads_dir, filename))
                                    file_matched = True
                                    break
                            except:
                                pass
            
            if matching_files:
                # Use the most recent file if multiple matches found
                if len(matching_files) > 1:
                    matching_files.sort(key=os.path.getmtime, reverse=True)
                    logger.debug(f"Multiple files found for scan {scan_id}, using most recent: {matching_files[0]}")
                
                nessus_files.append((scan_id, os.path.basename(matching_files[0]), matching_files[0]))
                logger.info(f"Using existing .nessus file: {matching_files[0]}")
            else:
                # If no matching files found locally, download from server
                # Get connection parameters from session
                url = session['nessus_url']
                username = session['nessus_username']
                password = session['nessus_password']
                verify_ssl = session['nessus_verify_ssl']
                
                # Get scan name for better labeling
                client = _get_client()
                scan_details = client.get_scan_details(int(scan_id))
                scan_name = f"Scan {scan_id}"
                if 'info' in scan_details:
                    scan_name = scan_details['info'].get('name', scan_name)
                
                logger.info(f"Downloading scan {scan_id} ({scan_name})")
                # Download the scan
                downloader = NessusDownloader(url, username, password, verify_ssl)
                nessus_file_path = downloader.download_scan(int(scan_id), app.config['UPLOAD_FOLDER'])
                
                if nessus_file_path:
                    nessus_files.append((scan_id, scan_name, nessus_file_path))
                    logger.info(f"Downloaded scan {scan_id} to {nessus_file_path}")
                else:
                    logger.warning(f"Failed to download scan {scan_id}")
                    if not is_ajax:
                        flash(f'Failed to download scan {scan_id}', 'warning')
        
        if not nessus_files:
            if is_ajax:
                return jsonify({'success': False, 'message': 'No .nessus files found or downloaded for the selected scans'})
            flash('No .nessus files found or downloaded for the selected scans', 'danger')
            return redirect(url_for('dashboard'))
        
        # Create timestamp for filenames
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        
        # For multiple scans, create a zip file if we have more than one scan and format is .nessus
        create_zip = len(nessus_files) > 1 and export_format == 'nessus'
        
        # If using Nessus file format, just zip the files and return
        if export_format == 'nessus':
            if create_zip:
                # Create a zip file containing all downloaded Nessus files
                zip_filename = f"nessus_scans_{timestamp}.zip"
                zip_path = os.path.join(app.config['UPLOAD_FOLDER'], zip_filename)
                
                with zipfile.ZipFile(zip_path, 'w') as zipf:
                    for scan_id, scan_name, file_path in nessus_files:
                        # Add the file to the zip with a clean name
                        clean_name = f"{scan_name.replace(' ', '_').replace('/', '_')}.nessus"
                        zipf.write(file_path, arcname=clean_name)
                
                if is_ajax:
                    return jsonify({
                        'success': True, 
                        'message': f'Added {len(nessus_files)} Nessus scan files to ZIP', 
                        'download_url': url_for('download_exported_file', filename=zip_filename)
                    })
                flash(f'Downloaded {len(nessus_files)} Nessus scan files as zip: {zip_filename}', 'success')
            else:
                # Just a single file, no need for zip
                _, _, file_path = nessus_files[0]
                filename = os.path.basename(file_path)
                if is_ajax:
                    return jsonify({
                        'success': True, 
                        'message': 'Ready to download Nessus scan file', 
                        'download_url': url_for('download_exported_file', filename=filename)
                    })
                flash(f'Downloaded Nessus scan file: {filename}', 'success')
            
            return redirect(url_for('dashboard'))
        
        # For CSV or Excel format, parse and combine the data
        parsed_data_list = []
        for scan_id, scan_name, file_path in nessus_files:
            logger.info(f"Parsing scan file: {file_path}")
            
            parser = NessusParser(file_path)
            parsed_data = parser.parse()
            
            # Get scan details again to ensure correct name association
            client = _get_client()
            scan_details = client.get_scan_details(int(scan_id))
            correct_scan_name = f"Scan {scan_id}"
            if 'info' in scan_details:
                correct_scan_name = scan_details['info'].get('name', correct_scan_name)
            
            logger.info(f"Using scan name '{correct_scan_name}' for scan ID {scan_id}")
            
            # Add scan name to each vulnerability for tracking
            if 'vulnerabilities' in parsed_data:
                for vuln in parsed_data['vulnerabilities']:
                    vuln['scan_name'] = correct_scan_name
            
            parsed_data_list.append((scan_id, correct_scan_name, parsed_data))
            logger.info(f"Parsed {len(parsed_data.get('vulnerabilities', []))} vulnerabilities from {file_path}")
        
        converter = NessusConverter()
        
        if export_format == 'csv':
            # Export to a single CSV
            output_filename = f"batch_export_{timestamp}.csv"
            output_file = os.path.join(app.config['UPLOAD_FOLDER'], output_filename)
            logger.info(f"Generating CSV export to {output_file}")
            success = converter.batch_to_csv(parsed_data_list, output_file)
            
            if not success:
                if is_ajax:
                    return jsonify({'success': False, 'message': 'Failed to generate CSV file'})
                flash('Failed to generate CSV file', 'danger')
                return redirect(url_for('dashboard'))
                
            if is_ajax:
                return jsonify({
                    'success': True, 
                    'message': f'Exported {len(nessus_files)} scans to CSV', 
                    'download_url': url_for('download_exported_file', filename=output_filename)
                })
            flash(f'Exported {len(nessus_files)} scans to CSV: {output_filename}', 'success')
        else:
            # Default to Excel with multiple sheets
            output_filename = f"batch_export_{timestamp}.xlsx"
            output_file = os.path.join(app.config['UPLOAD_FOLDER'], output_filename)
            logger.info(f"Generating Excel export to {output_file}")
            success = converter.batch_to_excel(parsed_data_list, output_file)
            
            if not success:
                if is_ajax:
                    return jsonify({'success': False, 'message': 'Failed to generate Excel file'})
                flash('Failed to generate Excel file', 'danger')
                return redirect(url_for('dashboard'))
            
            logger.info(f"Excel file generated successfully: {output_file}")
            if is_ajax:
                download_url = url_for('download_exported_file', filename=output_filename)
                logger.info(f"Providing download URL: {download_url}")
                return jsonify({
                    'success': True, 
                    'message': f'Exported {len(nessus_files)} scans to Excel', 
                    'download_url': download_url
                })
            flash(f'Exported {len(nessus_files)} scans to Excel: {output_filename}', 'success')
        
        return redirect(url_for('dashboard'))
    
    except Exception as e:
        logger.error(f'Failed to process batch download: {str(e)}')
        logger.debug(traceback.format_exc())
        if is_ajax:
            return jsonify({'success': False, 'message': str(e)})
        flash(f'Failed to process batch download: {str(e)}', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/download-exported-file/<filename>')
def download_exported_file(filename):
    """Serve a previously exported file for download."""
    try:
        logger.info(f"Request to download file: {filename}")
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        if not os.path.exists(file_path):
            logger.error(f"File not found: {file_path}")
            flash(f'File not found: {filename}', 'danger')
            return redirect(url_for('dashboard'))
            
        logger.info(f"Serving file for download: {file_path}")
        return send_from_directory(
            directory=app.config['UPLOAD_FOLDER'], 
            path=filename, 
            as_attachment=True
        )
    except Exception as e:
        logger.error(f'Failed to download file {filename}: {str(e)}')
        logger.debug(traceback.format_exc())
        flash(f'Failed to download file: {str(e)}', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/delete-export/<filename>', methods=['POST'])
def delete_export(filename):
    """Delete an exported file."""
    if not _is_connected():
        return jsonify({'success': False, 'message': 'Not connected to server'})
    
    try:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        if os.path.exists(file_path):
            os.remove(file_path)
            return jsonify({'success': True})
        else:
            return jsonify({'success': False, 'message': 'File not found'})
    except Exception as e:
        logger.error(f'Failed to delete file {filename}: {str(e)}')
        logger.debug(traceback.format_exc())
        return jsonify({'success': False, 'message': str(e)})

@app.route('/logout')
def logout():
    """Clear session data."""
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('index'))

@app.route('/export-scan/<int:scan_id>')
def export_scan(scan_id):
    """Export a single scan to Nessus format and download it."""
    if not _is_connected():
        if request.args.get('ajax') == '1':
            return jsonify({'success': False, 'message': 'Not connected to server'})
        flash('Please connect to a Nessus server first', 'warning')
        return redirect(url_for('index'))
    
    is_ajax = request.args.get('ajax') == '1'
    
    try:
        # Get connection parameters from session
        url = session['nessus_url']
        username = session['nessus_username']
        password = session['nessus_password']
        verify_ssl = session['nessus_verify_ssl']
        
        # Get scan details to ensure correct naming
        client = _get_client()
        scan_details = client.get_scan_details(scan_id)
        scan_name = f"scan_{scan_id}"
        if 'info' in scan_details:
            scan_name = scan_details['info'].get('name', scan_name)
        
        logger.info(f"Exporting scan ID {scan_id}: {scan_name}")
        
        # Create a filename with the scan ID clearly indicated
        # Ensure the scan ID is part of the filename in a consistent format
        safe_name = "".join(c if c.isalnum() or c in ['-', '_', '.'] else '_' for c in scan_name)
        filename = f"{safe_name}_ScanID{scan_id}.nessus"
        
        # Export directly through the client to ensure correct ID association
        file_path = client.export_and_download(scan_id, app.config['UPLOAD_FOLDER'], filename)
        
        if not file_path:
            if is_ajax:
                return jsonify({'success': False, 'message': f'Failed to export scan with ID {scan_id}'})
            flash(f'Failed to export scan with ID {scan_id}', 'danger')
            return redirect(url_for('dashboard'))
        
        if is_ajax:
            return jsonify({
                'success': True, 
                'message': f'Scan exported successfully', 
                'download_url': url_for('download_exported_file', filename=os.path.basename(file_path))
            })
        
        flash(f'Scan exported to: {os.path.basename(file_path)}', 'success')
        return redirect(url_for('dashboard'))
        
    except Exception as e:
        logger.error(f'Failed to export scan {scan_id}: {str(e)}')
        logger.debug(traceback.format_exc())
        if is_ajax:
            return jsonify({'success': False, 'message': str(e)})
        flash(f'Failed to export scan: {str(e)}', 'danger')
        return redirect(url_for('dashboard'))

def _is_connected():
    """Check if connected to a Nessus server."""
    return all(k in session for k in ['nessus_url', 'nessus_username', 'nessus_password'])

def _get_client():
    """Get a configured NessusClient from session data."""
    if not _is_connected():
        return None
    
    return NessusClient(
        session['nessus_url'],
        session['nessus_username'],
        session['nessus_password'],
        session['nessus_verify_ssl']
    )

def run_webapp(host='0.0.0.0', port=5000, debug=False):
    """Run the Flask web application."""
    app.run(host=host, port=port, debug=debug)

if __name__ == '__main__':
    run_webapp(debug=True)