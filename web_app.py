#!/usr/bin/env python3
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
import os
import json
from datetime import datetime
from .nessus_client import NessusClient
from .nessus_downloader import NessusDownloader
from .nessus_parser import NessusParser
from .nessus_converter import NessusConverter

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
            flash('Failed to connect to Nessus server', 'danger')
            return redirect(url_for('index'))
        
        flash('Successfully connected to Nessus server', 'success')
        return redirect(url_for('dashboard'))
    except Exception as e:
        flash(f'Connection failed: {str(e)}', 'danger')
        return redirect(url_for('index'))

@app.route('/dashboard')
def dashboard():
    """Show the main dashboard with scan list."""
    if not _is_connected():
        flash('Please connect to a Nessus server first', 'warning')
        return redirect(url_for('index'))
    
    client = _get_client()
    try:
        response = client.list_scans()
        scans = response.get('scans', [])
        return render_template('dashboard.html', scans=scans)
    except Exception as e:
        flash(f'Failed to get scans: {str(e)}', 'danger')
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
        return jsonify({'success': False, 'message': str(e)})

@app.route('/download-scan/<int:scan_id>')
def download_scan(scan_id):
    """Download a scan by ID."""
    if not _is_connected():
        flash('Please connect to a Nessus server first', 'warning')
        return redirect(url_for('index'))
    
    try:
        url = session['nessus_url']
        username = session['nessus_username']
        password = session['nessus_password']
        verify_ssl = session['nessus_verify_ssl']
        
        downloader = NessusDownloader(url, username, password, verify_ssl)
        file_path = downloader.download_scan(scan_id, app.config['UPLOAD_FOLDER'])
        
        if not file_path:
            flash(f'Failed to download scan with ID {scan_id}', 'danger')
            return redirect(url_for('dashboard'))
        
        # Process the file
        parser = NessusParser(file_path)
        parsed_data = parser.parse()
        
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        output_file = os.path.join(app.config['UPLOAD_FOLDER'], f'scan_{scan_id}_{timestamp}.xlsx')
        
        converter = NessusConverter()
        converter.to_excel(parsed_data, output_file)
        
        flash(f'Scan downloaded and converted to Excel: {output_file}', 'success')
        return redirect(url_for('dashboard'))
    except Exception as e:
        flash(f'Failed to download scan: {str(e)}', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    """Clear session data."""
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('index'))

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