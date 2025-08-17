from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import tempfile
import subprocess
import zipfile
import plistlib
import requests
import json
from werkzeug.utils import secure_filename
import uuid

app = Flask(__name__)
CORS(app)

# Configuration
UPLOAD_FOLDER = '/app/uploads'
ALLOWED_EXTENSIONS = {'ipa', 'p12', 'mobileprovision'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Global variables to store certificates
stored_p12_path = None
stored_password = None
stored_mobileprovision_path = None

def allowed_file(filename, allowed_extensions):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions

def extract_app_info(ipa_path):
    """Extract app name and bundle ID from IPA"""
    try:
        with zipfile.ZipFile(ipa_path, 'r') as zip_ref:
            # Find the .app directory
            app_dir = None
            for name in zip_ref.namelist():
                if name.endswith('.app/') and '/Payload/' in name:
                    app_dir = name
                    break
            
            if not app_dir:
                return None, None
            
            # Extract Info.plist
            info_plist_path = app_dir + 'Info.plist'
            if info_plist_path in zip_ref.namelist():
                with zip_ref.open(info_plist_path) as f:
                    plist_data = plistlib.load(f)
                    
                    app_name = plist_data.get('CFBundleDisplayName') or plist_data.get('CFBundleName', 'Unknown App')
                    bundle_id = plist_data.get('CFBundleIdentifier', 'Unknown Bundle ID')
                    
                    return app_name, bundle_id
    
    except Exception as e:
        print(f"Error extracting app info: {e}")
        return None, None

def sign_ipa_with_zsign(ipa_path, output_path):
    """Sign IPA using zsign"""
    try:
        if not all([stored_p12_path, stored_password, stored_mobileprovision_path]):
            return False, "Certificates not uploaded"
        
        # zsign command
        cmd = [
            'zsign',
            '-k', stored_p12_path,
            '-p', stored_password,
            '-m', stored_mobileprovision_path,
            '-o', output_path,
            ipa_path
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            return True, "IPA signed successfully"
        else:
            return False, f"zsign error: {result.stderr}"
    
    except Exception as e:
        return False, f"Signing error: {str(e)}"

def upload_to_transfer_sh(file_path):
    """Upload file to transfer.sh"""
    try:
        with open(file_path, 'rb') as f:
            response = requests.post('https://transfer.sh/', files={'file': f})
            if response.status_code == 200:
                return response.text.strip()
            else:
                return None
    except Exception as e:
        print(f"Upload error: {e}")
        return None

def create_manifest_plist(app_name, bundle_id, ipa_url):
    """Create manifest.plist for ITMS installation"""
    manifest = {
        'items': [{
            'assets': [{
                'kind': 'software-package',
                'url': ipa_url
            }],
            'metadata': {
                'bundle-identifier': bundle_id,
                'bundle-version': '1.0',
                'kind': 'software',
                'title': app_name
            }
        }]
    }
    
    return plistlib.dumps(manifest)

@app.route('/uploadCert', methods=['POST'])
def upload_certificates():
    global stored_p12_path, stored_password, stored_mobileprovision_path
    
    try:
        if 'p12' not in request.files or 'mobileprovision' not in request.files:
            return jsonify({'status': 'error', 'message': 'Missing p12 or mobileprovision file'}), 400
        
        p12_file = request.files['p12']
        mobileprovision_file = request.files['mobileprovision']
        password = request.form.get('password', '')
        
        if not password:
            return jsonify({'status': 'error', 'message': 'Password is required'}), 400
        
        if not allowed_file(p12_file.filename, {'p12'}):
            return jsonify({'status': 'error', 'message': 'Invalid p12 file'}), 400
        
        if not allowed_file(mobileprovision_file.filename, {'mobileprovision'}):
            return jsonify({'status': 'error', 'message': 'Invalid mobileprovision file'}), 400
        
        # Save files
        p12_filename = secure_filename(f"cert_{uuid.uuid4()}.p12")
        mobileprovision_filename = secure_filename(f"profile_{uuid.uuid4()}.mobileprovision")
        
        p12_path = os.path.join(app.config['UPLOAD_FOLDER'], p12_filename)
        mobileprovision_path = os.path.join(app.config['UPLOAD_FOLDER'], mobileprovision_filename)
        
        p12_file.save(p12_path)
        mobileprovision_file.save(mobileprovision_path)
        
        # Store globally
        stored_p12_path = p12_path
        stored_password = password
        stored_mobileprovision_path = mobileprovision_path
        
        return jsonify({
            'status': 'success',
            'message': 'Certificates uploaded successfully'
        })
    
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Upload error: {str(e)}'}), 500

@app.route('/signIPA', methods=['POST'])
def sign_ipa():
    try:
        if 'file' not in request.files:
            return jsonify({'status': 'error', 'message': 'No IPA file provided'}), 400
        
        ipa_file = request.files['file']
        
        if not allowed_file(ipa_file.filename, {'ipa'}):
            return jsonify({'status': 'error', 'message': 'Invalid IPA file'}), 400
        
        if not all([stored_p12_path, stored_password, stored_mobileprovision_path]):
            return jsonify({'status': 'error', 'message': 'Certificates not uploaded. Please upload certificates first.'}), 412
        
        # Save uploaded IPA
        ipa_filename = secure_filename(f"input_{uuid.uuid4()}.ipa")
        ipa_path = os.path.join(app.config['UPLOAD_FOLDER'], ipa_filename)
        ipa_file.save(ipa_path)
        
        # Extract app info
        app_name, bundle_id = extract_app_info(ipa_path)
        if not app_name or not bundle_id:
            return jsonify({'status': 'error', 'message': 'Could not extract app info from IPA'}), 400
        
        # Sign IPA
        signed_ipa_path = os.path.join(app.config['UPLOAD_FOLDER'], f"signed_{uuid.uuid4()}.ipa")
        success, message = sign_ipa_with_zsign(ipa_path, signed_ipa_path)
        
        if not success:
            return jsonify({'status': 'error', 'message': message}), 500
        
        # Upload signed IPA to transfer.sh
        ipa_url = upload_to_transfer_sh(signed_ipa_path)
        if not ipa_url:
            return jsonify({'status': 'error', 'message': 'Failed to upload signed IPA'}), 500
        
        # Create manifest.plist
        manifest_content = create_manifest_plist(app_name, bundle_id, ipa_url)
        manifest_path = os.path.join(app.config['UPLOAD_FOLDER'], f"manifest_{uuid.uuid4()}.plist")
        
        with open(manifest_path, 'wb') as f:
            f.write(manifest_content)
        
        # Upload manifest to transfer.sh
        manifest_url = upload_to_transfer_sh(manifest_path)
        if not manifest_url:
            return jsonify({'status': 'error', 'message': 'Failed to upload manifest'}), 500
        
        # Create ITMS URL
        itms_url = f"itms-services://?action=download-manifest&url={manifest_url}"
        
        # Cleanup temporary files
        try:
            os.remove(ipa_path)
            os.remove(signed_ipa_path)
            os.remove(manifest_path)
        except:
            pass
        
        return jsonify({
            'status': 'success',
            'message': f'IPA signed successfully: {app_name} ({bundle_id})',
            'itms_url': itms_url
        })
    
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Signing error: {str(e)}'}), 500

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'ok', 'message': 'Backend is running'})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)
