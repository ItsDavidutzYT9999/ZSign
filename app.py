from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import subprocess
import zipfile
import plistlib
import uuid
from werkzeug.utils import secure_filename

app = Flask(__name__)
CORS(app)

# In-memory certificate state (paths point to temp files created only once)
stored_p12_path = None
stored_password = None
stored_mobileprovision_path = None

ALLOWED = {
    'ipa': {'ipa'},
    'p12': {'p12'},
    'mp': {'mobileprovision'}
}

def allowed_file(filename, allowed):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed

def extract_app_info(ipa_path):
    try:
        with zipfile.ZipFile(ipa_path, 'r') as zf:
            app_dir = next((n for n in zf.namelist() if n.endswith('.app/') and '/Payload/' in n), None)
            if not app_dir:
                return None, None
            info_path = app_dir + 'Info.plist'
            if info_path not in zf.namelist():
                return None, None
            with zf.open(info_path) as f:
                plist_data = plistlib.load(f)
                app_name = plist_data.get('CFBundleDisplayName') or plist_data.get('CFBundleName', 'Unknown App')
                bundle_id = plist_data.get('CFBundleIdentifier', 'unknown.bundle')
                return app_name, bundle_id
    except Exception:
        return None, None

def run_curl_upload_bytes(data: bytes, remote_name: str) -> str | None:
    # Upload bytes to transfer.sh without writing a local file
    try:
        proc = subprocess.run(
            [
                'curl', '--silent', '--show-error',
                '--upload-file', '-', f'https://transfer.sh/{remote_name}'
            ],
            input=data,
            capture_output=True
        )
        if proc.returncode == 0:
            return proc.stdout.decode().strip()
        return None
    except Exception:
        return None

def run_curl_upload_file(path: str, remote_name: str) -> str | None:
    # Upload a file directly with curl; avoids creating duplicates
    try:
        proc = subprocess.run(
            [
                'curl', '--silent', '--show-error',
                '--upload-file', path, f'https://transfer.sh/{remote_name}'
            ],
            capture_output=True
        )
        if proc.returncode == 0:
            return proc.stdout.decode().strip()
        return None
    except Exception:
        return None

@app.route('/uploadCert', methods=['POST'])
def upload_cert():
    global stored_p12_path, stored_password, stored_mobileprovision_path

    if 'p12' not in request.files or 'mobileprovision' not in request.files:
        return jsonify({'status': 'error', 'message': 'Missing p12 or mobileprovision'}), 400

    p12f = request.files['p12']
    mpf = request.files['mobileprovision']
    pwd = request.form.get('password', '')

    if not pwd:
        return jsonify({'status': 'error', 'message': 'Password is required'}), 400
    if not allowed_file(p12f.filename, ALLOWED['p12']):
        return jsonify({'status': 'error', 'message': 'Invalid .p12 file'}), 400
    if not allowed_file(mpf.filename, ALLOWED['mp']):
        return jsonify({'status': 'error', 'message': 'Invalid .mobileprovision file'}), 400

    # Save once to ephemeral temp files for zsign usage
    p12_path = f"/tmp/{secure_filename('cert_' + str(uuid.uuid4()) + '.p12')}"
    mp_path = f"/tmp/{secure_filename('profile_' + str(uuid.uuid4()) + '.mobileprovision')}"
    p12f.save(p12_path)
    mpf.save(mp_path)

    stored_p12_path = p12_path
    stored_password = pwd
    stored_mobileprovision_path = mp_path

    return jsonify({'status': 'success', 'message': 'Certificates uploaded successfully'})

@app.route('/signIPA', methods=['POST'])
def sign_ipa():
    if 'file' not in request.files:
        return jsonify({'status': 'error', 'message': 'No IPA file provided'}), 400
    if not all([stored_p12_path, stored_password, stored_mobileprovision_path]):
        return jsonify({'status': 'error', 'message': 'Certificates not uploaded'}), 412

    ipaf = request.files['file']
    if not allowed_file(ipaf.filename, ALLOWED['ipa']):
        return jsonify({'status': 'error', 'message': 'Invalid .ipa file'}), 400

    # Save IPA temporarily for zsign to read
    ipa_in_path = f"/tmp/{secure_filename('input_' + str(uuid.uuid4()) + '.ipa')}"
    ipaf.save(ipa_in_path)

    app_name, bundle_id = extract_app_info(ipa_in_path)
    if not app_name or not bundle_id:
        try: os.remove(ipa_in_path)
        except Exception: pass
        return jsonify({'status': 'error', 'message': 'Could not extract app info'}), 400

    # Sign into a temp file
    ipa_out_path = f"/tmp/{secure_filename('signed_' + str(uuid.uuid4()) + '.ipa')}"
    cmd = [
        'zsign',
        '-k', stored_p12_path,
        '-p', stored_password,
        '-m', stored_mobileprovision_path,
        '-o', ipa_out_path,
        ipa_in_path
    ]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        try:
            os.remove(ipa_in_path)
            if os.path.exists(ipa_out_path): os.remove(ipa_out_path)
        except Exception:
            pass
        return jsonify({'status': 'error', 'message': f'zsign error: {res.stderr}'}), 500

    # Upload signed IPA to transfer.sh directly via curl (no extra local copy)
    ipa_remote_name = f"signed_{uuid.uuid4()}.ipa"
    ipa_url = run_curl_upload_file(ipa_out_path, ipa_remote_name)
    if not ipa_url:
        try:
            os.remove(ipa_in_path)
            os.remove(ipa_out_path)
        except Exception:
            pass
        return jsonify({'status': 'error', 'message': 'Failed to upload signed IPA'}), 500

    # Create manifest.plist in memory and upload via stdin
    manifest = {
        'items': [{
            'assets': [{ 'kind': 'software-package', 'url': ipa_url }],
            'metadata': {
                'bundle-identifier': bundle_id,
                'bundle-version': '1.0',
                'kind': 'software',
                'title': app_name
            }
        }]
    }
    manifest_bytes = plistlib.dumps(manifest)
    manifest_remote_name = f"manifest_{uuid.uuid4()}.plist"
    manifest_url = run_curl_upload_bytes(manifest_bytes, manifest_remote_name)
    if not manifest_url:
        try:
            os.remove(ipa_in_path)
            os.remove(ipa_out_path)
        except Exception:
            pass
        return jsonify({'status': 'error', 'message': 'Failed to upload manifest'}), 500

    itms_url = f"itms-services://?action=download-manifest&url={manifest_url}"

    # Cleanup temps
    try:
        os.remove(ipa_in_path)
        os.remove(ipa_out_path)
    except Exception:
        pass

    return jsonify({'status': 'success', 'message': f'IPA signed: {app_name} ({bundle_id})', 'itms_url': itms_url})

@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok'})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)
