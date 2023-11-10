from flask import Flask, jsonify, request, send_from_directory, redirect, url_for, session
from flask_oidc import OpenIDConnect
from datetime import datetime
import requests
import os
import json
import logging
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Set up basic logging
logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__, static_url_path='')

app.config.update({
    'OIDC_CLIENT_SECRETS': os.getenv('OIDC_CLIENT_SECRETS', 'client_secrets.json'),
    'OIDC_ID_TOKEN_COOKIE_SECURE': os.getenv('OIDC_ID_TOKEN_COOKIE_SECURE', 'True').lower() == 'true',
    'OIDC_OPENID_REALM': os.getenv('OIDC_OPENID_REALM'),
    'SECRET_KEY': os.getenv('SECRET_KEY'),
    'OIDC_COOKIE_SECURE': os.getenv('OIDC_COOKIE_SECURE', 'True').lower() == 'true',
    'OIDC_CALLBACK_ROUTE': os.getenv('OIDC_CALLBACK_ROUTE', '/oidc-callback'),
    'DEBUG': os.getenv('DEBUG', 'True').lower() == 'true',
})

oidc = OpenIDConnect(app)

# Load the JumpCloud API key from the environment variable
JUMP_CLOUD_API_KEY = os.getenv('JUMP_CLOUD_API_KEY')

# Load the JumpCloud base URL from the environment variable
JUMPCLOUD_BASE_URL = os.getenv('JUMPCLOUD_BASE_URL', 'https://console.jumpcloud.com/api/v2/')

# Load the whitelist from the JSON file
with open('whitelisted_apps.json') as f:
    whitelisted_apps = json.load(f)["whitelisted_apps"]

# Create a mapping of app IDs to compatible OSes
whitelisted_apps_dict = {app['id']: app['compatible_os'] for app in whitelisted_apps}

@app.route('/')
def index():
    if not oidc.user_loggedin:
        return redirect(url_for('login'))
    return send_from_directory(os.getcwd(), 'index.html')

# This route is used to fetch the apps for a user
@app.route('/api/apps', methods=['GET'])
@oidc.require_login
def apps():
    os_filter = request.args.get('os', '').lower()  # Convert the query parameter to lowercase
    headers = {'x-api-key': JUMP_CLOUD_API_KEY}
    params = {'limit': 100}
    response = requests.get(f"{JUMPCLOUD_BASE_URL}softwareapps", headers=headers, params=params)
    if response.status_code != 200:
        print("Error with API call:", response.status_code, response.text)
        return jsonify([])  # Return an empty list in case of API call failure

    all_apps = response.json()
    # Filter apps based on the OS, ensuring the app ID exists in the whitelist dictionary
    # and comparing OS in a case-insensitive manner
    filtered_apps = [
        app for app in all_apps 
        if app['id'] in whitelisted_apps_dict and os_filter in (os.lower() for os in whitelisted_apps_dict[app['id']])
    ]

    return jsonify(filtered_apps)

# This function parses the lastContact string into a datetime object
def parse_last_contact(last_contact_str):
    # Handle the 'Never' case or any other special cases you have
    if last_contact_str == 'Never':
        return datetime.min
    # Parse the lastContact string into a datetime object with the correct format
    return datetime.strptime(last_contact_str, '%Y-%m-%dT%H:%M:%S.%fZ')

# This route is used to fetch the devices for a user
@app.route('/api/devices', methods=['GET'])
@oidc.require_login
def devices():
    user_info = session['oidc_auth_profile']
    user_id = user_info.get('sub')
    devices = get_user_devices(user_id)

    # Sort devices by the parsed 'lastContact' time and include inactive devices
    sorted_devices = sorted(
        devices,
        key=lambda d: parse_last_contact(d['lastContact']),
        reverse=True
    )
    return jsonify(sorted_devices)

# This function fetches the devices for a user from JumpCloud
def get_user_devices(user_id):
    # Fetching the devices for the user from JumpCloud
    url = JUMPCLOUD_BASE_URL + f'users/{user_id}/systems'
    headers = {'x-api-key': JUMP_CLOUD_API_KEY}
    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        print(f"Error: Unable to fetch devices for user {user_id} from JumpCloud. Status code: {response.status_code}, Response: {response.text}")
        return []

    # Parsing the device IDs correctly from the response
    device_ids = [device['id'] for device in response.json()]
    devices_details = []
    for device_id in device_ids:
        # Fetching the details for each device
        url = f'https://console.jumpcloud.com/api/systems/{device_id}'
        device_response = requests.get(url, headers=headers)
        if device_response.status_code != 200:
            print(f"Error: Unable to fetch details for device {device_id} from JumpCloud. Status code: {device_response.status_code}, Response: {device_response.text}")
            continue
        device_data = device_response.json()
        devices_details.append({
            'id': device_id, 
            'name': device_data.get('displayName', 'Unknown'), 
            'os': device_data.get('os', 'Unknown'),
            'osVersion': device_data.get('osVersionDetail', {}).get('osName', 'N/A'),
            'arch': device_data.get('arch', 'Unknown'),
            'hostname': device_data.get('hostname', 'Unknown'),
            'lastContact': device_data.get('lastContact', 'Never'),  
            'active': device_data.get('active', False),
            'model': device_data.get('model', 'Unknown'),
            'manufacturer': device_data.get('manufacturer', 'Unknown'),
            'serialNumber': device_data.get('serialNumber', 'Unknown'),
            'biosVersion': device_data.get('biosVersion', 'Unknown'),
            'biosReleaseDate': device_data.get('biosReleaseDate', 'Unknown'),
            'systemUptime': device_data.get('systemUptime', 'Unknown'),
            'lastUser': device_data.get('lastUser', 'Unknown')
            # ... add other fields as necessary ...
        })
    return devices_details

# This route is used to install an app on a device
@app.route('/api/install', methods=['POST'])
@oidc.require_login
def install():
    data = request.json
    app_id = data['appId']
    device_id = data['deviceId']
    url = f"{JUMPCLOUD_BASE_URL}softwareapps/{app_id}/associations"
    headers = {'x-api-key': JUMP_CLOUD_API_KEY, 'Content-Type': 'application/json'}
    payload = {'op': 'add', 'type': 'system', 'id': device_id}
    response = requests.post(url, headers=headers, json=payload)
    status = 'Initiated' if response.status_code == 200 else 'Failed or already installed'
    return jsonify({'status': status})

@app.route('/login')
@oidc.require_login
def login():
    return redirect(url_for('index'))

@app.route('/logout', methods=['GET'])
def logout():
    oidc.logout()
    return redirect(url_for('index'))

@app.route('/oidc-callback', methods=['GET', 'POST'])
@oidc.require_login
def oidc_callback():
    return redirect(url_for('index'))

# This route is used to fetch the user profile
@app.route('/profile')
@oidc.require_login
def profile():
    user_info = session['oidc_auth_profile']
    user_id = user_info.get('sub')
    name = user_info.get('name')
    email = user_info.get('email')
    return f'User ID: {user_id}, Name: {name}, Email: {email}'

# This route is used to fetch the user info
@app.route('/api/user-info', methods=['GET'])
@oidc.require_login
def user_info():
    user_info = session['oidc_auth_profile']
    return jsonify(user_info)

if __name__ == '__main__':
    app.run(debug=True)