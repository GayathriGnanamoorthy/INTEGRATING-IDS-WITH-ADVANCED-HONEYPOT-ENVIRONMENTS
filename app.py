import json
import re
import os
from flask import Flask, render_template, request, redirect, url_for
from werkzeug.utils import secure_filename

def parse_cowrie_logs(log_file):
    if not os.path.isfile(log_file):
        raise FileNotFoundError(f"Log file '{log_file}' not found.")

    try:
        with open(log_file, 'r') as f:
            log_entries = []
            for line in f:
                try:
                    log_entry = json.loads(line)
                    log_entries.append(log_entry)
                except json.JSONDecodeError:
                    print(f"Skipping malformed JSON entry: {line}")

            index = 0
            while index < len(log_entries):
                if 'eventid' in log_entries[index] and log_entries[index]['eventid'] == 'cowrie.login.success':
                    username = log_entries[index].get('username')
                    password = log_entries[index].get('password')
                    source_ip = log_entries[index].get('src_ip')

                    # Search for the destination IP in subsequent log entries
                    destination_ip = None
                    for next_index in range(index + 1, len(log_entries)):
                        if 'dst_ip' in log_entries[next_index]:
                            destination_ip = log_entries[next_index]['dst_ip']
                            break

                    if username is not None and password is not None and source_ip is not None and destination_ip is not None:
                        yield (username, password, source_ip, destination_ip)

                index += 1
    except Exception as e:
        print(f"Error occurred while parsing Cowrie logs: {e}")

def parse_honeytrap_logs(log_file):
    if not os.path.isfile(log_file):
        raise FileNotFoundError(f"Log file '{log_file}' not found.")

    log_pattern = r'(\d+\.\d+\.\d+\.\d+:\d+) -> (\d+\.\d+\.\d+\.\d+:\d+) [0-9a-f]+ [0-9a-f]+ \((\d+) bytes\)'
    parsed_data = []
    try:
        with open(log_file, 'r') as file:
            for line in file:
                match = re.search(log_pattern, line)
                if match:
                    source_ip = match.group(1)
                    destination_ip = match.group(2)
                    bytes_count = match.group(3)
                    parsed_data.append((source_ip, destination_ip, bytes_count))
    except Exception as e:
        print(f"Error occurred while parsing HoneyTrap logs: {e}")

    return parsed_data

def generate_suricata_rule_cowrie(parsed_data, initial_sid):
    rules = []
    sid = initial_sid
    for data in parsed_data:
        username, password, source_ip, destination_ip = data
        escaped_username = username.replace('"', '\\"')  # Escape double quotes
        escaped_password = password.replace('"', '\\"')  # Escape double quotes
        rule = f'alert tcp {source_ip} -> {destination_ip} (msg:"Suspicious activity detected: Login attempt with username: \\"{escaped_username}\\" and password: \\"{escaped_password}\\"; sid:{sid}; rev:1; classtype:attempted-user;)'
        rules.append(rule)
        sid += 1
    return rules

def generate_suricata_rule_honeytrap(parsed_data, initial_sid):
    rules = []
    sid = initial_sid
    for data in parsed_data:
        source_ip, destination_ip, bytes_count = data
        rule = f'alert tcp {source_ip}:any -> {destination_ip}:22 (msg:"Suspicious activity detected: Unauthorized access attempt with {bytes_count} bytes"; sid:{sid}; rev:1; classtype:attempted-recon;)'
        rules.append(rule)
        sid += 1
    return rules

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads/'

@app.route('/', methods=['GET', 'POST'])
def index():
    suricata_rules = []
    cowrie_error = None
    honeytrap_error = None

    if request.method == 'POST':
        initial_sid = int(request.form['initial_sid'])

        # Upload Cowrie log file
        cowrie_file = request.files.get('cowrie_logs')
        if cowrie_file:
            cowrie_filename = secure_filename(cowrie_file.filename)
            cowrie_file_path = os.path.join(app.config['UPLOAD_FOLDER'], cowrie_filename)
            cowrie_file.save(cowrie_file_path)

            try:
                cowrie_data = list(parse_cowrie_logs(cowrie_file_path))
            except FileNotFoundError as e:
                cowrie_error = str(e)
            except Exception as e:
                cowrie_error = f"Error occurred while parsing Cowrie logs: {e}"
            else:
                cowrie_rules = generate_suricata_rule_cowrie(cowrie_data, initial_sid)
                suricata_rules.extend(cowrie_rules)

        # Upload HoneyTrap log file
        honeytrap_file = request.files.get('honeytrap_logs')
        if honeytrap_file:
            honeytrap_filename = secure_filename(honeytrap_file.filename)
            honeytrap_file_path = os.path.join(app.config['UPLOAD_FOLDER'], honeytrap_filename)
            honeytrap_file.save(honeytrap_file_path)

            try:
                honeytrap_data = parse_honeytrap_logs(honeytrap_file_path)
            except FileNotFoundError as e:
                honeytrap_error = str(e)
            except Exception as e:
                honeytrap_error = f"Error occurred while parsing HoneyTrap logs: {e}"
            else:
                honeytrap_rules = generate_suricata_rule_honeytrap(honeytrap_data, initial_sid)
                suricata_rules.extend(honeytrap_rules)

    return render_template('index.html', suricata_rules=suricata_rules, cowrie_error=cowrie_error, honeytrap_error=honeytrap_error)

if __name__ == '__main__':
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    app.run(debug=True)