#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import json
import time
from datetime import datetime, timedelta
import urllib3
from requests.auth import HTTPBasicAuth

try:
    import requests
except Exception:
    print("No module 'requests' found. Install: pip3 install requests")
    sys.exit(1)

CHAT_ID = "-4293547659"

def get_document_id(index_name, alert_id, retries=7, delay=3):
    document_headers = {'content-type': 'application/json'}
    document_url = f"https://192.168.140.109:9200/{index_name}/_search?pretty"
    document_data = json.dumps({
        "query": {
            "term": {
                "id": f"{alert_id}"
            }
        }
    })

    urllib3.disable_warnings(category=urllib3.exceptions.InsecureRequestWarning)

    for attempt in range(retries):
        try:
            response_doc = requests.post(document_url, headers=document_headers, data=document_data,
                                         auth=HTTPBasicAuth(username="admin", password=".AH9QFUXjE7it5iUkLdmBR4.oMf+RF0f"), verify=False)

            if response_doc.status_code == 200:
                response_info = response_doc.json()
                hits = response_info.get('hits', {}).get('hits', [])
                if hits:
                    document_id = hits[0]['_id']
                    country_name = hits[0]['_source'].get('GeoLocation', {}).get('country_name', "Unknown")

                    # Log debug information
                    with open('/var/ossec/logs/integrations.log', 'a') as f:
                        f.write(f"Success: Found document ID {document_id} for alert_id {alert_id}\n")

                    return document_id, country_name

            # Log retries
            with open('/var/ossec/logs/integrations.log', 'a') as f:
                f.write(f"Attempt {attempt + 1}: No hits found for alert_id {alert_id}, retrying in {delay} seconds...\n")
            time.sleep(delay)

        except Exception as e:
            # Log exceptions
            with open('/var/ossec/logs/integrations.log', 'a') as f:
                f.write(f"Exception on attempt {attempt + 1} for alert_id {alert_id}: {e}\n")

    # Log failure
    with open('/var/ossec/logs/integrations.log', 'a') as f:
        f.write(f"Failed to retrieve document ID for alert_id {alert_id} after {retries} attempts at {index_name}\n")
        f.write(f"{response_info}")

    return None, ""

def create_message(alert_json):
    # Get alert information
    title = alert_json['rule']['description'] if 'description' in alert_json['rule'] else ''

    # Get alert level
    alert_level = int(alert_json['data']['alert']['severity'])

    if (alert_level == 1):
        flag = "❌"
    elif (alert_level >= 2):
        flag = "⚠️"

    # Get timestamp
    timestamp = alert_json['data']['timestamp']
    dt = datetime.fromisoformat(timestamp.removesuffix("+0700").replace("T", " "))
    dtime = dt.strftime("%d/%m/%Y %H:%M:%S")

    # Get document id
    dt_utc = dt - timedelta(hours=7)
    index_date = dt_utc.strftime("%Y.%m.%d")
    index_name = f"wazuh-alerts-4.x-{index_date}"
    alert_id = alert_json['id']
    document_id, country_name = get_document_id(index_name, alert_id)

    # Get ip address
    src_ip = alert_json['data']['src_ip'] if 'src_ip' in alert_json['data'] else ''
    dst_ip = alert_json['data']['dest_ip'] if 'dest_ip' in alert_json['data'] else ''
    dst_port = alert_json['data']['dest_port'] if 'dest_port' in alert_json['data'] else ''

    # Format message with HTML
    msg_content = f'{dtime} \n{flag} <b>{title}</b>\n\n'
    msg_content += f'<b>Source IP:</b> <a href="https://www.virustotal.com/gui/ip-address/{src_ip}">{src_ip}</a> {country_name}\n' if len(src_ip) > 0 else ''
    msg_content += f'<b>Destination IP:</b> {dst_ip} <b>Port:</b> {dst_port}\n\n' if len(dst_ip) > 0 else ''
    msg_content += f'<a href="https://guard.bravo.com.vn/app/discover#/doc/wazuh-alerts-*/{index_name}?id={document_id}">More Information</a>'

    # Format message with markdown
    # msg_content = f'{dtime} \n{flag} *{title}*\n\n'
    # msg_content += f'*Source IP:* {src_ip}\n' if len(src_ip) > 0 else ''
    # msg_content += f'*Source IP:* [{src_ip}](https://www.virustotal.com/gui/ip-address/{src_ip})\n' if len(src_ip) > 0 else ''
    # msg_content += f'*Destination IP:* {dst_ip}\n\n' if len(dst_ip) > 0 else ''
    # msg_content += f'*Payload:* \n{payload}'

    # Message content
    msg_data = {}
    msg_data['chat_id'] = CHAT_ID
    msg_data['text'] = msg_content
    msg_data['parse_mode'] = 'HTML'

    # Debug information
    with open('/var/ossec/logs/integrations.log', 'a') as f:
        f.write(f'MSG: {msg_data}\n')

    return json.dumps(msg_data)


# Read configuration parameters
alert_file = open(sys.argv[1])
hook_url = sys.argv[3]

# Read the alert file
alert_json = json.loads(alert_file.read())
alert_file.close()

# Send the request
msg_data = create_message(alert_json)
headers = {'content-type': 'application/json', 'Accept-Charset': 'UTF-8'}
response = requests.post(hook_url, headers=headers, data=msg_data)

# Debug information
error_info = response.json()  # Parse the JSON response
error_code = error_info.get("error_code")
description = error_info.get("description")

with open('/var/ossec/logs/integrations.log', 'a') as f:
    f.write(f'RESPONSE telegram-api: {response} {description}\n\n')
sys.exit(0)
