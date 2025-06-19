import logging
import json
import requests
import os
import smtplib
from email.mime.text import MIMEText

def main(req):
    req_body = req.get_json()
    alert_context = req_body['data']['alertContext']
    api_url = alert_context['condition']['allOf'][0]['linkToFilteredSearchResultsAPI']
    
    # App Insights API Key (stockée dans App Settings)
    api_key = os.environ['APPINSIGHTS_API_KEY']
    
    headers = {
        'x-api-key': api_key
    }
    
    response = requests.get(api_url, headers=headers)
    result = response.json()
    
    rows = result['tables'][0]['rows']
    email_content = ""

    for row in rows:
        timestamp = row[0]
        name = row[1]
        custom = json.loads(row[2])
        device = custom.get("DeviceName", "N/A")
        instance = row[3]
        
        email_content += f"""
        <p><b>Timestamp:</b> {timestamp}<br/>
        <b>Name:</b> {name}<br/>
        <b>Device:</b> {device}<br/>
        <b>Instance:</b> {instance}</p>
        <hr/>
        """

    send_email(email_content)
    return {
        "status": 200,
        "body": "Email sent"
    }

def send_email(content):
    smtp_server = os.environ['SMTP_SERVER']
    smtp_user = os.environ['SMTP_USER']
    smtp_pass = os.environ['SMTP_PASS']
    sender = smtp_user
    recipient = os.environ['EMAIL_RECIPIENT']

    msg = MIMEText(content, 'html')
    msg['Subject'] = 'App Insights Alert'
    msg['From'] = sender
    msg['To'] = recipient

    with smtplib.SMTP(smtp_server, 587) as server:
        server.starttls()
        server.login(smtp_user, smtp_pass)
        server.sendmail(sender, [recipient], msg.as_string())
