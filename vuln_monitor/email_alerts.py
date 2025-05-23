# email_alerts.py
import smtplib
from email.message import EmailMessage
from smtplib import SMTPException

def send_email_alert(subject, body, config):
    msg = EmailMessage()
    msg.set_content(body)
    msg['Subject'] = subject
    msg['From'] = config['email']['sender']
    msg['To'] = ', '.join(config['email']['recipients'])

    try:
        with smtplib.SMTP(config['email']['smtp_server'], config['email']['smtp_port']) as server:
            server.starttls()
            if 'username' in config['email'] and 'password' in config['email']:
                server.login(config['email']['username'], config['email']['password'])
            server.send_message(msg)
    except SMTPException as e:
        raise RuntimeError(f"Failed to send email: {e}")
