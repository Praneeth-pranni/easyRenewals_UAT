import string
import random
import smtplib
from config import MAILSERVER,MAILSERVER_DOMAIN,MAILSERVER_PORT,MAILSERVER_USERNAME,MAILSERVER_PASSWORD
from encryption import DataEncryption
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import jwt
from datetime import datetime


def RandomStringwithDigitsAndSymbols(stringLength=10):
    """Generate a random string of letters, digits and special characters """

    password_characters = string.ascii_letters + string.digits
    return ''.join(random.choice(password_characters) for i in range(stringLength))

def toSendEmail(toEmail,subject,message):
    smtpObj = smtplib.SMTP_SSL(MAILSERVER_DOMAIN, port = MAILSERVER_PORT)
    smtpObj.login(DataEncryption().decrypt(MAILSERVER_USERNAME), DataEncryption().decrypt(MAILSERVER_PASSWORD))
    msg = MIMEMultipart()
    msg['subject'] = subject
    msg['from'] = DataEncryption().decrypt(MAILSERVER_USERNAME)
    msg['to'] = toEmail
    msgtext1 = MIMEText(message, 'html')
    msg.attach(msgtext1)
    try:
        smtpObj.sendmail(DataEncryption().decrypt(MAILSERVER_USERNAME), toEmail, msg.as_string())
    except Exception as e:
        print(e)
        return "mail failed"
    print("mail sent")
    return "mail sent"


def checkToken(token):
    print("In check token")
    result = False
    try:
        print(token)
        datas = token.replace('"', '')
        print(datas)
        decoded = jwt.decode(datas, str('secret'), 'utf-8')
        print(decoded)
        if decoded["exp"] != datetime.now().timestamp():
            result = True
    except jwt.DecodeError:
        print("decode error")
        result = False
    except jwt.ExpiredSignatureError:
        print("sign")
        result = False
    except KeyError:
        print("key error")
        print(result)
        result = False

    return result


