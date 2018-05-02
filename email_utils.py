import os

from flask_mail import Message

SENDER = os.getenv('MAIL_USERNAME')

def send_confirmation_message(recipient, url, app, mail):
    '''send confirmation message to recipient'''
    msg = Message('confirmation message', sender=SENDER, recipients=[recipient])
    msg.body = 'text body'

    html_body = '<p> to create an account with the email {} please follow the link</p>'.format(
            recipient)
    html_body += '<p>{}</p>'.format(url)
    msg.html = html_body
    
    with app.app_context():
        mail.send(msg)
