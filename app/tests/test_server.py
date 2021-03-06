import email
import imaplib
import os
import re
import time
import urllib3

import pytest
import requests

# disable insecure request warning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

URL = os.getenv('WEBAPP_URL')
X_API_KEY = os.getenv('X_API_KEY')

SESSION = requests.Session()

verify_certificate = os.getenv('VERIFY_CERTIFICATE')
if verify_certificate == 'true':
    SESSION.verify = True
else:
    SESSION.verify = False

TEST_EMAIL = os.getenv('TEST_MAIL_USERNAME')
TEST_PASSWORD = os.getenv('TEST_MAIL_PASSWORD')
MAIL_SERVER = 'imap.gmail.com'
MAIL_PORT = 993

# helper functions
def get_csrf_token(server_response):
    '''grab csrf token from html of server_response'''

    text = server_response.text.replace('\n', '')

    return re.sub(r'^.*name."csrf_token" value."([^"]*)".*$', r'\1', text)

# get link from email
def get_link():
    mail = imaplib.IMAP4_SSL(MAIL_SERVER)
    mail.login(TEST_EMAIL, TEST_PASSWORD)

    mail.select('inbox')

    m_type, data = mail.search(None, 'ALL')

    mail_ids = data[0]
    mail_ids = [m_id for m_id in mail_ids.split()]

    m_type, data = mail.fetch(mail_ids[-1], '(RFC822)')

    msg = data[0][1].decode()

    link = re.findall(r'<p>http.*</p>', msg)[0]
    link = link[3:-4]

    return link


def test_home():
    url = URL

    r = SESSION.get(url)

    assert r.status_code == 200


def test_unauthorized_secret_portal():
    url = URL + '/super-secret'

    r = SESSION.get(url)

    assert r.status_code == 401

def test_create_user():
    url = URL + '/user'

    r = SESSION.get(url)

    assert r.status_code == 200

    SESSION.headers.update({
        'X-CSRFToken': get_csrf_token(r)
        })

    payload = {
            'email': TEST_EMAIL,
            }

    r = SESSION.post(url, data=payload, headers={'Referer': r.request.url})

    assert r.status_code == 200

def test_fail_to_create_user_with_same_email():
    # give time for user to be created
    time.sleep(5)

    url = URL + '/user'

    r = SESSION.get(url)

    assert r.status_code == 200

    SESSION.headers.update({
        'X-CSRFToken': get_csrf_token(r)
        })

    payload = {
            'email': TEST_EMAIL,
            }

    r = SESSION.post(url, data=payload, headers={'Referer': r.request.url})

    assert r.status_code == 400


def test_confirm_user_fake_token_failure():
    url = URL + '/user/12345'

    r = SESSION.get(url)

    assert r.status_code != 200

def test_confirm_user():
    # give time for email to be sent
    time.sleep(5)

    url = get_link()

    r = SESSION.get(url)

    assert r.status_code == 200

    SESSION.headers.update({
        'X-CSRFToken': get_csrf_token(r)
        })

    payload = {
            'password': TEST_PASSWORD,
            }

    r = SESSION.post(r.request.url, data=payload, headers={'Referer': r.request.url})

    assert r.status_code == 200

def test_login_user():
    # give time for account to be created
    time.sleep(5)

    url = URL + '/login'

    r = SESSION.get(url)

    assert r.status_code == 200

    SESSION.headers.update({
        'X-CSRFToken': get_csrf_token(r)
        })

    payload = {
            'email': TEST_EMAIL,
            'password': TEST_PASSWORD,
            }

    r = SESSION.post(url, data=payload, headers={'Referer': r.request.url})

    assert r.status_code == 200


def test_authorized_secret_portal():
    url = URL + '/super-secret'

    r = SESSION.get(url)

    assert r.status_code == 200

def test_logout():
    url = URL + '/logout'

    r = SESSION.get(url)

    assert r.status_code == 200

def test_unauthorized_delete_user():
    url = URL + '/user/' + TEST_EMAIL

    r = requests.delete(url, verify=False)

    assert r.status_code == 401

def test_delete_user():
    url = URL + '/user/' + TEST_EMAIL

    r = requests.delete(url, verify=False,
            headers={'x-api-key': X_API_KEY})

    assert r.status_code == 200
