import os
import re

import pytest
import requests

URL = os.getenv('WEBAPP_URL')
X_API_KEY = os.getenv('X_API_KEY')

SESSION = requests.Session()

TEST_EMAIL = 'test@test.com'
TEST_PASSWORD = 'test123'

# helper function
def get_csrf_token(server_response):
    '''grab csrf token from html of server_response'''

    text = server_response.text.replace('\n', '')

    return re.sub(r'^.*name."csrf_token" value."([^"]*)".*$', r'\1', text)

def test_get_login():
    url = URL + '/login'

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
            'password': TEST_PASSWORD
            }

    r = SESSION.post(url, data=payload)

    assert r.status_code == 200

def test_fail_to_create_user_with_same_email():
    url = URL + '/user'

    r = SESSION.get(url)

    assert r.status_code == 200

    SESSION.headers.update({
        'X-CSRFToken': get_csrf_token(r)
        })

    payload = {
            'email': TEST_EMAIL,
            'password': TEST_PASSWORD
            }

    r = SESSION.post(url, data=payload)

    assert r.status_code == 400

def test_login_user():
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

    r = SESSION.post(url, data=payload)

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

    r = requests.delete(url)

    assert r.status_code == 401

def test_delete_user():
    url = URL + '/user/' + TEST_EMAIL

    r = requests.delete(url, headers={'x-api-key': X_API_KEY})

    assert r.status_code == 200
