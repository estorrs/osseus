from functools import wraps
import logging
import os

from boto3.dynamodb.conditions import Key, Attr
from flask_bcrypt import Bcrypt
from flask_mail import Mail
from flask_wtf.csrf import CSRFProtect
from itsdangerous import URLSafeTimedSerializer, BadSignature

import boto3
import flask
import flask_login

import email_utils
import user_utils

logging.basicConfig(format='%(asctime)s:%(levelname)s:%(message)s', level=logging.INFO)


#################################
### initialize app and mixins ###
#################################

# can also do this bit in __init__
app = flask.Flask(__name__)

# grab secret key
app.secret_key = os.getenv('FLASK_SECRET_KEY')

## various configuration settings
# no time limit for csrf tokens
app.config.update(dict(
    WTF_CSRF_TIME_LIMIT=None
))

# email stuff
app.config.update(dict(
    MAIL_SERVER='smtp.gmail.com',
    MAIL_PORT=465,
    MAIL_USE_TLS=False,
    MAIL_USE_SSL=True,
    MAIL_USERNAME=os.getenv('MAIL_USERNAME'),
    MAIL_PASSWORD=os.getenv('MAIL_PASSWORD')
))

# enable csrf
csrf = CSRFProtect()
csrf.init_app(app)

# enable login manager
login_manager = flask_login.LoginManager()
login_manager.init_app(app)

# initialize bcrypt
bcrypt = Bcrypt(app)

# initialize url serializer
url_serializer = URLSafeTimedSerializer(app.secret_key)

# initialize mail
mail = Mail(app)

# x-api-key
X_API_KEY = os.getenv('X_API_KEY')


###################################
### AWS environmental variables ###
###################################

AWS_ACCESS_KEY = os.getenv('AWS_ACCESS_KEY')
AWS_SECRET_KEY = os.getenv('AWS_SECRET_KEY')
REGION = os.getenv('AWS_REGION')

BOTO3_SESSION = boto3.session.Session(
        aws_access_key_id=AWS_ACCESS_KEY, aws_secret_access_key=AWS_SECRET_KEY,
        region_name=REGION)
RESOURCE = BOTO3_SESSION.resource('dynamodb')
USER_TABLE = RESOURCE.Table(os.getenv('USER_TABLE'))


#####################
### login manager ###
#####################

@login_manager.user_loader
def user_loader(user_email):
    '''load user from dynamodb'''
    user_dict = user_utils.get_user_from_dynamodb(user_email, USER_TABLE)

    if user_dict is None:
        return None

    user = user_utils.User()
    user.id = user_dict['email']

    user.user_dict = user_dict

    return user

@login_manager.unauthorized_handler
def unauthorized_handler():
    '''handle unautohrized access'''
    return flask.Response('Unauthorized', 401)


##############################
### authorization for apis ###
##############################

def check_auth(x_api_key):
    '''x-api-key'''
    if X_API_KEY == x_api_key:
        return True
    return False

def authorize(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not check_auth(flask.request.headers.get('x-api-key')):
            return flask.Response('invalid x-api-key', 401)
        return f(*args, **kwargs)
    return decorated


##############
### Routes ###
##############

@app.route('/', methods=['GET'])
def home():
    return flask.render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    user = flask_login.current_user
    if user.is_authenticated:
        logging.info('user already detected.  redirecting to super secret')
        return flask.redirect(flask.url_for('super_secret'))

    if flask.request.method == 'GET':
        logging.info('Sending login page')
        return flask.render_template('login.html')

    email = flask.request.form['email']
    password = flask.request.form['password']

    logging.info('login attempt by {}'.format(email))

    user_dict = user_utils.get_user_from_dynamodb(email, USER_TABLE)
    if user_dict is None:
        return flask.Response('invalid email/password', 400)

    is_valid = user_utils.check_password(user_dict['password'], password, bcrypt)
    if is_valid:
        user = user_utils.User()
        user.id = email
        user.user_dict = user_dict
        flask_login.login_user(user)
        return flask.redirect(flask.url_for('super_secret'))

    return flask.Response('invalid email/password', 400)

@app.route('/logout', methods=['GET'])
def logout():
    logging.info('logging out {}'.format(flask_login.current_user.id))
    flask_login.logout_user()

    return flask.redirect(flask.url_for('login'))

@app.route('/user/<token>', methods=['GET', 'POST'])
def confirm_user(token):
    try:
        email = url_serializer.loads(token, max_age=86400)
    except BadSignature:
        return flask.Response('invalid user token', 404)

    user_dict = user_utils.get_user_from_dynamodb(email, USER_TABLE)

    if user_dict is None:
        return flask.Response('invalid token, email not found', 400)

    if flask.request.method == 'GET':
        logging.info('sending confirm user page to {}'.format(email))
        return flask.render_template('confirm_user.html', email=email)

    password = flask.request.form['password']

    logging.info('attempting confirm user {}'.format(email))

    kwargs = {
            'cool_number': 1.11111 # to make sure decoder is working
            }

    pw_hash = bcrypt.generate_password_hash(password).decode('utf-8')
    user_utils.update_user_dynamodb(email, pw_hash, USER_TABLE, **kwargs)

    return flask.Response('user {} added'.format(email), 200)


@app.route('/user', methods=['GET', 'POST'])
def create_user():
    if flask.request.method == 'GET':
        logging.info('create user account setup page sent')
        return flask.render_template('create_user.html')

    email = flask.request.form['email']

    user_dict = user_utils.get_user_from_dynamodb(email, USER_TABLE)
    if user_dict is not None:
        return flask.Response('Account with the email {} already exists :('.format(email), 400)

    user_utils.add_user_dynamodb(email, USER_TABLE)

    serialized = url_serializer.dumps(email)
    url = flask.request.url_root + 'user/' + serialized

    email_utils.send_confirmation_message(email, url, app, mail)

    message = 'A confirmation email has been sent.\n\nPlease open it to create your account'
    return flask.Response(message, 200)


@app.route('/super-secret', methods=['GET'])
@flask_login.login_required
def super_secret():
    logging.info('rendering super secret portal to {}'.format(flask_login.current_user.id))
    return flask.render_template('super_secret.html')


#######################
### delete user api ###
#######################

@app.route('/user/<email>', methods=['DELETE'])
@authorize
@csrf.exempt
def delete_user(email):
    logging.info('deleting {}'.format(email))
    user_utils.delete_user_dynamodb(email, USER_TABLE)

    return flask.Response('user {} deleted'.format(email), 200)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
