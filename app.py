import logging
import os

from boto3.dynamodb.conditions import Key, Attr
from flask_wtf.csrf import CSRFProtect
from flask_bcrypt import Bcrypt
from itsdangerous import URLSafeSerializer, BadSignature

import boto3
import flask
import flask_login

import user_utils

logging.basicConfig(format='%(asctime)s:%(levelname)s:%(message)s', level=logging.INFO)


#################################
### initialize app and mixins ###
#################################

# can also do this bit in __init__
app = flask.Flask(__name__)

# grab secret key
app.secret_key = os.getenv('FLASK_SECRET_KEY')

# enable csrf
csrf = CSRFProtect()
csrf.init_app(app)

# enable login manager
login_manager = flask_login.LoginManager()
login_manager.init_app(app)

# initialize bcrypt
bcrypt = Bcrypt(app)

# initialize url serializer
url_serializer = URLSafeSerializer(app.secret_key)


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


##############
### Routes ###
##############

@app.route('/', methods=['GET'])
def home():
    flask.render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    user = flask_login.current_user
    if user.is_authenticated:
        return flask.redirect(flask.url_for('super_secret'))

    if flask.request.method == 'GET':
        return flask.render_template('login.html')

    email = flask.request.form['email']
    password = flask.request.form['password']

    user_dict = user_utils.get_user_from_dynamodb(email, USER_TABLE)
    if user_dict is None:
        return flask.Response('invalid email/password', 401)

    is_valid = user_utils.check_password(user_dict['password'], password, bcrypt)
    if is_valid:
        user = user_utils.User()
        user.id = email
        user.user_dict = user_dict
        flask_login.login_user(user)
        return flask.redirect(flask.url_for('super_secret'))

    return flask.Response('invalid email/password', 401)

@app.route('/super-secret', methods=['GET'])
@flask_login.login_required
def super_secret():
    flask.render_template('super_secret.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
