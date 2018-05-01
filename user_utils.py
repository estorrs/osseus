import decimal
import json

from boto3.dynamodb.conditions import Key, Attr
import flask_login

from dynamodb_utils import DynamodbEncoder


def get_user_from_dynamodb(user_email, table):
    if user_email is None:
        return None

    response = table.get_item(
            Key={
                'email': user_email
            }
        )

    user_info = response.get('Item', None)

    if user_info is None:
        return None

    encoded_user_info = json.dumps(user_info, cls=DynamodbEncoder)

    return json.loads(encoded_user_info)

def add_user_dynamodb(email, pw_hash, table, **kwargs):
    '''add user to dynamo db table'''
    payload = {
            'email': email,
            'password': pw_hash,
            }.update(kwargs)

    # there's probably a more efficient way to do this
    payload = json.dumps(payload)
    payload = json.loads(payload, parse_float=decimal.Decimal)

    response = table.put_item(
            Item=payload
            )


def check_password(password_hash, password_to_check, bcrypt):
    '''check password hash for user against user given password'''
    if password_hash is None or password_to_check is None:
        return False

    return bcrypt.check_password_hash(password_hash, password_to_check)


class User(flask_login.UserMixin):
    def __init__(self):
        flask_login.UserMixin.__init__(self)
        # additional attributes here
        self.user_dict = {}
