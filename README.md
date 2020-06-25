Flask-Cognito
-------------

Authenticate users based on AWS Cognito JWT.


# Initialization
```python3
# configuration
app.config.extend({
    'COGNITO_REGION': 'eu-central-1',
    'COGNITO_USERPOOL_ID': 'eu-central-1c3fea2',

    # optional
    'COGNITO_APP_CLIENT_ID': 'abcdef123456',  # client ID you wish to verify user is authenticated against
    'COGNITO_CHECK_TOKEN_EXPIRATION': False,  # disable token expiration checking for testing purposes
    'COGNITO_JWT_HEADER_NAME': 'X-MyApp-Authorization',
    'COGNITO_JWT_HEADER_PREFIX': 'Bearer',
})


# initialize extension
from flask_cognito import CognitoAuth
cogauth = CognitoAuth(app)

@cogauth.identity_handler
def lookup_cognito_user(payload):
    """Look up user in our database from Cognito JWT payload."""
    return User.query.filter(User.cognito_username == payload['username']).one_or_none()
```

# Check Authentication
```python3
from flask_cognito import cognito_auth_required, current_user, current_cognito_jwt

@route('/api/private')
@cognito_auth_required
def api_private():
    # user must have valid cognito access or ID token in header
    # (accessToken is recommended - not as much personal information contained inside as with idToken)
    return jsonify({
        'cognito_username': current_cognito_jwt['username'],   # from cognito pool
        'user_id': current_user.id,   # from your database
    })
```

# Restrict access by Cognito Group
```python3
from flask_cognito import cognito_auth_required, current_user, current_cognito_jwt

@route('/api/foo')
@cognito_auth_required
@cognito_group_permissions(['admin','developer'])
def api_private():
    # user must belongs to "admin" or "developer" groups
    return jsonify({
        'foo': "bar"
    })
```

### Acknowledgements
* Uses [cognitojwt](https://github.com/borisrozumnuk/cognitojwt) at its core.
* Based on [flask-jwt](https://github.com/mattupstate/flask-jwt/).
