Flask-Cognito
-------------

Authenticate users based on AWS Cognito JWT.


# Initialization
```python3

# configuration
app.config.extend({
    'COGNITO_REGION': 'eu-central-1',
    'COGNITO_USERPOOL_ID': 'eu-central-1c3fea2',
    'COGNITO_APP_CLIENT_ID': 'abcdef123456',  # client ID you wish to verify user is authenticated against

    # optional
    'COGNITO_JWT_HEADER_NAME': 'X-MyApp-Authentication',
    'COGNITO_CHECK_TOKEN_EXPIRATION': False,  # disable token expiration checking for testing purposes
    'COGNITO_JWT_HEADER_NAME': 'Authorization',
    'COGNITO_JWT_HEADER_PREFIX': 'JWT',
})


# initialize extension
cogauth = CognitoAuth(app)

@cogauth.identity_handler
def lookup_cognito_user(payload):
    """Look up user in our database from Cognito JWT payload."""
    return User.query.filter(User.cognito_username == payload['cognito:username']).one_or_none()
```

# Check Authentication
```python3
from flask_cognito import cognito_auth_required, current_user, current_cognito_jwt

@route('/api/private')
@cognito_auth_required
def api_private():
    # user must have valid cognito auth token in header
    return jsonify({
        'cognito_username': current_cognito_jwt['cognito:username'],   # from cognito pool
        'user_id': current_user.id,   # from your database
    })
```


### Acknowledgements
* Uses [cognitojwt](https://github.com/borisrozumnuk/cognitojwt) at its core.
* Based on [flask-jwt](https://github.com/mattupstate/flask-jwt/).
