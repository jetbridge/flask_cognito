Flask-Cognito
-------------

Authenticate users based on AWS Cognito JWT.


# Initialization
```python3

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

CognitoAuth(app)
```

# Check Authentication
```python3
from flask_cognito import cognito_auth_required, cognito_user

@route('/api/private')
@cognito_auth_required
def api_private():
    # user must have valid cognito auth token in header
    return jsonify({
        'COGNITO_USERNAME': cognito_user['cognito:username'],   # from cognito pool
    })
```


### Acknowledgements
* Uses [cognitojwt](https://github.com/borisrozumnuk/cognitojwt) at its core.
* Based on [flask-jwt](https://github.com/mattupstate/flask-jwt/).
