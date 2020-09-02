import flask_cognito
from unittest import TestCase
from unittest.mock import Mock


class objectview(object):
    def __init__(self, d):
        self.__dict__ = d

class TestHeaderPrefix(TestCase):

  def test_valid_header_prefix(self):
    flask_cognito._cog = objectview({'jwt_header_name' :'Authorization',
                          'jwt_header_prefix' : 'Bearer'})

    get_mock = Mock(return_value='Bearer Test')
    request_mock = objectview({'headers': objectview({'get': get_mock})})
    
    flask_cognito.request = request_mock


    ca = flask_cognito.CognitoAuth()
    result  = ca.get_token()
    assert (result == 'Test')
    
  def test_incorrect_header_prefix(self):
    flask_cognito._cog = objectview({'jwt_header_name' :'Authorization',
                          'jwt_header_prefix' : 'Bearer'})

    get_mock = Mock(return_value='Something Test')
    request_mock = objectview({'headers': objectview({'get': get_mock})})
    flask_cognito.request = request_mock
    ca = flask_cognito.CognitoAuth()
    self.assertRaises(flask_cognito.CognitoAuthError, ca.get_token)
  
    
  def test_malformed_header(self):
    flask_cognito._cog = objectview({'jwt_header_name' :'Authorization',
                          'jwt_header_prefix' : 'Bearer'})

    get_mock = Mock(return_value='Something To Fail')
    request_mock = objectview({'headers': objectview({'get': get_mock})})
    flask_cognito.request = request_mock
    ca = flask_cognito.CognitoAuth()
    self.assertRaises(flask_cognito.CognitoAuthError, ca.get_token)

  def test_with_prefix_empty_string(self):
    flask_cognito._cog = objectview({'jwt_header_name' :'Authorization',
                          'jwt_header_prefix' : ''})

    get_mock = Mock(return_value='Something')
    request_mock = objectview({'headers': objectview({'get': get_mock})})
    flask_cognito.request = request_mock
    ca = flask_cognito.CognitoAuth()
    result = ca.get_token()
    self.assertEqual('Something',result)
  
  def test_with_prefix_none(self):
    flask_cognito._cog = objectview({'jwt_header_name' :'Authorization',
                          'jwt_header_prefix' : None})

    get_mock = Mock(return_value='Something')
    request_mock = objectview({'headers': objectview({'get': get_mock})})
    flask_cognito.request = request_mock
    ca = flask_cognito.CognitoAuth()
    result = ca.get_token()
    self.assertEqual('Something',result)

  def test_without_prefix_malformed(self):
    flask_cognito._cog = objectview({'jwt_header_name' :'Authorization',
                          'jwt_header_prefix' : None})

    get_mock = Mock(return_value='Something Else')
    request_mock = objectview({'headers': objectview({'get': get_mock})})
    flask_cognito.request = request_mock
    ca = flask_cognito.CognitoAuth()
    self.assertRaises(flask_cognito.CognitoAuthError, ca.get_token)

  def test_without_prefix_missing(self):
    flask_cognito._cog = objectview({'jwt_header_name' :'Authorization',
                          'jwt_header_prefix' : None})

    get_mock = Mock(return_value=None)
    request_mock = objectview({'headers': objectview({'get': get_mock})})
    flask_cognito.request = request_mock
    ca = flask_cognito.CognitoAuth()
    result = ca.get_token()
    self.assertIsNone(result)


    


