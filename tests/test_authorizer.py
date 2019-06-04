from basicauthserve.authorizer import check_basicauth_header_authorization_handler

import pytest


def test_check_basicauth_header_authorization_handler():
    auth = 'Basic bGl2ZXBhc3M6c3VuZGF5c2FyZWZ1bmRheXM='
    event = {
        'methodArn': "arn:partition:service:region:account-id:resourcetype/resource:qualifier",
        'headers': {
            'Authorization': auth,
        }
    }
    context = {}
    try:
        response = check_basicauth_header_authorization_handler(event, context)
    except Exception as e:
        pytest.fail(f'Exception: {e.args}')

    assert response
