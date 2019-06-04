
from basicauthserve.app import app


def test_index():
    app.config['TESTING'] = True
    client = app.test_client()

    response = client.get('index.html')
    assert response.status_code == 401

    auth = 'Basic bGl2ZXBhc3M6c3VuZGF5c2FyZWZ1bmRheXM='
    response = client.get('index.html', headers={'Authorization': auth})
    assert response
    assert response.status_code == 200
