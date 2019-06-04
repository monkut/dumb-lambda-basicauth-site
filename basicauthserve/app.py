import os
import sys
import logging
from pathlib import Path

from flask import Flask, send_from_directory
from flask_basicauth import BasicAuth

logging.basicConfig(
    stream=sys.stdout,
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] (%(name)s) %(funcName)s: %(message)s'
)
logger = logging.getLogger(__name__)


STAGE = os.getenv('STAGE', '')

app = Flask(__name__)

app.config['BASIC_AUTH_USERNAME'] = os.getenv('BASIC_AUTH_USERNAME', None)
app.config['BASIC_AUTH_PASSWORD'] = os.getenv('BASIC_AUTH_PASSWORD', None)
app.config['SITE_DIRECTORY_RELPATH'] = Path(__file__).parent.parent / 'site'
app.config['JSONIFY_PRETTYPRINT_REGULAR'] = True
logger.warning(app.config['BASIC_AUTH_USERNAME'])
logger.warning(app.config['BASIC_AUTH_PASSWORD'])
app.config['BASIC_AUTH_FORCE'] = True
if not app.config['BASIC_AUTH_PASSWORD'] or not app.config['BASIC_AUTH_USERNAME']:
    raise ValueError(f'Required environment variable not set: BASIC_AUTH_PASSWORD or BASIC_AUTH_USERNAME')
basic_auth = BasicAuth(app)


@app.route('/<path:path>')
@basic_auth.required
def serve(path):
    """Serve collection html in defined SITE_DIRECTORY_RELPATH"""
    logger.info(f'SITE_DIRECTORY_RELPATH: {app.config["SITE_DIRECTORY_RELPATH"]}')
    return send_from_directory(app.config['SITE_DIRECTORY_RELPATH'], path)
