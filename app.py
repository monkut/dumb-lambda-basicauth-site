import os
import sys
import logging
from pathlib import Path

from flask import Flask, send_from_directory

logging.basicConfig(
    stream=sys.stdout,
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] (%(name)s) %(funcName)s: %(message)s'
)
logger = logging.getLogger(__name__)


STAGE = os.getenv('STAGE', '')

app = Flask(__name__)

app.config['BASICAUTH_USERNAME'] = os.getenv('BASICAUTH_USERNAME', None)
app.config['BASICAUTH_PASSWORD'] = os.getenv('BASICAUTH_PASSWORD', None)
app.config['SITE_DIRECTORY_RELPATH'] = Path(__file__).parent / 'site'
app.config['JSONIFY_PRETTYPRINT_REGULAR'] = True
logger.warning(app.config['BASICAUTH_USERNAME'])
logger.warning(app.config['BASICAUTH_PASSWORD'])
app.config['BASIC_AUTH_FORCE'] = True
if not app.config['BASICAUTH_PASSWORD'] or not app.config['BASICAUTH_USERNAME']:
    raise ValueError(f'Required environment variable not set: BASICAUTH_PASSWORD or BASICAUTH_USERNAME')


@app.route('/<path:path>')
def serve_ui(path):
    """Serve collection html in defined SITE_DIRECTORY_RELPATH"""
    logger.info(f'SITE_DIRECTORY_RELPATH: {app.config["SITE_DIRECTORY_RELPATH"]}')
    return send_from_directory(app.config['SITE_DIRECTORY_RELPATH'], path)
