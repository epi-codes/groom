#!/usr/bin/env python3
import flask as fk
from functools import partial
import time

# Flask Plugins
from flask_limiter import Limiter
from flask_oauthlib.client import OAuth
from flask_sqlalchemy import SQLAlchemy

def prepare_app(name):
	app = fk.Flask(name)
	app.config.from_pyfile('config.py', silent=True)

	# Check for required configuration variables
	required = [
		'SECRET_KEY',
		'MSAPI_CONSUMER_KEY',
		'MSAPI_CONSUMER_SECRET',
		'MSAPI_REDIRECT_URL',
	]

	absent = list(filter(lambda v: v not in app.config, required))
	if len(absent) > 0:
		absent = ', '.join(absent)
		raise LookupError(f'The following variables are needed to proceed: {absent}')

	# Set defaults for optional variables
	optional = {
		'MSAPI_ORIGIN_URL': 'https://graph.microsoft.com/v1.0/',
		'MSAPI_TOKEN_URL': 'https://login.microsoftonline.com/common/oauth2/v2.0/token',
		'MSAPI_AUTHORIZE_URL': 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
		'GROOM_HOST': 'localhost',
		'GROOM_PORT': 4221,
	}

	for key, value in optional.items():
		app.config.setdefault(key, value)

	# Configure plugins
	limiter = Limiter(app, key_func=partial(get_limit_key, app))
	db = SQLAlchemy(app)
	class Attempt(db.Model):
		__tablename__ = 'attempt'

		id     = db.Column(db.Integer, primary_key=True)
		user   = db.Column(db.Text)
		time   = db.Column(db.Integer)
		# XXX: Maybe we should use an enum instead.
		result = db.Column(db.Text)

		def __init__(self, user, result):
			self.user, self.result = user or 'unknown', result
			self.time = time.time()

	class User(db.Model):
		__tablename__ = 'user'

		id    = db.Column(db.Integer, primary_key=True)
		user  = db.Column(db.Text, unique=True)
		# XXX: Maybe we should use an enum instead.
		level = db.Column(db.Integer)
		# Levels:
		# -1 : Disabled
		#  0 : Can open the door
		#  1 : Can view logs
		#  2 : Can ban/unban users from the service if level < theirs
		#  3 : Can promote/demote users

		def __init__(self, user, level):
			self.user, self.level = user, level

	msapi = OAuth(app).remote_app(
		'msapi',
		consumer_key=app.config['MSAPI_CONSUMER_KEY'],
		consumer_secret=app.config['MSAPI_CONSUMER_SECRET'],
		request_token_params={'scope': ['User.Read']},
		base_url=app.config['MSAPI_ORIGIN_URL'],
		access_token_method='POST',
		access_token_url=app.config['MSAPI_TOKEN_URL'],
		request_token_url=None,
		authorize_url=app.config['MSAPI_AUTHORIZE_URL']
	)

	@app.before_request
	def groom_export():
		fk.g.db = db
		fk.g.Attempt = Attempt
		fk.g.User = User
		fk.g.msapi = msapi

	@msapi.tokengetter
	def msapi_get_token():
		return fk.session.get('access_token'), ''

	return app, limiter, db, User, Attempt

def get_limit_key(app):
	_, _, ident = get_user(app)
	if ident is None:
		return json(401, 'Not logged in')
	return ident

def _is_user_allowed(app, org):
	return org['id'] == app.config.get('MSAPI_ORGANIZATION', org['id'])

def get_user(app):
	"""
	Get the current user's clearance level, mail address and Azure ID
	"""
	_is_allowed = partial(_is_user_allowed, app)
	try:
		organizations = fk.g.msapi.get('organization').data['value']
		allowed = any(map(_is_allowed, organizations))

		user = fk.g.msapi.get('me').data
		mail = user['mail']
		ident = user['id']

		if allowed:
			u = fk.g.User.query.filter_by(user=mail).first()
			level = 0 if u is None else u.level
		else:
			level = -1
	except Exception:
		if 'access_token' in fk.session:
			del fk.session['access_token']
		level, allowed, mail, ident = -1, False, None, None

	return level, mail, ident

def get_user_dict(app):
	"""
	Get the current user's clearance level, mail address and Azure ID as a dict
	"""
	return dict(zip(('level', 'mail', 'id'), get_user(app)))

def log_attempt(app, mail, result):
	"""
	Log an attempt to open the door in the database, along with what happened of it.
	"""
	attempt = fk.g.Attempt(mail, result)
	fk.g.db.session.add(attempt)
	fk.g.db.session.commit()

def log_ratelimit():
	_, mail, _ = get_user(app)
	log_attempt(app, mail, 'ratelimit-hit')
	return 'Chill out! Spend a few minutes outside. Take a deep breath.'


def json(code, message):
	"""
	Prepare a JSON response for API use, with the provided `code` and `message`.
	"""
	response = {'ok': code == 200, 'code': code}
	if message is not None:
		response['error' if code != 200 else 'message'] = message

	response = fk.json.jsonify(response)
	response.status_code = code
	return response
