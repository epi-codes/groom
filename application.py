#!/usr/bin/env python3
import click as cl
import flask as fk
import socket
import uuid
import utilities as util

# Application Setup
app, rates, db, User, Attempt = util.prepare_app(__name__)

@app.cli.command('init', help="Initialize the application's structures")
def groom_init():
	print('Creating tables in database...')
	db.create_all()

@app.cli.command('promote', help='Promote an user, giving them more permissions')
@cl.argument('user')
def groom_promote(user):
	print(f'Promoting {user}...')
	u = User.query.filter_by(user=user).first()
	if u is None:
		u = User(user, 1)
		db.session.add(u)
		db.session.commit()
	else:
		u.level += 1
		db.session.commit()

@app.cli.command('demote', help='Demote an user, withdrawing permissions from them')
@cl.argument('user')
def groom_demote(user):
	print(f'Demoting {user}...')
	u = User.query.filter_by(user=user).first()
	if u is None:
		u = User(user, -1)
		db.session.add(u)
		db.session.commit()
	else:
		u.level -= 1
		db.session.commit()

@app.route('/')
def groom_index():
	return fk.render_template('index.html', **util.get_user_dict(app))

@app.route('/log')
@app.route('/log/<int:page>')
def groom_log(page=1):
	user = util.get_user_dict(app)
	if user['level'] < 1 or not user['mail']:
		fk.abort(403)

	return fk.render_template('log.html', page=page, **user)

@app.route('/api/auth/login')
def groom_api_login():
	if 'access_token' in fk.session:
		fk.abort(403)
		# return util.json(403, 'Already logged in')

	state = fk.session['state'] = str(uuid.uuid4())
	callback = app.config['MSAPI_REDIRECT_URL']
	return fk.g.msapi.authorize(callback=callback, state=state)

@app.route('/api/auth/logout')
def groom_api_logout():
	if 'access_token' not in fk.session:
		fk.abort(401)
		# return util.json(401, 'Not logged in')

	del fk.session['access_token']
	return fk.redirect('/')

@app.route('/api/auth/authorized')
def groom_api_authorized():
	if fk.session['state'] != str(fk.request.args['state']):
		fk.abort(401)
		# return util.json(401, 'Invalid state')

	response = fk.g.msapi.authorized_response()
	fk.session['access_token'] = response['access_token']
	return fk.redirect('/')

@app.route('/api/door', methods=['POST'])
@rates.limit('2/minute', error_message=util.log_ratelimit)
def groom_api_open():
	level, mail, _ = util.get_user(app)

	if level < 0 or not mail:
		util.log_attempt(app, mail, 'unauthorized')
		return util.json(403 if mail else 401, 'Not authorized')

	try:
		print('Contacting the groom service...')
		with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
			sock.connect((app.config['GROOM_HOST'], app.config['GROOM_PORT']))
			sock.sendall(b'UNLOCK\n')
			if sock.recv(12) == b'UNLOCK START':
				util.log_attempt(app, mail, 'granted')
				return util.json(200, 'Door opened')
			else:
				raise ValueError('Protocol Error')
	except Exception:
		util.log_attempt(app, mail, 'protocol-error')
		return util.json(500, 'Protocol error while interacting with groom')

	return util.json(200, 'Door opened')

@app.route('/api/log')
@app.route('/api/log/<int:page>')
def groom_api_log(page=1):
	level, _, _ = util.get_user(app)
	if level < 1:
		return util.json(403, 'Not authorized')

	attempts = Attempt.query.order_by(Attempt.time.desc()).paginate(page, 10)
	keys = Attempt.__table__.columns.keys()
	m = map(lambda a: {k: getattr(a, k) for k in keys}, attempts.items)
	response = fk.json.jsonify(
		ok=True, attempts=list(m),
		prev=attempts.has_prev, next=attempts.has_next
	)

	return response
