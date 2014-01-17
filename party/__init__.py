from party.guid import GUID
from flask import Flask, render_template, request, redirect, url_for
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.login import (
    LoginManager, login_user, logout_user, UserMixin, current_user,
    login_required)
import uuid

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/test.db'
app.config['SQLALCHEMY_ECHO'] = True
app.config['SECRET_KEY'] = '1tj2oengiknjr5uj23pogqsvgnjwru1wjp'

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)


######################################################################
# Models
######################################################################

class Invitation(db.Model):
    guid = db.Column(GUID(), primary_key=True, default=uuid.uuid4)
    name = db.Column(db.String(128), unique=True)
    email = db.Column(db.String(128))

    attend_stl = db.Column(db.Boolean(), default=False)
    attend_cu = db.Column(db.Boolean(), default=False)


class User(db.Model, UserMixin):
    id = db.Column(db.Integer(), primary_key=True)

    username = db.Column(db.String(32), unique=True)

    # Obviously stupid to store in plaintext
    password = db.Column(db.String(128))


######################################################################
# Login
######################################################################

@login_manager.user_loader
def load_user(userid):
    return User.query.get(userid)


######################################################################
# App
######################################################################

@app.route('/')
def index():
    return render_template('index.html', user=current_user)


class LoginForm(object):

    def validate(self):
        form = request.form
        if not ('user' in form and 'password' in form):
            return None

        return User.query.filter_by(
            username=form['user'],
            password=form['password']).first()


@app.route('/login', methods=['GET', 'POST'])
def login():
    app.logger.info('Attempting to log in')

    if request.method != 'POST':
        return render_template('login.html', user=current_user)

    form = LoginForm()
    user = form.validate()

    if user:
        app.logger.info('Logged in as {}'.format(user.username))
        login_user(user)
        return redirect(url_for('index'))
    else:
        app.logger.error('Could not log in')

    return render_template('login.html', user=current_user)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/admin')
@login_required
def admin():
    invites = Invitation.query.all()
    return render_template('admin.html', user=current_user, invites=invites)


def valid_confirmation(form):
    return 'guid' in form and 'stl' in form and 'cu' in form


@app.route('/confirm', methods=['GET', 'POST'])
def confirm():
    if request.method != 'POST':
        return redirect(url_for('index'))

    if not valid_confirmation(request.form):
        return render_template(
            'confirm.html', success=False, user=current_user)

    inv = Invitation.query.get(uuid.UUID(request.form['guid']))
    if inv is None:
        return render_template(
            'confirm.html', success=False, user=current_user)

    inv.attend_stl = request.form['stl'].lower() == 'yes'
    inv.attend_cu = request.form['cu'].lower() == 'yes'

    try:
        db.session.add(inv)
        db.session.commit()
        success = True
    except:
        db.session.rollback()
        success = False

    return render_template('confirm.html', success=success, user=current_user)


@app.route('/invite/<guid>')
def invite(guid):
    guid = guid.strip()
    app.logger.info('GUID: {}'.format(guid))

    app.logger.debug(Invitation.query.all())

    inv = Invitation.query.get(uuid.UUID(guid))
    if inv is None:
        app.logger.error('No invitation found')
    else:
        app.logger.info("User is '{}'".format(inv.name))

    return render_template('invite.html', invitation=inv, user=current_user)


######################################################################
# Initialize application and db
######################################################################

def initialize():
    db.create_all()
