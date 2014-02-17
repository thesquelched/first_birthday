import party.config as config
from party.guid import GUID
from flask import Flask, render_template, request, redirect, url_for, flash
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.login import (
    LoginManager, login_user, logout_user, UserMixin, current_user,
    login_required)
import uuid
import hashlib
import csv
import random
from itertools import chain

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = config.SQLALCHEMY_DATABASE_URI
app.config['SQLALCHEMY_ECHO'] = config.SQLALCHEMY_ECHO
app.config['SECRET_KEY'] = config.SECRET_KEY

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)


######################################################################
# Models
######################################################################

class Invitation(db.Model):
    guid = db.Column(GUID(), primary_key=True, default=uuid.uuid4)
    name = db.Column(db.String(128))
    email = db.Column(db.String(128))
    viewed = db.Column(db.Boolean(), default=False)
    confirmed = db.Column(db.Boolean(), default=False)

    attend_stl = db.Column(db.Boolean(), default=False)
    attend_cu = db.Column(db.Boolean(), default=False)

    attendees = db.Column(db.Integer(), default=1)


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


@login_manager.unauthorized_handler
def redirect_to_login():
    return redirect(url_for('login'))


######################################################################
# App
######################################################################

@app.route('/')
def index():
    static_imgs = [
        url_for('static', filename=img)
        for img in config.SLIDESHOW_IMAGES_STATIC
    ]
    images = static_imgs + config.SLIDESHOW_IMAGES
    random.shuffle(images)

    return render_template(
        'index.html',
        user=current_user,
        slideshow=images,
        guid=request.args.get('guid', None)
    )


class LoginForm(object):

    def validate(self):
        form = request.form
        if not ('user' in form and 'password' in form):
            return None

        pw_hash = hashlib.sha512()
        pw_hash.update(form['password'].encode())
        pw_hash.update(config.PASSWORD_SALT)

        return User.query.filter_by(
            username=form['user'],
            password=pw_hash.hexdigest()).first()


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

    total_stl, total_cu = 0, 0
    confirmed, unconfirmed = [], []
    for invite in invites:
        if invite.confirmed:
            confirmed.append(invite)
            total_stl += invite.attendees if invite.attend_stl else 0
            total_cu += invite.attendees if invite.attend_cu else 0
        else:
            unconfirmed.append(invite)

    return render_template(
        'admin.html',
        user=current_user,
        confirmed=confirmed,
        unconfirmed=unconfirmed,
        total_stl=total_stl,
        total_cu=total_cu,
        total_attendees=total_stl + total_cu)


@app.route('/admin/action', methods=['POST'])
@login_required
def admin_action():
    guids = request.form.getlist('guid')
    invites = Invitation.query.filter(Invitation.guid.in_(guids)).all()

    if 'email' in request.form:
        if not guids:
            return redirect(url_for('admin'))

        return render_template(
            'email.html',
            invites=invites,
            user=current_user,
            content=config.EMAIL_CONTENT_DEFAULT)
    elif 'create' in request.form:
        return render_template(
            'create.html',
            user=current_user)
    elif 'delete' in request.form:
        return delete_invitations(invites)
    elif 'import' in request.form:
        return render_template(
            'import.html',
            user=current_user)

    return redirect(url_for('admin'))


def delete_invitations(invites):
    try:
        for invite in invites:
            db.session.delete(invite)
        db.session.commit()
    except Exception as ex:
        app.logger.error('Unable to delete invitations: {}'.format(ex))
        db.session.rollback()
        flash('Unable to delete invitations', 'danger')
        return redirect(url_for('admin'))

    flash(
        'Sucessfully deleted {} invitations'.format(len(invites)),
        'success'
    )
    return redirect(url_for('admin'))


@app.route('/admin/create', methods=['POST'])
@login_required
def create_invitation():
    if not ('email' in request.form and 'name' in request.form):
        flash('Invalid invitation', 'danger')
        return render_template('email.html', user=current_user)

    invite = Invitation(
        email=request.form['email'],
        name=request.form['name']
    )

    db.session.add(invite)
    db.session.commit()

    flash(
        'Successfully added invitation for {}'.format(request.form['name']),
        'success'
    )

    return redirect(url_for('admin'))


def valid_invite(info):
    return (
        'Name' in info
    )


@app.route('/admin/import', methods=['POST'])
@login_required
def admin_import():
    if 'file' not in request.files:
        return redirect(url_for('admin'))

    csv_file = request.files['file']

    try:
        lines = csv_file.read().decode('UTF-8').strip().split('\n')
        reader = csv.DictReader(lines)
        data = [row for row in reader if valid_invite(row)]

        for row in data:
            invite = Invitation(
                name=row['Name'],
                email=row['Email Addresses'],
                attendees=int(row.get('Count', 1))
            )
            db.session.add(invite)

        db.session.commit()
        flash(
            'Successfully loaded {} invitations'.format(len(data)),
            'success'
        )
    except Exception as ex:
        db.session.rollback()

        flash('Could not load CSV file', 'danger')
        app.logger.error('Could not load CSV: {}'.format(ex))

    return redirect(url_for('admin'))


@app.route('/admin/email', methods=['POST'])
@login_required
def admin_email():
    guids = request.form.getlist('guid')
    invites = Invitation.query.filter(Invitation.guid.in_(guids)).all()

    subject = request.form['subject']
    content_template = request.form['content']
    emailer_cls = config.EMAIL_CLASS

    if not subject:
        flash('Invalid Subject', 'danger')
        return render_template(
            'email.html',
            invites=invites,
            user=current_user,
            content=content_template)

    with emailer_cls(config.EMAIL_SENDER, logger=app.logger) as emailer:
        for invite in invites:
            for email in invite.email.split(','):
                url = config.URL_BASE + url_for('index', guid=invite.guid)
                content = content_template.format(
                    name=invite.name,
                    invitation_url=url
                )

                emailer.send(email, subject, content)

    emails = list(chain.from_iterable(
        invite.email.split(',') for invite in invites))
    flash('Successfully sent {} emails'.format(len(emails)), 'success')
    return redirect(url_for('admin'))


def valid_confirmation(form):
    app.logger.debug('Form: {}'.format(form))
    return 'guid' in form and 'stl' in form and 'cu' in form


def confirmation_error():
    flash(
        'Unable to confirm invitation.  Please contact Scott or Lindsay.',
        'danger'
    )
    return redirect(url_for('index'))


@app.route('/confirm', methods=['POST'])
def confirm():
    if not valid_confirmation(request.form):
        return confirmation_error()

    inv = Invitation.query.get(uuid.UUID(request.form['guid']))
    if inv is None:
        return confirmation_error()

    inv.attend_stl = request.form['stl'].lower() == 'yes'
    inv.attend_cu = request.form['cu'].lower() == 'yes'
    inv.attendees = int(request.form['attendees'])
    inv.confirmed = True

    try:
        db.session.add(inv)
        db.session.commit()
    except:
        db.session.rollback()
        return confirmation_error()

    flash('Successfully confirmed your invitation.  Thanks!', 'success')
    return redirect(url_for('index'))


@app.route('/invite/<guid>')
def invite(guid):
    guid = guid.strip()
    app.logger.info('GUID: {}'.format(guid))

    app.logger.debug(Invitation.query.all())

    inv = Invitation.query.get(uuid.UUID(guid))
    if not current_user.is_authenticated() and not inv.viewed:
        inv.viewed = True
        db.session.commit()

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
