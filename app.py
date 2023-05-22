from backend.forms import RegistrationForm , LoginForm ,ForgotPasswordForm ,ResetPasswordForm ,VerifyEmail
from flask import Flask, render_template, url_for, flash, redirect, request ,make_response
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user 
from flask_dance.contrib.google import make_google_blueprint, google
from flask_dance.contrib.github import make_github_blueprint, github

from datetime import datetime, timedelta

from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from flask_avatars import Avatars
from flask_bcrypt import Bcrypt

from functools import wraps

import hashlib
import secrets
import os

from dotenv import load_dotenv
load_dotenv()

app = Flask(__name__)

app.config['SECRET_KEY'] = secrets.token_hex(32)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI')
app.config['RECAPTCHA_PUBLIC_KEY'] = os.getenv('RECAPTCHA_PUBLIC_KEY')
app.config['RECAPTCHA_PRIVATE_KEY'] = os.getenv('RECAPTCHA_PRIVATE_KEY')
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True


blueprint_google = make_google_blueprint(
    client_id=os.getenv('GOOGLE_CLIENT_ID'),
    client_secret=os.getenv('GOOGLE_CLIENT_SECRET'),
    #scope=["profile", "email"]
    scope=["openid",'https://www.googleapis.com/auth/userinfo.email', 'https://www.googleapis.com/auth/userinfo.profile']

)
blueprint_github = make_github_blueprint(
    client_id=os.getenv('GITHUB_CLIENT_ID'),
    client_secret=os.getenv('GITHUB_CLIENT_SECRET'),
)

app.register_blueprint(blueprint_google, url_prefix="/login")
app.register_blueprint(blueprint_github, url_prefix="/login")

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
mail = Mail(app)
avatars = Avatars(app)

login_manager = LoginManager(app)

login_manager.login_view = 'login'
login_manager.session_protection = 'strong'
login_manager.login_message_category = 'info'

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    reset_token = db.Column(db.String(32), unique=True, default=None)
    reset_token_expiration = db.Column(db.DateTime, default=None)
    verify_token = db.Column(db.String(32), unique=True, default=None)
    verify_token_expiration = db.Column(db.DateTime, default=None)
    verified = db.Column(db.Boolean(),default=False,nullable=False)
    icon = db.Column(db.String(120), nullable=False)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash('You must create an account to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.before_first_request
def create_tables():
    db.create_all()

@app.context_processor
def inject_template_scope():
    injections = dict()
        
    def cookies_check():
        value = request.cookies.get('cookie_consent')
        return value == 'true'

    injections.update(cookies_check=cookies_check)
    
    return injections

@app.route('/',methods=['GET', 'POST'])
def index():
    form_login = LoginForm()
    form_register = RegistrationForm()

    if google.authorized:
        
        resp = google.get("/user")#
        
        if not resp.ok:
            flash("could not get user info from server","warning")
        print("GOOGLE AUTHED")#You are @{login} on GOOGLE".format(login=resp.json()["login"]))
    elif not google.authorized:
        print("GOOGLE NOT AUTHED")

    return render_template('index.html',title="Home",form_login=form_login,form_register=form_register)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if form.validate_on_submit():
        
        user = User(
                email=form.email.data, 
                password=bcrypt.generate_password_hash(form.password.data).decode('utf-8'), 
                icon=avatars.gravatar(hashlib.md5(form.email.data.lower().encode('utf-8')).hexdigest())
            )

        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('login'))

    return render_template('index.html',title="Register",form_register=form,form_login=LoginForm())

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():

        email = form.email.data
        password = form.password.data
        remember = form.remember.data

        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):        
            resp = make_response(redirect(url_for('index')))            
            if remember == True:
                login_user(user,remember=True)
            else:
                login_user(user)
            return resp
        if not user:
            flash('Login unsuccessful. Account not found', 'danger')
        else:
            flash('Login unsuccessful. Please check email or password', 'danger')
    
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    return render_template('index.html' , title="Login" ,form_login=form,form_register=RegistrationForm())

@app.route('/logout')
def logout(): 
    logout_user()
    return redirect(url_for('index'))

@app.route('/verify/<email>', methods=['GET', 'POST'])
@login_required
def verify(email):
    form = VerifyEmail()
    user = User.query.filter_by(email=email).first()

    if not user:
        flash(f'No Account assiociated with the {email} address was found.', 'warning')
        return redirect(url_for('index'))

    if user and user.verified:
        flash('Account has already been verified.', 'warning')
        return redirect(url_for('index'))

    if user and not user.verified and form.validate_on_submit():

        user.verify_token=secrets.token_hex(16)
        user.verify_token_expiration = datetime.utcnow() + timedelta(hours=1)
        db.session.commit()

        verify_url = url_for('verify_account', token=user.verify_token, _external=True)

        text_body = f'Click the link below to verify your account:\n\n{verify_url}'
        html_body = render_template('verify_account_email.html', verify_url=verify_url)

        message = Message('Verify account', recipients=[user.email], sender="help@oraaacle.com")
        message.body = text_body
        message.html = html_body
        mail.send(message)

        flash('An Email with the verification link has been sent.', 'success')

    return render_template("verify_email.html",form=form,addr=user.email,form_login=LoginForm(),form_register=RegistrationForm())

@app.route('/verify-account/<token>', methods=['GET', 'POST'])
def verify_account(token):
    user = User.query.filter_by(verify_token=token).first()

    if not user:
        flash('This Link has expired.', 'warning')
        return redirect(url_for('login'))

    if user:
        if datetime.utcnow() > user.verify_token_expiration:
            flash('This Link has expired.', 'warning')
            return redirect(url_for('login'))

        user.verified = True
        db.session.commit()
        user.verify_token = None
        db.session.commit()

        flash('Your Account has been verified.', 'success')

        if current_user.is_authenticated:
            return redirect(url_for('index'))

    return redirect(url_for("login"))


@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user = User.query.filter_by(reset_token=token).first()#_or_404()

    if not user:
        flash('This Link is invalid.', 'warning')
        return redirect(url_for('login'))
    elif user:
        if datetime.utcnow() > user.reset_token_expiration:
            flash('This Link has expired.', 'warning')
            return redirect(url_for('login'))

    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        db.session.commit()
        user.reset_token = None
        db.session.commit()
        user.reset_token_expiration = None
        db.session.commit()

        flash('Your password has been reset.', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html', form=form, addr=user.email,token=token ,form_login=LoginForm(),form_register=RegistrationForm())


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    form = ForgotPasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            reset_token = secrets.token_hex(16)
            user.reset_token = reset_token
            user.reset_token_expiration = datetime.utcnow() + timedelta(hours=1)
            db.session.commit()

            reset_url = url_for('reset_password', token=reset_token, _external=True)
            text_body = f'Click the link below to reset your password:\n\n{reset_url}'
            html_body = render_template('reset_password_email.html', reset_url=reset_url)

            message = Message('Reset Your Password', recipients=[user.email], sender="help@oraaacle.com")
            message.body = text_body
            message.html = html_body
            mail.send(message)

            flash('An email has been sent with instructions to reset your password , the link expires in an Hour', 'info')
            return redirect(url_for('login'))
        else:
            flash('The email address you entered is not associated with an account.', 'danger')
    return render_template('forgot_password.html', form=form,form_login=LoginForm(),form_register=RegistrationForm())


if __name__ == "__main__":
    app.run(debug=True)