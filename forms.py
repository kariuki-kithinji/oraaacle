from flask_wtf import FlaskForm ,RecaptchaField
from wtforms import (StringField,PasswordField, SubmitField,BooleanField)
from wtforms.validators import DataRequired, Length, Email, EqualTo

class RegistrationForm(FlaskForm):
    email = StringField('Email',validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password',message="passwords must match")])
    recaptcha = RecaptchaField()
    submit = SubmitField('Sign Up')
    

class LoginForm(FlaskForm):
    email = StringField('Email',validators = [DataRequired(),Email()])
    password = PasswordField('Password',validators = [DataRequired()])
    remember = BooleanField(label='Remember Me',default='checked')
    recaptcha = RecaptchaField()
    submit = SubmitField('Login')

class ResetPasswordForm(FlaskForm):
    email = StringField('Email',validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password', message='Passwords must match')])
    recaptcha = RecaptchaField()
    submit = SubmitField('Reset Password')

class ForgotPasswordForm(FlaskForm):
    email = StringField('Email',validators=[DataRequired(), Email()])
    recaptcha = RecaptchaField()
    submit = SubmitField('Send reset email')

class VerifyEmail(FlaskForm):
    email = StringField('Email',validators=[DataRequired(), Email()])
    recaptcha = RecaptchaField()
    submit = SubmitField('Send verification email')