from flask_wtf import FlaskForm ,RecaptchaField
from wtforms import (StringField,PasswordField, SubmitField,BooleanField)
from wtforms.validators import DataRequired, Length, Email, EqualTo

class RegistrationForm(FlaskForm):
    email = StringField('Email',validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password',message="passwords must match")])
    submit = SubmitField('Sign Up')
    

class LoginForm(FlaskForm):
    email = StringField('Email',validators = [DataRequired(),Email()])
    password = PasswordField('Password',validators = [DataRequired()])
    remember = BooleanField(label='Remember Me',default='checked')
    submit = SubmitField('Login')

class ResetPasswordForm(FlaskForm):
    email = StringField('Email',validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password', message='Passwords must match')])
    submit = SubmitField('Reset Password')

class ForgotPasswordForm(FlaskForm):
    email = StringField('Email',validators=[DataRequired(), Email()])
    submit = SubmitField('Send reset email')

class VerifyEmail(FlaskForm):
    email = StringField('Email',validators=[DataRequired(), Email()])
    submit = SubmitField('Send verification email')