"""
utils/forms.py
-----------------
Flask-WTF form definitions. Using WTForms gives us automatic CSRF
protection and server-side validation for every form in the app.
"""

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError, URL


class RegistrationForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(min=3, max=80)])
    email = StringField("Email", validators=[DataRequired(), Email(), Length(max=120)])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=8, max=128)])
    confirm_password = PasswordField(
        "Confirm Password", validators=[DataRequired(), EqualTo("password", message="Passwords must match.")]
    )
    submit = SubmitField("Create Account")

    def validate_username(self, field):
        if not field.data.replace("_", "").replace("-", "").isalnum():
            raise ValidationError("Username may only contain letters, numbers, hyphens, and underscores.")


class LoginForm(FlaskForm):
    username = StringField("Username or Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    remember_me = BooleanField("Remember Me")
    submit = SubmitField("Sign In")


class PasswordChangeForm(FlaskForm):
    current_password = PasswordField("Current password", validators=[DataRequired()])
    new_password = PasswordField(
        "New password", validators=[DataRequired(), Length(min=8, max=128)]
    )
    confirm_password = PasswordField(
        "Confirm new password",
        validators=[DataRequired(), EqualTo("new_password", message="Passwords must match.")],
    )
    submit = SubmitField("Update password")


class PasswordCheckForm(FlaskForm):
    password = PasswordField("Password to Analyze", validators=[DataRequired(), Length(max=256)])
    submit = SubmitField("Analyze Password")


class URLCheckForm(FlaskForm):
    url = StringField("URL to Analyze", validators=[DataRequired(), Length(max=2048)])
    submit = SubmitField("Analyze URL")


class SettingsForm(FlaskForm):
    theme = StringField("Theme")
    submit = SubmitField("Save Settings")
