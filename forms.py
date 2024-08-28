from flask_wtf import   FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired , Length

class ProfileForm(FlaskForm):
    username = StringField('Username', render_kw={"readonly": True})
    employee_id = StringField('Employee ID', render_kw={"readonly": True})
    new_password = PasswordField('New Password', validators=[Length(min=6)])
    submit = SubmitField('Update Profile')