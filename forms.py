from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, SelectField, DateField, RadioField, FormField, TextAreaField, SelectMultipleField
from wtforms.validators import ValidationError, DataRequired, Email, EqualTo, Optional, Length
from flask_wtf.file import FileField, FileRequired
from app.models import User, Turma


class LoginForm(FlaskForm):
	username = StringField('Username', validators=[DataRequired()])
	password = PasswordField('Password', validators=[DataRequired()])
	remember_me = BooleanField('Remember me')
	submit = SubmitField('Sign In')

class EditUserForm (FlaskForm):
	username = StringField('Username', validators=[DataRequired()])
	email = StringField('Email', validators=[DataRequired()])
	student_number = StringField('Student number', validators=[DataRequired()])
	target_turmas = SelectMultipleField('For classes', coerce=int, validators=[DataRequired()])
	submit = SubmitField('Edit user')
	
class ConfirmationForm (FlaskForm):
	submit = SubmitField('Confirm')

class RegistrationForm(FlaskForm):
	username = StringField('Username', validators=[DataRequired()])
	email = StringField('Email', validators=[DataRequired(), Email()])
	password = PasswordField('Password', validators=[DataRequired()])
	student_number = StringField('Student number', validators=[DataRequired()])
	target_turmas = SelectMultipleField('For classes', coerce=int, validators=[DataRequired()])
	signUpCode = StringField('Sign-up code', validators=[DataRequired()])
	submit = SubmitField('Register')

	def validate_username(self, username):
		user = User.query.filter_by(username=username.data).first()
		if user is not None:
			raise ValidationError('Please use a different username.')

	def validate_email(self, email):
		user = User.query.filter_by(email=email.data).first()
		if user is not None:
			raise ValidationError('Please use a different email address.')
		
	def validate_student_number(self, student_number):
		user = User.query.filter_by(student_number=student_number.data).first()
		if user is not None:
			raise ValidationError('This student number is already in use. Please ask your tutor for help.')
				
class EmailForm(FlaskForm):
	email = StringField('Email', validators=[DataRequired(), Email()])
	submit = SubmitField('Request password reset')

class PasswordForm(FlaskForm):
	password = PasswordField('Password', validators=[DataRequired()])
	submit = SubmitField('Reset password')
	
class RegistrationCodeChangeForm(FlaskForm):
	registration_code = StringField('New registration code:', validators=[DataRequired()])
	submit = SubmitField('Change code')	
		
class BatchStudentImportForm(FlaskForm):
	target_turmas = SelectMultipleField('For classes', coerce=int, validators=[DataRequired()])
	excel_file = FileField(validators=[FileRequired()], label='Excel File')
	submit = SubmitField('Process...')
	
class AdminRegistrationForm(FlaskForm):
	is_superintendant = BooleanField('Superintendant user', default=False)
	username = StringField('Username:', validators=[DataRequired()])
	email = StringField('Email:', validators=[DataRequired(), Email()])
	target_turmas = SelectMultipleField('For classes:', coerce=int)
	submit = SubmitField('Register')

	def validate_username(self, username):
		user = User.query.filter_by(username=username.data).first()
		if user is not None:
			raise ValidationError('Please use a different username.')

	def validate_email(self, email):
		user = User.query.filter_by(email=email.data).first()
		if user is not None:
			raise ValidationError('Please use a different email address.')
		
class EditUserProfileForm (FlaskForm):
	profile_name = StringField('Your full name:', validators=[Optional(), Length(max = 200)])
	profile_title = StringField('Profile Title:', validators=[Optional(), Length(max = 200)])
	profile_education = StringField('Profile education:', validators=[Optional(), Length(max = 200)])
	profile_qualification = StringField('Profile qualification:', validators=[Optional(), Length(max = 200)])
	profile_text = StringField('Profile text:', validators=[Optional(), Length(max = 2000)])
	submit = SubmitField('Update your profile')
	
class EditUserProfilePicture(FlaskForm):
	profile_picture = FileField(label='Your profile picture:', validators=[DataRequired()])
	submit = SubmitField('Upload this picture')