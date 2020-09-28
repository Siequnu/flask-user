from flask import render_template, redirect, url_for, session, flash, request, abort, current_app
import datetime

from flask_login import current_user, login_user, login_required, logout_user
from werkzeug.urls import url_parse

from app.models import User, Turma
from app import db

import app.email_model

import app.main.forms
from app.user import bp, models, forms

from datetime import datetime

from app import executor

from time import sleep

# Log-in page
@bp.route('/login', methods=['GET', 'POST'])
def login():
	if current_user.is_authenticated:
		return redirect(url_for('main.index'))
	form = app.user.forms.LoginForm()
	if form.validate_on_submit():
		user = User.query.filter_by(username=form.username.data).first()
		if user is None or not user.check_password(form.password.data):
			flash('Invalid username or password', 'error')
			return redirect(url_for('user.login'))
		# Check for email validation
		if User.user_email_is_confirmed(user.username) == False:
			flash('Please click the confirmation link in the email that was sent to you.', 'warning')
			return redirect(url_for('user.login'))		
		login_user(user, remember=form.remember_me.data)
		next_page = request.args.get('next')
		if not next_page or url_parse(next_page).netloc != '':
			next_page = url_for('main.index')
		return redirect(next_page)
	return render_template('user/login.html', title='Sign In', form=form)



# Log-out page
@bp.route('/logout')
def logout():
	logout_user()
	return redirect(url_for('main.index'))

############## User registration, log-in/out, and management

# Log-in help page
@bp.route('/troubleshooting')
def troubleshooting():
	return render_template('user/troubleshooting.html', title='Having problems logging in?')

# Display a user profile
@bp.route('/profile/<user_id>')
def user_profile(user_id):
	try:
		user = User.query.get(int(user_id))
	except:
		abort (404)
	
	# Is user an admin (do not show student profiles)
	if user is not None and app.models.is_admin(user.username):
		# Display their profile
		return render_template('user/user_profile.html', title='User profile', user = user)
	else:
		abort (404)

# Edit a user profile
@bp.route('/profile/edit', methods=['GET', 'POST'])
def profile_edit ():
	if current_user.is_authenticated and app.models.is_admin(current_user.username):
		user = User.query.get(current_user.id)
		form = app.user.forms.EditUserProfileForm(obj=user)
		if form.validate_on_submit():
			user.profile_name = form.profile_name.data
			user.profile_title = form.profile_title.data
			user.profile_education = form.profile_education.data
			user.profile_qualification = form.profile_qualification.data
			user.profile_text = form.profile_text.data
			
			db.session.commit()
			flash('User profile edited successfully.', 'success')
			return redirect(url_for('user.user_profile', user_id = user.id))
		return render_template('user/profile_edit.html', title='Edit user profile', form=form)
	else:
		abort (403)
	
# Edit a user profile
@bp.route('/profile/photo/edit', methods=['GET', 'POST'])
def photo_edit ():
	if current_user.is_authenticated and app.models.is_admin(current_user.username):
		user = User.query.get(current_user.id)
		form = app.user.forms.EditUserProfilePicture(obj=user)
		if form.validate_on_submit():
			app.user.models.new_profile_picture_upload_from_form (form, user)
			flash('User profile edited successfully.', 'success')
			return redirect(url_for('user.user_profile', user_id = user.id))
		return render_template('user/profile_edit.html', title='Edit user profile', form=form)
	else:
		abort (403)

# Registration
@bp.route('/register', methods=['GET', 'POST'])
@bp.route('/register/<int:turma_id>', methods=['GET', 'POST'])
def register(turma_id = False):
	# If the user is authenticated, and not an admin (admin can use this form to register a student), redirect to index
	if current_user.is_authenticated and app.models.is_admin(current_user.username) is not True:
		return redirect(url_for('main.index'))

	# If we are passing in a target class number, exit if this class does not exist
	if turma_id:
		turma = Turma.query.get (turma_id)
		if turma is None:
			flash ('Could not find this class. Please ask your tutor to help you with your registration', 'warning')
			return redirect(url_for('main.index'))
	
	# If registration is open or we are an admin, create a new form
	if current_app.config['REGISTRATION_IS_OPEN'] == True or current_user.is_authenticated and app.models.is_admin(current_user.username):
		form = app.user.forms.RegistrationForm()
		
		# If we are an admin (i.e., creating an account for the student) remove the form.password and sign up code fields
		if current_user.is_authenticated and app.models.is_admin(current_user.username):
			del form.password
			del form.signUpCode
			
		# Get the possible class choices
		if turma_id:
			form.target_turmas.choices = [(turma.id, turma.turma_label)]
		else:
			if current_user.is_authenticated:
				if current_user.is_superintendant:
					form.target_turmas.choices = [(turma.id, turma.turma_label) for turma in Turma.query.all()]
				else:
					form.target_turmas.choices = [(turma.id, turma.turma_label) for turma in app.classes.models.get_teacher_classes_from_teacher_id (current_user.id)]
			else:
				form.target_turmas.choices = [(turma.id, turma.turma_label) for turma in Turma.query.all()]
		
		# On submission
		if form.validate_on_submit():
			# If the sign up code is correct, or we are admin
			if form.signUpCode and form.signUpCode.data in current_app.config['SIGNUP_CODES'] or current_user.is_authenticated and app.models.is_admin(current_user.username):
				
				# Create a new user
				user = User(username=form.username.data, email=form.email.data, student_number=form.student_number.data, registered = datetime.now())
				
				# If we are not an admin, set the user's password (this field does not exist in the admin form)
				if current_user.is_authenticated is not True:
					user.set_password(form.password.data)

				# Add the user and flush					
				db.session.add(user)
				db.session.flush() # Access the new user.id field in the next step
				
				# Enroll the student in the classes
				for turma_id in form.target_turmas.data:
					app.assignments.models.enroll_user_in_class(user.id, turma_id)
				db.session.commit()
				
				# Build an email with a sign-up completion link
				subject = current_app.config['APP_NAME'] + " - your account is almost ready"
				token = app.email_model.ts.dumps(str(form.email.data), salt=current_app.config["TS_SALT"])
				
				# If we are an admin, send essentially a password reset email, but with a welcome message
				if current_user.is_authenticated and app.models.is_admin(current_user.username):
					# Send the email confirmation link, with link to set a password
					recover_url = url_for('user.reset_with_token', token=token, _external=True)
					html = render_template('email/set_password.html', recover_url=recover_url, username = form.username.data, app_name = current_app.config['APP_NAME'])
					flash('An email has been sent to the new user with further instructions.', 'success')
				
				# Otherwise, send a normal email confirmation link
				else:
					# Send the email confirmation link
					confirm_url = url_for('user.confirm_email', token=token, _external=True)
					html = render_template('email/activate.html',confirm_url=confirm_url, username = form.username.data, app_name = current_app.config['APP_NAME'])
					flash('An email has been sent to you with further instructions.', 'success')
				
				# Send email in background
				executor.submit(app.email_model.send_email, user.email, subject, html)
				return redirect(url_for('user.login'))
			else:
				flash('Please ask your tutor for sign-up instructions.', 'warning')
				return redirect(url_for('user.login'))
		return render_template('user/register.html', title='Register', form=form)
	else:
		flash('Sign up is currently closed.', 'warning')
		return redirect(url_for('main.index'))

# Send new confirmation email to all unconfirmed users (bulk)
@bp.route('/confirmation/bulk')
def send_new_confirmation_email_to_all_unconfirmed_users():
	if current_user.is_authenticated and app.models.is_admin(current_user.username):
		unconfirmed_users = User.query.filter_by(email_confirmed=False).all()
		for user in unconfirmed_users:
			send_new_confirmation_email(user.id)
			sleep(1)
		flash ('Sent a new confirmation email to ' + str(len(unconfirmed_users)) + ' users.')
		return redirect(url_for('user.manage_students'))
	abort (403)

# Send new confirmation email
@bp.route('/confirmation/<user_id>')
def send_new_confirmation_email(user_id):
	if current_user.is_authenticated and app.models.is_admin(current_user.username):
		user = User.query.filter_by(id=user_id).first_or_404()
		subject = current_app.config['APP_NAME'] + " - please confirm your email address"
		token = app.email_model.ts.dumps(str(user.email), salt=current_app.config["TS_SALT"])
		confirm_url = url_for('user.confirm_email', token=token, _external=True)
		
		html = render_template('email/activate.html',confirm_url=confirm_url, username = user.username, app_name = current_app.config['APP_NAME'])
		executor.submit(app.email_model.send_email, user.email, subject, html)
		flash('A new confirmation email has been sent to ' + user.username + ' with further instructions.', 'success')
		return redirect(url_for('user.manage_students'))
	abort(403)

# Confirm email
@bp.route('/confirm/<token>')
def confirm_email(token):
	try:
		email = app.email_model.ts.loads(token, salt=current_app.config["TS_SALT"], max_age=86400)
	except:
		abort(404)
	user = User.query.filter_by(email=email).first_or_404()
	user.email_confirmed = True
	db.session.commit()
	flash('Your email has been confirmed. Please log-in now.', 'success')
	return redirect(url_for('user.login'))

# Reset password form
@bp.route('/reset', methods=["GET", "POST"])
def reset():
	form = app.user.forms.EmailForm()
	if form.validate_on_submit():
		user = User.query.filter_by(email=form.email.data).first_or_404()
		subject = "Password reset requested"
		token = app.email_model.ts.dumps(user.email, salt=current_app.config["TS_RECOVER_SALT"])

		recover_url = url_for('user.reset_with_token', token=token, _external=True)
		html = render_template('email/recover.html', recover_url=recover_url, username = user.username, app_name = current_app.config['APP_NAME'])
		
		executor.submit(app.email_model.send_email, user.email, subject, html)
		flash('An email has been sent to your inbox with a link to recover your password.', 'info')
		return redirect(url_for('main.index'))
		
	return render_template('user/reset.html', form=form)

# Reset password with token
# This also confirms the email address
@bp.route('/reset/<token>', methods=["GET", "POST"])
def reset_with_token(token):
	try:
		email = app.email_model.ts.loads(token, salt=current_app.config['TS_RECOVER_SALT'], max_age=current_app.config['TS_MAX_AGE'])
	except:
		abort(404)
	form = app.user.forms.PasswordForm()
	if form.validate_on_submit():
		user = User.query.filter_by(email=email).first_or_404()
		user.email_confirmed = True
		user.set_password(form.password.data)
		db.session.commit()
		flash('Your password has been changed. You can now log-in with your new password.', 'success')
		return redirect(url_for('user.login'))
	return render_template('user/reset_with_token.html', form=form, token=token)


@bp.route('/edit/<user_id>', methods=['GET', 'POST'])
def edit_user(user_id):
	if current_user.is_authenticated and app.models.is_admin(current_user.username):
		user = User.query.get(user_id)

		# If not superintendant, can only edit own students
		if current_user.is_superintendant is not True: # Account for both Null and False
			
			# Any "normal" teacher can not edit other teachers, or superintendants
			if user.is_superintendant is True or user.is_admin is True:
				flash ("You can not edit other teacher profiles. Please contact an administrator to change other teacher details.", 'warning')
				return redirect (url_for ('main.index'))
			
			# As the user to be edited is not teacher or superintendant, check if they are enrolled in this teacher's class
			if app.classes.models.check_if_student_is_in_teachers_class(user.id, current_user.id) is False:
				abort (403)

		form = app.user.forms.EditUserForm(obj=user)
		form.target_turmas.choices = [(turma.id, turma.turma_label) for turma in Turma.query.all()]
		if form.validate_on_submit():
			user.username = form.username.data
			user.email = form.email.data
			user.student_number = form.student_number.data
			app.assignments.models.reset_user_enrollment(user.id)
			for turma_id in form.target_turmas.data:
				app.assignments.models.enroll_user_in_class(user.id, turma_id)
			
			db.session.commit()
			flash('User edited successfully.', 'success')
			return redirect(url_for('user.manage_students'))
		return render_template('user/register.html', title='Edit user', form=form)
	abort (403)
	
@bp.route('/delete/<user_id>', methods=['GET', 'POST'])
def delete_user(user_id):
	if current_user.is_authenticated and app.models.is_admin(current_user.username):
		user = User.query.get(user_id)

		# If not superintendant, can only edit own students
		if current_user.is_superintendant is not True: # Account for both Null and False
			
			# Any "normal" teacher can not edit other teachers, or superintendants
			if user.is_superintendant is True or user.is_admin is True:
				flash ("You can not edit other teacher profiles. Please contact an administrator to change other teacher details.", 'warning')
				return redirect (url_for ('main.index'))
			
			# As the user to be edited is not teacher or superintendant, check if they are enrolled in this teacher's class
			if app.classes.models.check_if_student_is_in_teachers_class(user.id, current_user.id) is False:
				abort (403)


		form = app.user.forms.ConfirmationForm()
		confirmation_message = 'Are you sure you want to delete ' + user.username + "'s account?"
		if form.validate_on_submit():
			
			app.collaboration.models.delete_all_user_pads_and_collabs (user_id)
			
			app.classes.models.delete_all_user_absence_justification_uploads(user_id)
			app.classes.models.delete_all_user_attendance_records(user_id)
			
			app.grammar.models.delete_all_grammar_check_records_from_user_id(user_id)			
			
			app.assignments.models.delete_all_comments_from_user_id (user_id)
			app.assignments.models.delete_all_grades_from_user_id (user_id)
			
			app.files.models.delete_uploads_enrollments_and_download_records_for_user(user_id)
			
			app.models.User.delete_user(user_id)
			
			flash('User deleted successfully.', 'success')
			return redirect(url_for('user.manage_students'))

		return render_template('confirmation_form.html',
							   title='Delete user',
							   confirmation_message = confirmation_message,
							   form=form)
	abort (403)

# Manage Users
@bp.route('/students/manage')
@login_required
def manage_students():
	if current_user.is_authenticated and app.models.is_admin(current_user.username):
		student_info = app.user.models.get_all_student_info()
		non_enrolled_users = app.user.models.get_non_enrolled_user_info ()
		return render_template('user/manage_students.html',
							   title='Manage students',
							   student_info = student_info,
							   non_enrolled_users = non_enrolled_users,
							   sign_up_code = current_app.config['SIGNUP_CODES'],
							   registration_is_open = current_app.config['REGISTRATION_IS_OPEN'])
	abort(403)
	
# Toggle registration status
@bp.route('/registration/toggle')
@login_required
def toggle_registration_status():
	if current_user.is_authenticated and app.models.is_admin(current_user.username):
		current_app.config.update(
			REGISTRATION_IS_OPEN = not current_app.config['REGISTRATION_IS_OPEN']
		)
		flash ('Registration status changed successfully')
		return redirect(url_for('user.manage_students'))
	
	abort(403)
	
	
# Change registration code
@bp.route('/registration/code', methods=['GET', 'POST'])
@login_required
def change_registration_code():
	if current_user.is_authenticated and app.models.is_admin(current_user.username):
		form = forms.RegistrationCodeChangeForm()
		if form.validate_on_submit():
			current_app.config.update(
				SIGNUP_CODES = [form.registration_code.data]
			)
			flash ('Sign up code changed successfully to ' + form.registration_code.data)
			return redirect(url_for('user.manage_students'))
		return render_template('user/change_registration_code.html', title='Change registration code', form=form)
	abort(403)
	
# Manage Users
@bp.route('/teachers/manage')
@login_required
def manage_teachers():
	if current_user.is_authenticated and current_user.is_superintendant:
		teacher_info = app.user.models.get_all_admin_info()
		return render_template('user/manage_teachers.html', title='Manage teachers', teacher_info = teacher_info)
	abort(403)
	


# Convert a teacher into a student of one of their classes
@bp.route('/view/<class_id>')
@login_required
def view_as_member_of_class(class_id):
	if current_user.is_authenticated and app.models.is_admin(current_user.username):
		try:
			# Additional security to check if the teacher owns this class? 
			teacher_manages_this_class = False
			if current_user.is_superintendant is True:
				teacher_manages_this_class = True
			else:
				for turma in app.classes.models.get_teacher_classes_from_teacher_id (current_user.id):
					if int(turma.id) == int(class_id):
						teacher_manages_this_class = True

			if teacher_manages_this_class is False:
				abort (403)

			# Make the database changes
			app.models.User.remove_admin_rights(current_user.id)
			flash('Student view enabled.', 'success')

			user = User.query.get(current_user.id)
			user.set_can_return_to_admin (True)

			# "Enroll" the teacher in the class
			app.assignments.models.enroll_user_in_class(user.id, class_id)

		except Exception as e:
			print (e)
			flash('An error occured while emabling student view.', 'error')
		return redirect(url_for('main.index'))
	else:
		abort(403)


# Convert a teacher into a student of one of their classes
@bp.route('/view/admin')
@login_required
def view_as_admin():
	if current_user.is_authenticated and current_user.can_return_to_admin is True:
		try:
			app.models.User.give_admin_rights(current_user.id)

			app.classes.models.remove_all_enrollment_from_user (current_user.id)

			user = User.query.get(current_user.id)
			user.set_can_return_to_admin (False)
			
			flash('Teacher view enabled.', 'success')
		except:
			flash('An error occured while enabling teacher view.', 'error')
		return redirect(url_for('main.index'))
	else:
		abort(403)


# Convert normal user into admin
@bp.route('/give_admin_rights/<user_id>')
@login_required
def give_admin_rights(user_id):
	if current_user.is_authenticated and app.models.is_admin(current_user.username):
		try:
			# Make DB call to convert user into admin
			app.models.User.give_admin_rights(user_id)
			flash('User successfully made into administrator.', 'success')
		except:
			flash('An error occured when changing the user to an administrator.', 'error')
		return redirect(url_for('user.manage_students'))
	else:
		abort(403)
		
# Remove admin rights from user
@bp.route('/remove_admin_rights/<user_id>')
@login_required
def remove_admin_rights(user_id):
	if current_user.is_authenticated and app.models.is_admin(current_user.username):
		try:	
			app.models.User.remove_admin_rights(user_id)
			flash('Administrator rights removed from the user.', 'success')
		except:
			flash('An error occured when changing the user to an administrator.', 'error')
		return redirect(url_for('user.manage_students'))
	else:
		abort(403)


# Convert normal user into admin
@bp.route('/superintendant/add/<user_id>')
@login_required
def make_superintendant(user_id):
	if current_user.is_authenticated and current_user.is_superintendant:
		try:
			user = User.query.get (user_id)
			if user is None:
				flash('Could not find the user you requested.', 'error')
				return redirect(url_for('user.manage_teachers'))

			# Make DB call to convert user into admin
			app.models.User.give_superintendant_rights(user_id)
			flash(user.username + ' successfully made into superintendant.', 'success')
		except:
			flash('An error occured when changing ' + user.username + ' to a superintendant.', 'error')
		return redirect(url_for('user.manage_teachers'))
	else:
		abort(403)
		
# Remove admin rights from user
@bp.route('/superintendant/remove/<user_id>')
@login_required
def strip_of_superintendant(user_id):
	if current_user.is_authenticated and current_user.is_superintendant:
		try:	
			app.models.User.remove_superintendant_rights(user_id)
			flash('Superintendant rights removed from the user.', 'success')
		except:
			flash('An error occured when removing superintendant roles from the user.', 'error')
		return redirect(url_for('user.manage_teachers'))
	else:
		abort(403)


# Admin can register a new user
@bp.route('/register/admin', methods=['GET', 'POST'])
@login_required
def register_admin():
	if current_user.is_authenticated and current_user.is_superintendant:
		form = forms.AdminRegistrationForm()
		
		if current_user.is_superintendant:
			form.target_turmas.choices = [(turma.id, turma.turma_label) for turma in Turma.query.all()]
		else:
			form.target_turmas.choices = [(turma.id, turma.turma_label) for turma in app.classes.models.get_teacher_classes_from_teacher_id (current_user.id)]
		
		if current_user.is_superintendant is not True: del form.is_superintendant

		if form.validate_on_submit():
			if current_user.is_superintendant is not True: 
				is_superintendant = False
			else:
				is_superintendant = form.is_superintendant.data
			
			user = User(
				username=form.username.data, 
				email=form.email.data, 
				is_admin = True, 
				registered=datetime.now(),
				is_superintendant=is_superintendant
			)
			db.session.add(user)
			db.session.commit()

			# Register the teacher as being part of whatever classes were selected
			for turma_id in form.target_turmas.data:
				app.classes.models.add_teacher_to_class (user.id, turma_id)
			
			# Send the email confirmation link, with link to set a password
			subject = current_app.config['APP_NAME'] + " - your account is almost ready"
			token = app.email_model.ts.dumps(str(form.email.data), salt=current_app.config["TS_SALT"])
			recover_url = url_for('user.reset_with_token', token=token, _external=True)
			html = render_template('email/set_password.html', recover_url=recover_url, username = form.username.data, app_name = current_app.config['APP_NAME'])		
			executor.submit(app.email_model.send_email, user.email, subject, html)
			
			flash('An email has been sent to the new user with further instructions.', 'success')
			return redirect(url_for('user.login'))
		return render_template('user/register_admin.html', title='Register Admin', form=form)
	else:
		abort(403)

# Admin page to batch import and create users from an xls file
@bp.route("/import", methods=['GET', 'POST'])
@login_required
def batch_import_students():
	if current_user.is_authenticated and app.models.is_admin(current_user.username):
		form = forms.BatchStudentImportForm()
		if current_user.is_superintendant:
			form.target_turmas.choices = [(turma.id, turma.turma_label) for turma in Turma.query.all()]
		else:
			form.target_turmas.choices = [(turma.id, turma.turma_label) for turma in app.classes.models.get_teacher_classes_from_teacher_id (current_user.id)]
		if form.validate_on_submit():
			if not form.excel_file.data.filename:
				flash('No file uploaded.', 'warning')
				return redirect(request.url)
			file = form.excel_file.data
			if file and models.check_if_excel_spreadsheet(file.filename):
				session['student_info_array'] = models.process_student_excel_spreadsheet (file)
				session['target_turma_ids'] = form.target_turmas.data
				return redirect(url_for('user.batch_import_students_preview', turma_id = form.target_turmas.data))
			else:
				flash('You can not upload this kind of file. You must upload an Excel (.xls or .xlsx) file.', 'warning')
				return redirect(url_for('user.batch_import_students'))
		return render_template('user/batch_import_students.html', title='Batch import students', form=form)
	abort(403)

# Admin page to preview batch import
@bp.route("/import/preview")
@login_required
def batch_import_students_preview():
	if current_user.is_authenticated and app.models.is_admin(current_user.username):
		return render_template(
			'user/batch_import_students_preview.html', 
			target_turma_ids = session.get('target_turma_ids', {}), 
			student_info_array = session.get('student_info_array', {}), 
			title='Batch import students preview')
	abort(403)

# Admin page to display after the import process
@bp.route("/import/process")
@login_required
def batch_import_students_process():
	if current_user.is_authenticated and app.models.is_admin(current_user.username):
		student_info_array = session.get('student_info_array', {})
		target_turma_ids = session.get('target_turma_ids', {}), 
		if student_info_array == {} or target_turma_ids == {}:
			flash ('Could not locate the necessary student information','error')
			return redirect(url_for('user.batch_import_students'))
		
		models.add_users_from_excel_spreadsheet(student_info_array, target_turma_ids)
		flash ('Successfully added ' + str(len(student_info_array)) + ' students.', 'success')
		return redirect (url_for ('user.manage_students'))
	abort(403)
