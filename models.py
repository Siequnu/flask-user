from app import db
import app.models, app.email_model
import app.files.models
from app.models import Upload, Download, Assignment, User, Comment, Enrollment, Turma
from flask_login import current_user
import string, time, xlrd
from flask import url_for, render_template, redirect, session, flash, request, abort, current_app
from datetime import datetime, timedelta
from time import sleep
from sqlalchemy import func

from app import executor

def new_profile_picture_upload_from_form (form, user):
	file = form.profile_picture.data
	filename = app.files.models.save_file(file)
	user.profile_picture = filename
	db.session.commit()
	# Generate thumbnail
	executor.submit(app.files.models.get_thumbnail, user.profile_picture)

def get_total_user_count ():
	# Remove admins?
	return len(User.query.all())

def get_all_student_info ():
	return db.session.query(User, func.group_concat(
		Turma.turma_label, ", ")).join(
		Enrollment, User.id == Enrollment.user_id).join(
		Turma, Enrollment.turma_id == Turma.id).group_by(
		User.student_number).all()

def get_active_user_count ():
	now = datetime.now()
	active_cutoff = now - timedelta(minutes=1)
	return User.query.filter(User.last_seen > active_cutoff).count()
	
def get_non_enrolled_user_info():
	enrolled_student_info = get_all_student_info ()
	enrolled_students_dict = []
	for user, enrollment in enrolled_student_info:
		enrolled_students_dict.append(user)
		
	all_user_info = User.query.all()
	all_user_dict = []
	for user in all_user_info:
		all_user_dict.append (user)

	# Subtract enrolled_students from all_users
	non_enrolled_users = {user for user in all_user_dict if user not in enrolled_students_dict}
	
	return non_enrolled_users

def get_all_admin_info():
	return User.query.filter(User.is_admin==True).all()
	

def process_student_excel_spreadsheet (excel_data_file):
	# Open the workbook
	wb = xlrd.open_workbook(file_contents=excel_data_file.read())
	sheet = wb.sheet_by_index(0) 
	sheet.cell_value(0, 0) 

	# Get number of rows
	number_of_rows = sheet.nrows
	number_of_emails = number_of_rows - 1

	# Iterate through the file
	i = 1 # Start counter at 1 to skip header row
	student_data = []
	while i < number_of_rows:
		# Go to row
		row = sheet.row_values(i)
		
		# Get details
		student = {
			'name': str(row[0]),
			# Student number gets read as a float (123123123.0) so remove the trailing .0
			'number': str(row[1]).replace('.0', ''),
			'email': str (row[2])
		}
		
		student_data.append (student)

		# Increment counter
		i = i + 1
	
	return student_data
	

def add_users_from_excel_spreadsheet (student_info_array, target_turma_ids):
	for student in student_info_array:
		user = User(
			username=student['name'], 
			email=student['email'], 
			student_number=student['number'], 
			registered = datetime.now())
		
		db.session.add(user)
		db.session.flush() # Access the new user.id field in the next step

		# Enroll the student in the classes
		for turma_id in target_turma_ids:
			app.assignments.models.enroll_user_in_class(user.id, turma_id)
		db.session.commit()

		# Build an email with a sign-up completion link
		subject = current_app.config['APP_NAME'] + " - your account is almost ready"
		token = app.email_model.ts.dumps(str(user.email), salt=current_app.config["TS_SALT"])
				
		# Send the email confirmation link, with link to set a password
		recover_url = url_for('user.reset_with_token', token=token, _external=True)
		html = render_template('email/set_password.html', recover_url=recover_url, username = user.username, app_name = current_app.config['APP_NAME'])

		# Send email in background
		executor.submit(app.email_model.send_email, user.email, subject, html)

		# Prevent overloading the email sender
		sleep (1)

	return
		
# Returns a boolean True if a file is .xls or .xlsx
def check_if_excel_spreadsheet (filename):
	 return '.' in filename and filename.rsplit('.', 1)[1].lower() in ['xls'] or '.' in filename and filename.rsplit('.', 1)[1].lower() in ['xlsx']
	
############ Password generator
def roll_dice (number_of_dice = 5):
	while True:
		dice_roll = ''
		
		# Roll the dice x number_of_times
		for d in range(number_of_dice):
			dice_roll = dice_roll + str(random.choice(list(range(6))))
			
		# Check the combination connects to a word in the list
		word = add_to_word_list (dice_roll)
		if word != False:
			return word

def add_to_word_list (dice_roll):
	searchfile = open("eff_large_wordlist.txt", "r")
	
	for line in searchfile:
		if dice_roll in line:
			word = line[6:]
			searchfile.close()
			return word
	searchfile.close()
	return False

def generate_word_password (number_of_words = 4):
	password = ''
	
	for i in range(number_of_words):
		password = password + roll_dice ()
		
	generated_password = "-".join(password.splitlines())
	return generated_password
			
##########################
