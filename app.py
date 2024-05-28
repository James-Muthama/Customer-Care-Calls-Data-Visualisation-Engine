from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, session
import pymongo
from passlib.hash import pbkdf2_sha256
import uuid
import pyotp
import smtplib
from email.mime.text import MIMEText

# Create Flask app 'template_folder' specifies the folder where the HTML templates are stored. 'static_folder'
# specifies the folder where static files (CSS, JS, images) are stored.'static_url_path' sets the URL path that
# serves the static files.
app = Flask(__name__, template_folder="templates", static_folder='static', static_url_path='/')

#session secret key
app.secret_key = b'6o\xab\xc4\xf6\x915\x0e\xd6\xe9uP5d\xa6!'

# Database
client = pymongo.MongoClient("localhost", 27017)
db = client.CustomerInsightAI

# Email configuration
EMAIL_ADDRESS = 'jamesmuthaiks@gmail.com'
EMAIL_PASSWORD = 'vzzp rjzo thtm dvhh'


def send_email(to_address, subject, body):
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = EMAIL_ADDRESS
    msg['To'] = to_address

    with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
        server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        server.sendmail(EMAIL_ADDRESS, to_address, msg.as_string())


#Decorators for checking logged in to access homepage
def login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            return redirect('/')

    return wrap


# Route for the home page
@app.route('/')
def home():
    return render_template('index.html')


# Route for the signup page
@app.route('/signup/')
def signup():
    return render_template('signup.html')


# Route for the homepage after successful signup or login
@app.route('/homepage/')
@login_required
def homepage():
    return render_template('homepage.html')


# Route for displaying login page
@app.route('/login')
def login():
    return render_template('login.html')


# Route for handling user login
@app.route('/user/login', methods=['POST'])
def user_login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = db.customer.find_one({"email": email})

        if user and pbkdf2_sha256.verify(password, user['password']):
            # Generate a valid base32 secret key for TOTP
            totp_secret = pyotp.random_base32()

            totp = pyotp.TOTP(totp_secret)
            otp = totp.now()

            session['totp_secret'] = totp_secret
            session['logged_in'] = True
            session['user'] = user['name']

            send_email(email, 'Log In Verification Code', f'Your Verification Code is {otp}')

            return redirect(url_for('two_factor_authentication'))
        else:
            flash('Invalid email or password.', 'error')
            return redirect(url_for('login'))

    return render_template('login.html')


# Route for handling the user signup form submission
@app.route('/user/signup/', methods=['POST'])
def user_signup():
    if request.method == 'POST':
        user = {
            "_id": uuid.uuid4().hex,
            "name": request.form.get('name'),
            "email": request.form.get('email'),
            "password": request.form.get('password')
        }

        # Encrypt the user's password using pbkdf2_sha256 hashing.
        user['password'] = pbkdf2_sha256.hash(user['password'])

        # Check for existing email address
        if db.customer.find_one({"$or": [{"email": user['email']}, {"name": user['name']}]}):
            flash("Information filled is already in use.", "error")
            return redirect(url_for('user_login'))
        else:
            # Insert the new user into the 'customer' collection in the database.
            db.customer.insert_one(user)

            del user['password']
            #creating a session
            session['logged_in'] = True
            session['user'] = user['name']
            return redirect(url_for('homepage'))

    return render_template('signup.html')


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = db.customer.find_one({"email": email})

        if user:
            # Generate a valid base32 secret key for TOTP
            totp_secret = pyotp.random_base32()

            totp = pyotp.TOTP(totp_secret)
            otp = totp.now()
            send_email(user['email'], 'Change Password Verification Code', f'Your Verification Code is {otp}')

            # Store the TOTP secret in session
            session['reset_email'] = email
            session['totp_secret'] = totp_secret

            return redirect(url_for('verify_otp'))
        else:
            flash('Email not found.', 'error')
            return render_template('forgot_pass.html')
    elif request.method == 'GET':
        return render_template('forgot_pass.html')

    return render_template('forgot_pass.html')


@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if 'reset_email' not in session:
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        otp = request.form.get('otp')
        email = session['reset_email']
        totp_secret = session['totp_secret']
        user = db.customer.find_one({"email": email})

        if user:
            totp = pyotp.TOTP(totp_secret)
            if totp.verify(otp):
                return redirect(url_for('change_password'))
            else:
                flash('Invalid OTP.', 'error')

    return render_template('verify_otp.html')


@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'reset_email' not in session:
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        email = session['reset_email']

        if new_password != confirm_password:
            flash('Passwords do not match.', 'error')
        else:
            hashed_password = pbkdf2_sha256.hash(new_password)
            db.customer.update_one({'email': email}, {'$set': {'password': hashed_password}})
            flash('Password reset successful. Please log in with your new password.', 'success')
            session.pop('reset_email', None)
            return redirect(url_for('login'))

    return render_template('change_password.html')


# Checking 2-factor authentication code
@app.route('/verify_2_fa', methods=['GET', 'POST'])
def two_factor_authentication():
    if 'logged_in' not in session:
        return redirect(url_for('user_login'))

    if request.method == 'POST':
        otp = request.form.get('otp')
        totp_secret = session['totp_secret']

        totp = pyotp.TOTP(totp_secret)
        if totp.verify(otp):
            return redirect(url_for('homepage'))
        else:
            flash('Invalid OTP.', 'error')

    return render_template('2_fa.html')


#logging out the user
@app.route('/sign/out')
def sign_out():
    session.clear()
    return redirect('/')


if __name__ == "__main__":
    app.run(debug=True)
