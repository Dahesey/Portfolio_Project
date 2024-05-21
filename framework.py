import sys
import os


# Add the root directory of your project to the Python path
ROOT_DIR = os.path.dirname(os.path.abspath("/Portfolio_Project"))
sys.path.append(ROOT_DIR)

from flask import Blueprint, Flask, render_template, session, redirect, url_for, request, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, logout_user, login_required, current_user
from flask_login.login_manager import LoginManager
from flask_mail import Message
from models import user
from dotenv import load_dotenv
from Blueprint.auth_blueprint import auth_views
from Blueprint.main_blueprint import main_views
from db.database import get_db
import re, random


load_dotenv('.env')


user_auth = Blueprint('user_auth', __name__)


app = Flask(__name__)

app.register_blueprint(main_views) # type: ignore

login = LoginManager(auth_views)
login.login_view = "/login"

db = get_db()
collection = db["potters_queue"]
collection.User({})
print(collection)

@login.user_loader
def load_user(id):
    """Confirming user exists in database then use, else return none"""
    current_user = user.find.one({ "id": ObjectId(id) }) # type: ignore

    if current_user is None:
        return None

    return User(current_user.get("username"), str(current_user.get("id"))) # type: ignore

@app.route("/", methods=["GET", "POST"])
@app.route("/home", methods=["GET", "POST"])
def home():
    return render_template('homepage.html')

@user_auth.route('/login', methods=['GET', 'POST'])
def login():
    try:
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']
            remember = request.form.get('remember', False)

            user = User.query.filter_by(username=username).first()
            
            if not username or not password:
                flash('Enter a valid username and password', 'warning')
                return redirect(url_for('user_auth.login'))

            if user and not check_password_hash(user.password, password):
                flash("Invalid username or password", 'danger')
                return redirect(url_for('user_auth.login'))

            elif not user:    
                flash("Enter a valid username or password", 'danger')
                return redirect(url_for('user_auth.login'))

            else:
                if user.email_confirm == True:

                    login_user(user, remember=remember)
                    user = current_user
                    flash("Login successful, welcome back", 'success')
                    return redirect(url_for('main.home'))
                
                flash("Your account is not Verified", 'warning')
                    
        return render_template('login.html')
    
    except Exception as e:
        error = "{}".format(str(e))
        print(error)
        
        return render_template('login.html')
    
    @user_auth.route('sign_up', methods=['GET', 'POST'])
    def sign_up():
            try:
                if request.method == 'POST':
                    username = request.form['username']
                    email = request.form['email']
                    password = request.form['password']
                    confirm_password = request.form['confirm password']
                    user = User.query.filter_by(email=email).first()
                    
                    if not username or not email or not password:
                        flash('Kindly fill all fields!', 'danger')
                        return redirect(url_for('user_auth.sign_up'))
                    
                    if username.isupper() or email.isupper():
                        flash('Email and Username must be lowercase!', 'danger')
                        return redirect(url_for('user_auth.sign_up'))
                    
                    if user:
                        flash('username or email taken', 'danger')
                        return redirect(url_for('user_auth.sign_up'))
                    if password:
                        if password != confirm_password:
                            flash('Passwords do not match', 'danger')
                            return redirect(url_for('user_auth.sign_up'))
                        
                        minimum_length = 8
                        
                        if len(password) < minimum_length:
                            flash('Password should be at least {} characters long'.format(minimum_length), 'error')
                            return redirect(url_for('user_auth.sign_up'))
                        if not any(char.isalpha() for char in password) or not any(char.isdigit() for char in password):
                            flash('Password should contain alphanumeric', 'danger')
                            return redirect(url_for('user_auth.sign_up'))
                       
                        new_user = User(username=username, email=email, password=generate_password_hash(password, method='sha256'))
                        db.session.add(new_user)
                        db.session.commit()
                        #email verfication
                        otp = generate_otp()
                        send_otp(email, otp)
                        session['otp'] = otp
                        
                        flash('Enter the code sent to your email here', 'info')
                        return redirect(url_for('user_auth.confirm'))
                    return render_template('sign_up.html')
            except Exception as e:
                error = '{}'.format(str(e))
                flash(error, 'danger')
                return render_template('sign_up.html')
            def generate_otp():
                otp = ''.join([str(random.randint(0, 9)) for i in range(6)])
                return otp
            
            def send_otp(email, otp):
                message = Message('One Time Password', sender=os.environ.get('MAIL_SENDER'), recipients=[email])
                message.body = 'Your OTP is: {}'.format(otp)
                mail.send(message)
                session['email'] = email
@user_auth.route('confirm', methods=['GET', 'POST'])
def confirm():
    # email = request.args.get('email')
    # otp = request.args.get('otp')
    if request.method == 'POST':
        # email = request.args.get('email')
        otp = request.form.get('otp')
        
        stored_otp = session.get('otp')
        email = session.get('email')

        if otp == stored_otp:
            # Find the user in the database
            user = User.query.filter_by(email=email).first()

            if user:
                # Update the user's account status to True which indicates verified
                user.email_confirm = True
                db.session.commit()

                # create a wallet for the user account
                wallet = Wallet(user_id=user.id)
                db.session.add(wallet)
                db.session.commit()
                # send a notification to the user indicating account has been verified
                flash('Your account has been verified. Kindly Login', 'success')
                # redirect the user to signin after verification
                return redirect(url_for('user_auth.login'))
            else:
                # send a warning notification to the user
                flash('User not found.', 'warning')
        else:
            # send a warning notification to the user
            flash('Invalid OTP.', 'danger')
    
    # if the request method is not POST, then the page below is rendered
    return render_template('verification.html')




@user_auth.route('logout')
@login_required
def logout():
    """logging out the current user."""
    user = current_user
    user.authenticated = False
    db.session.add(user)
    db.session.commit()
    logout_user()

    flash('You are Logged out', 'warning')
    return redirect(url_for('user_auth.login'))


@user_auth.route('password-reset', methods=['GET', 'POST'])
def password_reset():
    if request.method == 'POST':
        email = request.form['email']

        # check if email is valid and registered in the database
        user = User.query.filter_by(email=email).first()

        if user.email_confirm is True:
            #email verfication
            otp = generate_otp() # type: ignore
            send_otp(email, otp) # type: ignore
            session['otp'] = otp
            return redirect(url_for('user_auth.verify'))
        
        flash('sorry, your email account is not valid with us', 'danger')

    return render_template('reset_password.html')


@user_auth.route('verify-email', methods=['GET', 'POST'])
def verify():
    if request.method == 'POST':

        # email = request.args.get('email')
        otp = request.form.get('otp')
        
        stored_otp = session.get('otp')
        email = session.get('email')

        if otp == stored_otp:
            flash('Email has been confirmed!, reset password now', 'success')
            return redirect(url_for('user_auth.change_password'))

    return render_template('email_verify.html')


@user_auth.route('change-password', methods=['GET', 'POST'])
def change_password():
    if request.method == 'POST':
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('password does not match', 'danger')

        minimum_length = 8

        if len(password) < minimum_length:
            flash('Password should be at least {} characters long'.format(minimum_length), 'error')
            return redirect(url_for('user_auth.sign_up'))

        if not any(char.isalpha() for char in password) or not any(char.isdigit() for char in password):
            flash('Password should contain alphanumeric', 'danger')
            return redirect(url_for('user_auth.sign_up'))

        # get the email from the session
        email = session.get('email')
        user = User.query.filter_by(email=email).first()
        user.password = generate_password_hash(password)

        db.session.commit()

        flash('Your password was reset successfully', 'alert')
        return redirect(url_for('user_auth.login'))

    return render_template('change_password.html')

@app.route("/contributions")
def contributions():
    return render_template('contributions.html')

@app.route("/contributors")
def contributors():
    return render_template('contributors.html')

@app.route("/forms")
def forms():
    return render_template('form_page.html')

@app.route("/landing")
def landing():
    return render_template('landing_page.html')

@app.route("/members")
def members():
    return render_template('members_page.html')

@app.route("/existing_members")
def existing_members():
    return render_template('existing_member.html')



if __name__ == '__main__':
    app.run(debug=True)
