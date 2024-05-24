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
from models.user import LoginSchema
from dotenv import load_dotenv
from Blueprint.auth_blueprint import auth_views
from Blueprint.main_blueprint import main_views
from db.database import get_db as db
import re, random
from datetime import datetime


load_dotenv('.env')


user_auth = Blueprint('user_auth', __name__)


app = Flask(__name__)

app.register_blueprint(main_views) # type: ignore

login = LoginManager(auth_views)
login.login_view = "/login"

def database(collection: str):
    db = get_db()
    collection = db[collection]
    return collection

@login.user_loader
def load_user(email: str):
    """Confirming user exists in database then use, else return none"""
    current_user = user.find_one({ "email": email}) # type: ignore
    if not current_user:
        return None
    return User(current_user.get("username"), str(current_user.get("id"))) # type: ignore

@app.route("/", methods=["GET"])
def home():
    return render_template('homepage.html')

@user_auth.route('/login', methods=['GET', 'POST'])
def login():
    try:
        if request.method == 'POST':
            email = request.form['email']
            password = request.form['password']

            collection = db["user"]
            user = collection.find_one({"email": email})

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
                if user.email:
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
                data = {
                    'fullname': request.form['fullname'],
                    'email': request.form['email'],
                    'ghana_card': request.form['ghana_card'],
                    'date_of_birth': request.form['date_of_birth'],
                    'password': request.form['password'],
                    'confirm': request.form['confirm_password'],
                    'timestamp': datetime.now()
                }
                user = RegistrationSchema(**data)
                if not user:
                    return
                collection = database("users")
                persist_user = collection.insert_one(user)
                return redirect(url_for('user_auth.home'))
            return render_template('sign_up.html')
        except Exception as e:
            print(str(e))
            flash(error, 'danger')
            return render_template('sign_up.html')

@user_auth.route('logout')
@login_required
def logout():
    """logging out the current user."""
    user = current_user
    user.authenticated = False
    logout_user()
    flash('You are Logged out', 'warning')
    return redirect(url_for('user_auth.login'))



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