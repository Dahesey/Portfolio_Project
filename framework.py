from flask import Flask, render_template
from Blueprint.main_blueprint import main_views
from Blueprint.auth_blueprint import auth_views
from flask_login import LoginManager


app = Flask(__name__)

app.register_blueprint(main_views)

login = LoginManager(auth_views)
login.login_view = "/login"

@login.user_loader
def load_user(id):
    """Confirming user exists in database then use, else return none"""
    current_user = user.find.one({ "id": ObjectId(id) })

    if current_user is None:
        return None

    return User(current_user.get("username"), str(current_user.get("id")))

@app.route("/")
@app.route("/home")
def home():
    return render_template('common.html')

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

    return render_template('login.html')

@app.route("/sign_up", methods=["GET", "POST"])
def sign_up():
    if request.method == "POST":
        name = request.form["fullname"]
        email = request.form["email"]
        password = request.form["password"]
        confirm_password = request.form["confirm"]

    return render_template('sign_up.html')

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
