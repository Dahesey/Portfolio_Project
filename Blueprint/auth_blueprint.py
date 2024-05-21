from flask import Blueprint, request, render_template
from flask import redirect

auth_views = Blueprint("auth", __name__)
# Create routes on this blueprint instance
@auth_views.route("/sign_up", strict_slashes=False, methods=["GET", "POST"])
def sign_up():
    # Defining application logic for homepage
    if request.method == "POST":
        username = request.form.get("username")
        email = request.email.get("email")
        password = request.password.get("password")
        return render_template("login.html")
    
    return render_template("sign_up.html")


@auth_views.route("/login", strict_slashes=False, methods=["GET", "POST"])
def login():
    # Define application logic for homepage
    if request.method == "POST":
        #Enter logic for processing registration
        return "<h2>Login successful</h2>"
    return render_template("login.html")
