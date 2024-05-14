from flask import Blueprint, request, render_template
from flask import send_from_directory

main_views = Blueprint("main", __name__)

#Create routes on this blueprint instance
@main_views.get("/download/<string:potters_queue>", strict_slashes=False)
def downlaod(potters_queue):
    return send_from_directory(f"/tmp/Potters/{potters_queue}")

def home():
    # Define application logic for homepage
    return render_template('common.html')

@main_views.get("/profile/<string:username>", strict_slashes=False)
def profile(username):
    #Define application logic for profile page
    return f"<h1>Welcome {username}!<h1>"
