from flask import Flask, render_template



app = Flask(__name__)

@app.route("/")
@app.route("/home")
def home():
    return render_template('common.html')

@app.route("/login")
def login():
    return render_template('login.html')

@app.route("/sign_up")
def sign_up():
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
