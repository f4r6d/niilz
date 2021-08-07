import os
import urllib.parse
import requests
from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session, url_for, abort, send_from_directory
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required

from werkzeug.utils import secure_filename



# arvan cloud
import boto3
import logging
from botocore.exceptions import ClientError

# Configure logging arvan cloud
logging.basicConfig(level=logging.INFO)



# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.config['MAX_CONTENT_LENGTH'] = 20 * 1024 * 1024
app.config['UPLOAD_EXTENSIONS'] = ['.mp3', '.wav', '.aac', '.flac', '.m4a']

#  app.config['UPLOAD_PATH'] = 'static/music/'

app.config['UPLOAD_PATH'] = 'https://songs.s3.ir-thr-at1.arvanstorage.com/'


# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response



# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
uri = os.environ.get("DATABASE_URL")
uri = uri.replace("postgres://", "postgresql://", 1)
db = SQL(uri)


# db.execute("CREATE TABLE users (id SERIAL PRIMARY KEY, username TEXT NOT NULL, hash TEXT NOT NULL, admin numeric)")

# db.execute("UPDATE users SET admin = 1 WHERE id = 1")

# db.execute("CREATE TABLE songs (id SERIAL PRIMARY KEY, user_id SERIAL, track TEXT NOT NULL, message TEXT, likes NUMERIC NOT NULL DEFAULT 0, ts  TIMESTAMP DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(user_id) REFERENCES users(id))")




@app.route("/")
@login_required
def index():
    files = db.execute("SELECT * FROM songs order by id desc")
    users = db.execute("SELECT * FROM users order by id")
    admin = db.execute("SELECT admin FROM users WHERE id= ?", session["user_id"])
    return render_template('index.html', files=files, users=users, admin=admin)

@app.route('/', methods=['POST'])
def upload_files():
    uploaded_file = request.files['file']
    filename = secure_filename(uploaded_file.filename)
    message = request.form.get('message')
    if filename != '':
        file_ext = os.path.splitext(filename)[1]
        if file_ext not in app.config['UPLOAD_EXTENSIONS']:
            flash("abort")
            abort(400)

        #  uploaded_file.save(os.path.join(app.config['UPLOAD_PATH'], filename))

        try:
            s3_resource = boto3.resource(
                's3',
                endpoint_url=os.environ.get("endpoint_url"),
                aws_access_key_id=os.environ.get("access_key"),
                aws_secret_access_key=os.environ.get("secret_key")
            )

        except Exception as exc:
            logging.error(exc)
        else:
            try:
                bucket = s3_resource.Bucket('songs')

                bucket.put_object(
                    ACL='public-read-write',
                    Body=uploaded_file,
                    Key=filename
                )

            except ClientError as e:
                logging.error(e)

        db.execute("INSERT INTO songs (user_id, track, message) VALUES(?, ?, ?)", session["user_id"], filename, message )
    flash(filename + ' Uploaded')
    return redirect(url_for('index'))


@app.route("/delete/<int:id>")
def delete(id):

    song = db.execute("select track from songs where id=?", id)
    db.execute("delete from songs where id=?", id)

    try:
        s3_resource = boto3.resource(
            's3',
            endpoint_url=os.environ.get("endpoint_url"),
            aws_access_key_id=os.environ.get("access_key"),
            aws_secret_access_key=os.environ.get("secret_key")
        )
    except Exception as exc:
        logging.error(exc)
    else:
        try:
            object_name = song[0]['track']

            bucket = s3_resource.Bucket('songs')
            object = bucket.Object(object_name)
            response = object.delete(
                VersionId='string',
            )
        except ClientError as e:
            logging.error(e)


    flash(object_name + ' Deleted')
    return redirect("/")



# @app.route("/messages", methods=['GET', 'POST'])
# @login_required
# def messages():
#     if request.method == "POST":
#         message = urllib.parse.quote(request.form.get('message'))
#         r = requests.get(f'https://api.kavenegar.com/v1/{os.environ.get("API_KEY")}/sms/send.json?receptor=09386048243&sender=10004346&message={message}')
#         if r.status_code == requests.codes.ok:
#             return render_template("send.html")
#     else:
#         return render_template("messages.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username").lower())

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        flash("Logged in!")
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/change", methods=["GET", "POST"])
@login_required
def change():
    """change password"""

    if request.method == 'POST':

        old = request.form.get('old')
        new = request.form.get('new')
        confirmation = request.form.get('confirmation')

        if not old:
            return apology("please enter old pass")

        if not new or not confirmation:
            return apology("please enter both new password")

        if new != confirmation:
            return apology("new passwords dont match")

        user = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])


        if not check_password_hash(user[0]["hash"], old):
            return apology("wrong old passwords ")
        else:
            db.execute("UPDATE users SET hash = ? WHERE id = ?", generate_password_hash(new), session["user_id"])

            session.clear()

            # Redirect user to home page
            return redirect("/")

    return render_template("change.html")



@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == 'POST':

        username = request.form.get('username').lower()
        password = request.form.get('password')
        confirmation = request.form.get('confirmation')

        if not username:
            return apology("please enter username")

        if not password or not confirmation:
            return apology("please enter both password")

        if password != confirmation:
            return apology("passwords dont match")

        already = db.execute("SELECT * FROM users WHERE username = ?", username)

        if already:
            return apology("username has been taken, try another")
        else:
            db.execute("INSERT INTO users (username, hash) VALUES(?, ?)", username, generate_password_hash(password))

            rows = db.execute("SELECT * FROM users WHERE username = ?", username)

            session["user_id"] = rows[0]["id"]

            # Redirect user to home page
            flash("Successfully registered!")
            return redirect("/")


    else:
        return render_template('register.html')




def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)


if __name__ == '__main__':
    app.run(debug=True)
