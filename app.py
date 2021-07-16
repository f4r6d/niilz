import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True


# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
uri = os.environ.get("DATABASE_URL")
uri = uri.replace("postgres://", "postgresql://", 1)
db = SQL(uri)


# db.execute("CREATE TABLE users (id SERIAL PRIMARY KEY, username TEXT NOT NULL, hash TEXT NOT NULL, cash NUMERIC NOT NULL DEFAULT 10000.00)")

# db.execute("CREATE TABLE trans (user_id SERIAL , symbol TEXT NOT NULL, shares NUMERIC NOT NULL, price NUMERIC NOT NULL DEFAULT 0, ts  TIMESTAMP DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(user_id) REFERENCES users(id))")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    rows = db.execute("SELECT symbol, sum(shares) FROM trans WHERE user_id=? GROUP BY symbol", session["user_id"])

    stocks = []
    total = 0
    for row in rows:
        if row['sum'] != 0:
            stock = {}
            stock['symbol'] = row['symbol'].upper()
            stock['name'] = lookup(row['symbol'])['name']
            stock['shares'] = row['sum']
            stock['price'] = lookup(row['symbol'])['price']
            stock['total'] = usd(stock['price'] * stock['shares'])
            total += stock['price'] * stock['shares']

            stocks.append(stock)
    for stock in stocks:
        stock['price'] = usd(stock['price'])

    user = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])
    cash = user[0]['cash']
    total += cash



    return render_template('index.html', stocks=stocks, cash=usd(cash), total=usd(total))


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == 'POST':
        if not request.form.get('shares'):
            return apology("enter how many shares")

        symbol = request.form.get('symbol').upper()
        if lookup(symbol):
            user = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])
            total = user[0]['cash']




            if not request.form.get('shares'):
                return apology("enter share count")

            if not request.form.get('shares').isdigit():
                return apology("enter valid share count")

            if float(request.form.get('shares')) < 0 or float(request.form.get('shares')) % 1 != 0:
                return apology("enter valid share count")

            price = lookup(symbol)['price'] * int(request.form.get('shares'))

            if price > total:
                return apology("not enough money")


            else:

                total -= price
                db.execute("UPDATE users SET cash = ? WHERE id = ?", total, session["user_id"])

                db.execute("INSERT INTO trans (user_id, symbol, shares, price) VALUES(?, ?, ?, ?)", session["user_id"], symbol, int(request.form.get('shares')), price)

                return redirect('/')

        return apology("wrong symbol")


    return render_template('buy.html')


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    records = db.execute("SELECT * FROM trans WHERE user_id=?", session["user_id"])

    for r in records:
        r['price'] = usd(r['price'])

    return render_template('history.html', records=records)


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
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
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


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == 'POST':
        symbol = request.form.get('symbol')
        if lookup(symbol):
            sym = lookup(symbol)["name"]
            price = usd(float(lookup(symbol)["price"]))
            return render_template('quote_price.html', sym=sym, price=price)

        return apology("wrong symbol")


    return render_template('quote.html')


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
            return redirect("/")




    else:
        return render_template('register.html')


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    rows = db.execute("SELECT symbol, sum(shares) FROM trans WHERE user_id=? GROUP BY symbol", session["user_id"])

    stocks = {}
    for row in rows:
        if row['sum'] != 0:
            stocks[row['symbol']] = row['sum']

    if request.method == "POST":
        sym = request.form.get('symbol').upper()
        if not sym:
            return apology("select one stock to sell")

        if sym not in stocks:
            return apology("you dont have that share, dont cheet")

        sh = request.form.get('shares')
        if not sh:
            return apology("enter how many to sell")

        if int(sh) > stocks[sym]:
            return apology("you dont have that much shares to sell")

        price = int(sh) * lookup(sym)['price']

        total =  (db.execute("SELECT * FROM users WHERE id=?", session["user_id"]))[0]['cash']

        total += price

        db.execute("UPDATE users SET cash = ? WHERE id = ?", total, session["user_id"])

        db.execute("INSERT INTO trans (user_id, symbol, shares, price) VALUES(?, ?, ?, ?)", session["user_id"], sym, int(sh) * -1, price)

        return redirect('/')




    return render_template('sell.html', stocks=stocks)


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
