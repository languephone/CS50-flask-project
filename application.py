import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
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
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    shares = db.execute("""SELECT symbol, SUM(shares) AS shares\
        FROM purchases\
        JOIN users ON users.username = purchases.username\
        WHERE users.id = ?\
        GROUP BY symbol""", session["user_id"])
    user = db.execute("SELECT * FROM users WHERE id = ?", session['user_id'])
    cash = user[0]['cash']
    account = cash
    for share in shares:
        share_info = lookup(share['symbol'])
        share['price'] = usd(share_info['price'])
        share['name'] = share_info['name']
        share['value'] = usd(share_info['price'] * share['shares'])
        account += share_info['price'] * share['shares']
    return render_template("index.html", user=user[0]['username'], shares=shares, cash=usd(user[0]['cash']), account=usd(account))


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    rows = db.execute("SELECT * FROM users WHERE id = ?", session['user_id'])
    cash = rows[0]['cash']
    if request.method == "GET":
        return render_template("buy.html", cash=usd(cash))
    else:
        symbol = request.form.get("symbol").upper()
        shares = request.form.get("shares")
        quote = lookup(symbol)

        # Ensure symbol is entered
        if not request.form.get("symbol"):
            return apology("must enter symbol", 400)

        # Ensure symbol is recognized
        elif not lookup(request.form.get("symbol")):
            return apology("symbol not recognized", 400)

        # Ensure shares entered
        elif not shares:
            return apology("must enter number of shares", 400)

        # Ensure shares entered as positive integer
        elif not shares.isnumeric() or int(shares) < 1:
            return apology("shares must be positive integer", 400)

        # Ensure user has enough cash to buy requested shares
        elif int(shares) * quote['price'] > cash:
            return apology("not enough ca$h in your account")
        else:
            # Enter buy transaction into database
            db.execute("""INSERT INTO purchases (username, symbol, shares, price)\
                VALUES (?, ?, ?, ?)""",
                    rows[0]["username"], symbol, shares, quote['price'])
            # Update user's cash to reflect purchase
            db.execute("""UPDATE users\
                SET cash = cash - ?\
                WHERE id = ?""",
                    int(shares) * quote['price'], session['user_id'])
            return redirect("/")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    username = db.execute("SELECT username FROM users WHERE id = ?", session['user_id'])[0]['username']
    transactions = db.execute("SELECT * FROM purchases WHERE username = ?", username)
    # Clean and format data
    for transaction in transactions:
        transaction['price'] = usd(transaction['price'])
    return render_template("history.html", transactions=transactions, username=username)


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


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "GET":
        return render_template("quote_live.html", )
    else:
        # Ensure symbol was submitted
        if not request.form.get("symbol"):
            return apology("must provide symbol", 400)
        # Ensure symbol is recognized
        elif not lookup(request.form.get("symbol")):
            return apology("symbol not recognized", 400)

        quote = lookup(request.form.get("symbol"))
        # return render_template("quote_live.html", quote=quote, price=quote['price'])
        return jsonify(quote)


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    # User reached route via GET (as by clicking a link or via redirect)
    if request.method == "GET":
        return render_template("register.html")
    else:
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)

        # Ensure confirmation password was submitted
        elif not request.form.get("confirmation"):
            return apology("must confirm password", 400)

        # Ensure confirmation password matches original
        elif request.form.get("confirmation") != request.form.get("password"):
            return apology("passwords must match", 400)

        # Ensure username isn't taken
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))
        if len(rows) > 0:
            return apology("Username already exists", 400)
        else:
            username = request.form.get("username")
            pass_hash = generate_password_hash(request.form.get("password"))
            db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, pass_hash)
            return redirect("/")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    # Get user's holdings to feed into selling template
    user = db.execute("SELECT * FROM users WHERE id = ?", session['user_id'])
    shares = db.execute("""SELECT symbol, SUM(shares) AS shares FROM purchases\
        JOIN users ON users.username = purchases.username\
        WHERE users.id = ?\
        GROUP BY symbol""", session["user_id"])
    holdings = [share['symbol'] for share in shares]  # TODO refactor code to remove this variable

    if request.method == "GET":
        return render_template("sell.html", holdings=holdings)

    else:
        # Ensure stock symbol was submitted
        if not request.form.get("symbol"):
            return apology("must enter stock symbol")

        # Ensure number of shares was submitted
        elif not request.form.get("shares"):
            return apology("must enter number of shares")

        # Look up existing holdings to check
        symbol = request.form.get("symbol")
        shares = int(request.form.get("shares"))
        holdings = db.execute("""SELECT purchases.username, symbol, SUM(shares) AS shares\
            FROM purchases JOIN users ON users.username = purchases.username\
            WHERE symbol = ? AND users.id = ?""", symbol, session['user_id'])
        quote = lookup(symbol)

        # Ensure symbol is recognized
        if not quote:
            return apology("symbol not recognized", 400)

        # Ensure shares are positive integer
        elif shares < 1:
            return apology("shares must be positive integer", 400)

        # Ensure users owns that stock
        elif not holdings[0]['shares']:
            return apology("you don't own that stock")

        # Ensure user doesn't sell more than he/she owns
        elif shares > holdings[0]['shares']:
            return apology("you don't own that many shares")

        else:
            # Record sale in purchases table by adding row with negative number of shares
            db.execute("""INSERT INTO purchases (username, symbol, shares, price)\
                VALUES (?, ?, ?, ?)""",
                    holdings[0]["username"], symbol, -shares, quote['price'])

            # Add value of sale back to cash in users table
            db.execute("""UPDATE users\
                SET cash = cash + ?\
                WHERE id = ?""",
                    shares * quote['price'], session['user_id'])
            return redirect("/")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)