from app import create_app, login
from flask_login import LoginManager, UserMixin
from flask import Flask, g
from werkzeug.security import generate_password_hash, check_password_hash


class User():

    # currently storing here, will be db later
    # users = {}

    def __init__(self, username, password, new=True):
        # user_info = {}
        self.username = username
        if new:
            self.set_password(password)
            self.authenticated = True
        else:
            # should check if authenticated, now just overwriting password
            self.set_password(password)
            self.authenticated = True
        self.active = True
        self.anon = False
        self.id = make_id(username)

    @staticmethod
    def make_id(username):
        res = ''
        for char in username:
            res += str(ord(char))
        return int(res)

    def is_authenticated(self):
        return self.authenticated

    def is_active(self):
        return self.active

    def is_anonymous(self):
        return self.anon

    def get_id(self):
        return unicode(self.id)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


app = create_app('config.development')

login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)


@app.route('/login', methods=['GET'])
def login():
    # Here we use a class of some kind to represent and validate our
    # client-side form data. For example, WTForms is a library that will
    # handle this for us, and we use a custom LoginForm to validate.
    form = LoginForm()
    if form.validate_on_submit():
        # Login and validate the user.
        # user should be an instance of your `User` class
        login_user(user)

        flask.flash('Logged in successfully.')

        next = flask.request.args.get('next')
        # is_safe_url should check if the url is safe for redirects.
        # See http://flask.pocoo.org/snippets/62/ for an example.
        if not is_safe_url(next):
            return flask.abort(400)

        return flask.redirect(next or flask.url_for('index'))
    return flask.render_template('login.html', form=form)


@app.route('/login', methods=['POST'])
def login_new():
    # Here we use a class of some kind to represent and validate our
    # client-side form data. For example, WTForms is a library that will
    # handle this for us, and we use a custom LoginForm to validate.
    form = LoginForm()
    if form.validate_on_submit():
        # Make a new user then log them in
        # user should be an instance of your `User` class
        login_user(user)

        flask.flash('Logged in successfully.')

        next = flask.request.args.get('next')
        # is_safe_url should check if the url is safe for redirects.
        # See http://flask.pocoo.org/snippets/62/ for an example.
        if not is_safe_url(next):
            return flask.abort(400)

        return flask.redirect(next or flask.url_for('index'))
    return flask.render_template('login.html', form=form)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(somewhere)


if __name__ == '__main__':
    app.run()
