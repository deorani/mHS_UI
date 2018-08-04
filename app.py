from flask import Flask, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_login import (LoginManager, login_user, current_user,
                            login_required, logout_user)
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField


app = Flask(__name__)
app.config.update(dict(
    SECRET_KEY="alanafalanadhimkana",
    WTF_CSRF_SECRET_KEY="blahblah"
))


login_manager = LoginManager()
db = SQLAlchemy()


class LoginForm(FlaskForm):
    username = StringField('username')
    password = PasswordField('password')
    submit = SubmitField('submit')

class User(db.Model):
    """An admin user capable of viewing reports.

    :param str email: email address of user
    :param str password: encrypted password for the user

    """
    __tablename__ = 'user'

    email = db.Column(db.String, primary_key=True)
    password = db.Column(db.String)
    authenticated = db.Column(db.Boolean, default=False)

    def is_active(self):
        """True, as all users are active."""
        return True

    def get_id(self):
        """Return the email address to satisfy Flask-Login's requirements."""
        return self.email

    def is_authenticated(self):
        """Return True if the user is authenticated."""
        return self.authenticated

    def is_anonymous(self):
        """False, as anonymous users aren't supported."""
        return False


@login_manager.user_loader
def user_loader(user_id):
    """Given *user_id*, return the associated User object.
        :param user_id: user_id (email) user to retrieve
    """
    return User.query.get(user_id)


@app.route('/login', methods=['GET', 'POST'])
def login():
    """For GET requests, display the login form.
    For POSTS, login the current user by processing the form.

    """
    print(db)
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.get(form.email.data)
        print(user)
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                user.authenticated = True
                db.session.add(user)
                db.session.commit()
                login_user(user, remember=True)
                return redirect(url_for("bull.reports"))
    return render_template("login.html", form=form)

@app.route("/logout", methods=["GET"])
@login_required
def logout():
    """Logout the current user."""
    user = current_user
    user.authenticated = False
    db.session.add(user)
    db.session.commit()
    logout_user()
    return render_template("logout.html")



@app.route("/")
@login_required
def hello():
    return "Hello World!"

if __name__ == "__main__":

    login_manager.init_app(app)
    db.init_app(app)
    app.run()
