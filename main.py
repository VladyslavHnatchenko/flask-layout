from flask import Flask
from flask import abort
from flask import make_response
from flask import redirect
from flask import request
from flask import render_template
from flask import url_for
from flask import flash
from flask import session

from flask_script import Manager, Shell
from flask_script import Command
from forms import ContactForm, LoginForm

from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_migrate import MigrateCommand
from flask_mail import Mail
from flask_mail import Message

from datetime import datetime
from threading import Thread

from werkzeug.security import generate_password_hash,  check_password_hash
from flask_login import LoginManager, UserMixin, current_user, login_required, login_user, logout_user


app = Flask(__name__)
app.debug = True
app.config['SECRET_KEY'] = "b'\x95v\xa5\r|\x1e\x0f\xc6W\xd7\xdb\xea\xd4D\xf8\x0bI\x1b2`y\xc6\x99i'"
app.config['SQLALCHEMY_DATABASE_URI'] = "mysql+mysqlconnector://***:***@localhost/flask_app_db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# pip install mysql-connector
"""HOW TO generate:
open bash: $ python3
            >>> import os
            >>> os.urandom(24)
copy output in app.config['SECRET_KEY']
"""
app.config['MAIL_SERVER'] = 'smtp.googlemail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = '***@gmail.com'  # enter your email
app.config['MAIL_DEFAULT_SENDER'] = '***@gmail.com'  # and here
app.config['MAIL_PASSWORD'] = '***'  # enter password

manager = Manager(app)
manager.add_command("db", MigrateCommand)
db = SQLAlchemy(app)
migrate = Migrate(app, db)
mail = Mail(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# msg = Message("Subject", sender="chack.norrys1991@gmail.com", recipients=['chack.norrys1991@gmail.com'])
# msg = Message("You are win 1.000.000$", recipients=["***@gmail.com"])
# msg.html = "<h1>You are win 1.000.000$</h1>\n<p>What's up, Man!</p>" \
#            "\n<a href='https://www.facebook.com/pg/Spanch-Boborg-441201049358840/posts/'>Your money HERE!</a>"
# msg.body = "Mail body"
# mail.send(msg)


class Category(db.Model):
    __tablename__ = "categories"
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    slug = db.Column(db.String(255), nullable=False)
    created_on = db.Column(db.DateTime(), default=datetime.utcnow)
    posts = db.relationship("Post", backref="category")

    def __repr__(self):
        return f"{self.id}: {self.name}"


post_tags = db.Table("post_tags",
                     db.Column("post_id", db.Integer, db.ForeignKey("posts.id")),
                     db.Column("tag_id", db.Integer, db.ForeignKey("tags.id")),
                     )


class Post(db.Model):
    __tablename__ = "posts"
    id = db.Column(db.Integer(), primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    slug = db.Column(db.String(255), nullable=False)
    content = db.Column(db.Text(), nullable=False)
    created_on = db.Column(db.DateTime(), default=datetime.utcnow)
    updated_on = db.Column(db.DateTime(), default=datetime.utcnow,
                           onupdate=datetime.utcnow)
    category_id = db.Column(db.Integer(), db.ForeignKey("categories.id"))

    def __repr__(self):
        return f"{self.id}: {self.title[:10]}"


class Tag(db.Model):
    __tablename__ = "tags"
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    slug = db.Column(db.String(255), nullable=False)
    created_on = db.Column(db.DateTime(), default=datetime.utcnow)
    posts = db.relationship("Post", secondary=post_tags, backref="tags")

    def __repr__(self):
        return f"{self.id}: {self.name}"


class Feedback(db.Model):
    __tablename__ = 'feedbacks'
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(1000), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    message = db.Column(db.Text(), nullable=False)
    created_on = db.Column(db.DateTime(), default=datetime.utcnow)

    def __repr__(self):
        return f"{self.id}: {self.name}"


class Employee(db.Model):
    __tablename__ = 'employees'
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    designation = db.Column(db.String(255), nullable=False)
    doj = db.Column(db.Date(), nullable=False)


@login_manager.user_loader
def load_user(user_id):
    return db.session.query(User).get(user_id)


class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(100))
    username = db.Column(db.String(50), nullable=False, unique=True)
    email = db.Column(db.String(100), nullable=False, unique=True)
    password_hash = db.Column(db.String(100), nullable=False)
    created_on = db.Column(db.DateTime(), default=datetime.utcnow)
    updated_on = db.Column(db.DateTime(), default=datetime.utcnow,  onupdate=datetime.utcnow)

    def __repr__(self):
        return f"<{self.id}:{self.username}>"

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Faker(Command):
    """Command to add fake data to a table"""
    def run(self):
        # function logic
        print("Fake data entered")


manager.add_command("faker", Faker())


def shell_context():
    import os, sys
    return dict(app=app, os=os, sys=sys)


manager.add_command("shell", Shell(make_context=shell_context))


def async_send_mail(app, msg):
    with app.app_context():
        mail.send(msg)


def send_mail(subject, recipient, template, **kwargs):
    msg = Message(subject, sender=app.config['MAIL_DEFAULT_SENDER'], recipients=[recipient])
    msg.html = render_template(template, **kwargs)
    thread_ = Thread(target=async_send_mail, args=[app, msg])
    thread_.start()
    return thread_


@app.route('/admin/')
@login_required
def admin():
    return render_template('admin.html')


@app.route('/')
def index():
    name, age, profession = "Chuck", 28, 'Programmer'
    template_context = dict(name=name, age=age, profession=profession)
    py_lang = ["Django", "web2py", "Flask"]
    return render_template('base.html', **template_context)

    # return "What's up, Man!"
    # return f"Hello! Your IP is {request.remote_addr} " \
    #        f"<br>and you are using: {request.user_agent}"


@app.route('/test')
def index1():
    return redirect(url_for('index'))


@app.route('/user/<int:user_id>/')
def user_profile(user_id):
    str_ = f"Profile page of user #{user_id}"
    template_c = dict(str_=str_)
    return render_template('index.html', **template_c)


@app.route('/books/<genre>/')
def books(genre):
    res = make_response(f"All Books in {genre} category")
    res.headers['Content-Type'] = 'text/plain'
    res.headers['Server'] = 'Foobar'
    return res
    # return f"All Books in {genre} category"


@app.route('/set-cookie/')
def set_cookie():
    res = make_response("Cookie setter")
    res.set_cookie("favorite-color", "skyblue", 60 * 60 * 24 * 1)
    res.set_cookie("favorite-font", "sans-serif", 60 * 60 * 24 * 15)
    return res


@app.route('/transfer')
def transfer():
    return redirect("http://localhost:5000/user/344/")


@app.route('/login/', methods=('GET', 'POST'))
def login():
    if current_user.is_authenticated:
        return redirect(url_for('admin'))

    form = LoginForm()
    if form.validate_on_submit():
        user = db.session.query(User).filter(User.username == form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember.data)
            return redirect(url_for('admin'))

        flash("Invalid username/password", 'error')
        return redirect(url_for('login'))

    return render_template('login.html', form=form)


@app.route('/logout/')
@login_required
def logout():
    logout_user()
    flash("You have been logged out.")
    return redirect(url_for('login'))


@app.route("/contact/", methods=('GET', 'POST'))
def contact():
    form = ContactForm()
    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        message = form.message.data
        # DB logic
        feedback = Feedback(name=name, email=email, message=message)
        db.session.add(feedback)
        db.session.commit()
        msg = Message("Feedback", recipients=[app.config['MAIL_USERNAME']])
        msg.body = f"You have received a new feedback from {name} <{email}>."
        mail.send(msg)

        print("\nData received. Now redirecting...")
        flash("Message received", "success")
        return redirect(url_for('contact'))

    return render_template('contact.html', form=form)


@app.route('/cookie/')
def cookie():
    if not request.cookies.get('foo'):
        res = make_response("Setting a cookie")
        res.set_cookie('foo', 'bar', max_age=60 * 60 * 24 * 365 * 2)
    else:
        res = make_response("Value of cookie foo is {}"
                            .format(request.cookies.get('foo')))
    return res


@app.route('/delete-cookie/')
def delete_cookie():
    res = make_response("Cookie Removed")
    res.set_cookie('font', 'arial', max_age=0)
    return res


@app.route('/article/', methods=('GET', 'POST'))
def article():
    if request.method == 'POST':
        print(request.form)
        res = make_response("")
        res.set_cookie("font", request.form.get('font'), 60*60*24*15)
        res.headers['location'] = url_for('article')
        return res, 302

    return render_template('article.html')


@app.route('/visits-counter/')
def visits():
    if 'visits' in session:
        session['visits'] = session.get('visits') + 1
    else:
        session['visits'] = 1
    return f"Total visits: {session.get('visits')}"


@app.route("/delete-visits/")
def delete_visits():
    session.pop('visits', None)
    return "Visits deleted!"


@app.route('/404')
def index_404():
    abort(404)


@app.errorhandler(404)
def http_404_handler(error):
    return "<p>HTTP 404 Error Encountered</p>", 404


@app.errorhandler(500)
def http_500_handler(error):
    return "<p>HTTP 500 Error Encountered</p>", 500


if __name__ == "__main__":
    manager.run()
    # app.run(debug=True)
