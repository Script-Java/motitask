from flask import Flask, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from getQuote import get_quote
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, ValidationError, EqualTo, Email
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from getQuote import get_quote
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///task.sqlite'
app.config['SQLALCHEMY_TRACK_MODIFICATION'] = False
app.config['SECRET_KEY'] = ""
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), nullable=False)
    email = db.Column(db.String(255), nullable=False)
    password = db.Column(db.String(100), nullable=False)
    tasks = db.relationship("Task", backref="user",lazy=True)
    
class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String, nullable=False)
    complete = db.Column(db.Boolean, default=False)
    created = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer(), db.ForeignKey('user.id'))
    

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=5, max=20)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=12, max=20)])
    submit = SubmitField('Login')
    
class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=5, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=12, max=20)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password', message='Password must match')])
    submit = SubmitField('Sign Up')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))    

@app.route('/')
def index():
    if current_user.is_authenticated:
        return render_template('autherized/aindex.html')
    
    return render_template('main/index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data)
        new_user = User(username = form.username.data, email = form.email.data, password = hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('auth/login'))
    
    return render_template('auth/register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username = form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('dashboard'))
    return render_template('auth/login.html', form=form)


@app.route('/dashboard')
@login_required
def dashboard():
    # current_user is a built-in function and .tasks is refering to our User model
    tasks = current_user.tasks
    quote = get_quote()
    return render_template('main/dashboard.html', tasks=tasks, quote=quote)

@app.route('/add', methods=['GET', 'POST'])
@login_required
def add():
    task_title = request.form.get('task_input')
    new_task = Task(title=task_title, complete=False, user_id=current_user)
    current_user.tasks.append(new_task)
    db.session.commit()
    return redirect(url_for('main/dashboard'))

@app.route('/remove/<int:task_id>', methods=['GET', 'POST'])
@login_required
def remove(task_id):
    task = Task.query.filter_by(id=task_id).first()
    
    if task:
        db.session.delete(task)
        db.session.commit()
    
    return redirect(url_for('dashboard'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))



if __name__ == '__main__':
    app.run(debug=True)
