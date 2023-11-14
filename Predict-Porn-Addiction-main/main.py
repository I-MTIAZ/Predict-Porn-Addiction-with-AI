from flask import Flask, render_template, url_for, redirect, request,jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
import pickle

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'thisisasecretkey'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
model = pickle.load(open('saved_model.sav', 'rb'))
login_manager = LoginManager(app)


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@login_manager.unauthorized_handler
def unauthorized_callback():
    return redirect('/login')


class RegisterForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username", 'class': 'form-control'})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password", 'class': 'form-control'})

    submit = SubmitField(label='Register', render_kw={
                         'class': 'btn btn-outline-dark'})

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            raise ValidationError(
                'That username already exists. Please choose a different one.')


class LoginForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username", 'class': 'form-control'})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password", 'class': 'form-control'})

    submit = SubmitField(label='Login', render_kw={
                         'class': 'btn btn-outline-dark'})


# @app.route('/predict')
# @login_required
# def predict():
#     # form = PredictForm()
#     return render_template('home.html')




@app.route('/predict', methods=['POST', 'GET'])
@login_required
def predict():
    result = ""
    
    if request.method == 'POST':
        # Get form values from the request
        excessive = int(request.form.get('excessive'))
        quit_unsuccessful = int(request.form.get('quit_unsuccessful'))
        loss_focus = int(request.form.get('loss_focus'))
        reduction = int(request.form.get('reduction'))
        engaging_risky = int(request.form.get('engaging_risky'))
        guilt_shame = int(request.form.get('guilt_shame'))
        cycles = int(request.form.get('cycles'))
        health_issue = int(request.form.get('health_issue'))
        demanding = int(request.form.get('demanding'))
        lost_attraction = int(request.form.get('lost_attraction'))
        physical_pain = int(request.form.get('physical_pain'))
        feeling_distracted = int(request.form.get('feeling_distracted'))
        a_u_issue_r = int(request.form.get('a_u_issue_r'))
        cope_feelings = int(request.form.get('cope_feelings'))
        sex_life_less_satisfying = int(request.form.get('sex_life_less_satisfying'))
        lost_interest = int(request.form.get('lost_interest'))
        obsessive_thoughts = int(request.form.get('obsessive_thoughts'))
        feeling_withdrawal = int(request.form.get('feeling_withdrawal'))

        try:
            # Use the input values to make predictions
            result = model.predict([[excessive, quit_unsuccessful, loss_focus, reduction, engaging_risky, guilt_shame, cycles, health_issue, demanding, lost_attraction,
                                     physical_pain, feeling_distracted, a_u_issue_r, cope_feelings, sex_life_less_satisfying, lost_interest, obsessive_thoughts, feeling_withdrawal]])[0]
        except (ValueError, TypeError) as e:
            error_message = f"Error: {str(e)}"
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'result': None, 'error_message': error_message})
            return render_template('home.html', result=result, error_message=error_message)

    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({'result': result, 'error_message': None})
    return render_template('home.html', result=result)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('landing'))
    return render_template('login.html', form=form)


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    return render_template('dashboard.html')


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@ app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('reg.html', form=form)


@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/')
def landing():
    return render_template('landing.html')

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
