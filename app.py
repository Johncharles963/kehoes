from flask import Flask, render_template, url_for, request, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from datetime import datetime
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
skey = os.urandom(12).hex()
app.config['SECRET_KEY'] = skey

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class NewReview(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    content = db.Column(db.String(200), nullable=False)
    first_name = db.Column(db.String(20), nullable=False)
    last_name = db.Column(db.String(20), nullable=False)
    star_rating = db.Column(db.Integer, nullable=False)

    def __repr__(self):
        return f'{self.first_name} {self.last_name}: {self.content}'

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(20), nullable=False)

    def __repr__(self):
        return f'{self.first_name} {self.last_name}: {self.content}'

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/reviews/', methods= ['POST', 'GET'])
def reviews():
    if request.method == 'POST':
        new_txt = request.form['review-txt']
        new_first = request.form['first-name']
        new_last = request.form['last-name']
        new_star = request.form['star']
        new_review = NewReview(content = new_txt, first_name = new_first, last_name = new_last, star_rating = new_star)

        try:
            db.session.add(new_review)
            db.session.commit()
            return redirect('/reviews/')
        except:
            'Issue pushing review to db'
    else:
        reviews = NewReview.query.all()
        return render_template('reviews.html', reviews = reviews)

@app.route('/create/')
def create():
    return render_template('create.html')

@app.route('/delete/<int:id>/')
def delete(id):
    review_to_delete = NewReview.query.get_or_404(id)
    try:
        db.session.delete(review_to_delete)
        db.session.commit()
        return redirect('/reviews/')
    except:
        return 'Problem deleteing item from db'

@app.route('/edit/<int:id>/', methods= ['POST', 'GET'])
def edit(id):
    review_to_edit = NewReview.query.get_or_404(id)
    if request.method == 'POST':
        try:
            review_to_edit.content = request.form['review-txt']
            review_to_edit.first_name = request.form['first-name']
            review_to_edit.last_name = request.form['last-name']
            review_to_edit.star_rating = request.form['star']
            db.session.commit()
            return redirect('/reviews/')
        except:
            return 'Problem editing the review'   
    else:
        return render_template('edit.html', review = review_to_edit)

@app.route('/login/', methods= ['POST', 'GET'])
def login():
    if request.method == 'POST':
        login_username = request.form['username']
        login_password = request.form['password']
        requested_user = User.query.filter_by(username=login_username).first()

        if not requested_user:
            return render_template('login.html', no_user_found = True)
        else:
            if bcrypt.check_password_hash(requested_user.password, login_password):
                login_user(requested_user)
                return redirect('/')
            else:
                return render_template('login.html', wrong_password = True)
    else:       
        return render_template('login.html')

@app.route('/signup/', methods= ['POST', 'GET'])
def signup():
    if request.method == 'POST':
        signup_username = request.form['username']
        signup_password = request.form['password']
        requested_username = User.query.filter_by(username=signup_username).first()

        if not requested_username:
            try:
                hashed_password = bcrypt.generate_password_hash(signup_password)
                new_user= User(username = signup_username, password = hashed_password)
                db.session.add(new_user)
                db.session.commit()
                return redirect('/login/')
            except:
                return 'Issue making hashed password and adding user to database'
        else:
            return render_template('signup.html', same_username = True)
    else:       
        return render_template('signup.html')

@app.route('/view')
def viewUsers():
    allusers = User.query.all()
    return render_template('viewusers.html', users = allusers)

@app.route('/logout/', methods = ['POST', 'GET'])
@login_required
def logout():
    logout_user()
    return redirect('/')

if __name__ == "__main__":
    app.run(debug=True)