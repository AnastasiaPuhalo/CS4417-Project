from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
import re  # For input validation
import bleach
from markupsafe import escape  # For sanitizing user input

app = Flask(__name__)
app.secret_key = 'supersecretkey'  # Change this in production!
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)


# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

class Feedback(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)

    # Relationship to fetch the user who posted the feedback
    user = db.relationship('User', backref='feedbacks', lazy=True)

# Routes
@app.route('/')
def home():
    return render_template('home.html')  

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if (len(username) < 5 or 
            not re.match(r'^[a-zA-Z0-9_.-@]+$', username)):
            flash('Username must be at least 5 characters long and can only contain letters, numbers and some special characters.', 'error')
            return redirect(url_for('register'))

        if (len(password) < 8 or 
            not re.search(r'[A-Z]', password) or 
            not re.search(r'[a-z]', password) or 
            not re.search(r'[0-9]', password) or 
            not re.search(r'[!@#$%^&*]', password)):
            flash('Password must be at least 8 characters long, include an uppercase letter, a lowercase letter, a number, and a special character.', 'error')
            return redirect(url_for('register'))

        username = username.lower()
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, password=hashed_password)
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('User registered successfully!', 'success')
            return redirect(url_for('login'))
        except:
            flash('Username already exists.', 'error')
    return render_template('register.html')  # Create a register.html file

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        username = username.lower()
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            session['user_id'] = user.id
            #flash('Logged in successfully!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid credentials.', 'error')
    return render_template('login.html')  # Create a login.html file

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    #flash('Logged out.', 'success')
    return redirect(url_for('home'))

@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'user_id' not in session:
        flash('Please log in first.', 'error')
        return redirect(url_for('login'))

    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        user = User.query.get(session['user_id'])

        if user and bcrypt.check_password_hash(user.password, current_password):
            # Check if the new password is the same as the old password
            if bcrypt.check_password_hash(user.password, new_password):
                flash('New password cannot be the same as the old password.', 'error')
                return render_template('change_password.html', current_password=current_password)

            # Validate new password strength
            if (len(new_password) < 8 or 
                not re.search(r'[A-Z]', new_password) or 
                not re.search(r'[a-z]', new_password) or 
                not re.search(r'[0-9]', new_password) or 
                not re.search(r'[!@#$%^&*]', new_password)):
                flash('New password must be at least 8 characters long, include an uppercase letter, a lowercase letter, a number, and a special character.', 'error')
                return render_template('change_password.html', current_password=current_password)
            
            else:
                user.password = bcrypt.generate_password_hash(new_password).decode('utf-8')
                db.session.commit()
                flash('Password changed successfully.', 'success')

                # Logout the user by clearing the session
                session.pop('user_id', None)
                return redirect(url_for('login'))
        else:
            flash('Incorrect current password.', 'error')
    return render_template('change_password.html')  # Create change_password.html


@app.route('/feedback', methods=['GET', 'POST'])
def feedback():
    if 'user_id' not in session:
        flash('Please log in first.', 'error')
        return redirect(url_for('login'))

    if request.method == 'POST':
        content = request.form['content']

        # Sanitize the input to prevent attacks
        # Define allowed tags for feedback
        allowed_tags = ['b', 'i', 'u', 'strong', 'em', 'a', 'p', 'blockquote']
        sanitized_content = bleach.clean(content, tags=allowed_tags, strip=True)

        if not sanitized_content:
            flash('Feedback cannot be empty.', 'error')
            return redirect(url_for('feedback'))

         # Save sanitized feedback to the database
        feedback = Feedback(user_id=session['user_id'], content=sanitized_content)
        db.session.add(feedback)
        db.session.commit()

        flash('Thank you for your feedback!', 'success')
        return redirect(url_for('feedback'))

    # Retrieve all feedbacks from the database, ordered by ID (newest first)
    all_feedbacks = Feedback.query.order_by(Feedback.id.desc()).all()

    return render_template('feedback.html', feedbacks=all_feedbacks)

# Initialize Database
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)




