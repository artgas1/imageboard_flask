from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask import render_template, request, redirect, session, flash, Markup, abort, url_for, send_from_directory
from werkzeug.utils import secure_filename
from flask_bootstrap import Bootstrap
import os
import time
import bcrypt
import hashlib
import base64


app = Flask(__name__)
Bootstrap(app)

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg', 'gif'])

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['DEBUG'] = False
app.debug = True
app.secret_key = os.urandom(24)
salt = b'$2b$12$cGdDcXYDdpaPrW4AyOc8De'
db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)

    def __repr__(self):
        return '<User {},{},{},{}>'.format(self.id, self.login, self.password, self.email)


class Theme(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    theme = db.Column(db.String(120), unique=True, nullable=False)
    description = db.Column(db.String(120), unique=True, nullable=False)
    rating = db.Column(db.Integer, default = 5)
    date = db.Column(db.Integer, default=int(time.time()))
    relevant = db.Column(db.Integer, default = 1)

    def __repr__(self):
        return '<Theme {},{},{},{},{}>'.format(self.id, self.theme, self.description, self.rating, self.date)


class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    theme_id = db.Column(db.Integer, nullable=False)
    author = db.Column(db.String(120), nullable=False)
    comment = db.Column(db.String(120), nullable=False)
    image_path = db.Column(db.String(120), nullable=True)

    def __repr__(self):
        return '<Comment {},{},{},{},{}>'.format(self.id, self.theme_id, self.author, self.comment, self.image_path)


class Vote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    theme_id = db.Column(db.Integer, nullable=False)
    vote_author = db.Column(db.String(120), nullable=False)
    up_down = db.Column(db.Integer, nullable=False)

    def __repr__(self):
        return '<Vote {},{},{},{}>'.format(self.id, self.theme_id, self.vote_author, self.up_down)


db.create_all()
db.session.commit()
all_users = User.query.all()
all_themes = Theme.query.all()
all_comments = Comment.query.all()
all_votes = Vote.query.all()
print(all_users)
print(all_themes)
print(all_comments)
print(all_votes)

time_to_update = 15


# print(Markup.escape('<script>'))

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS


@app.route("/", methods=['GET', 'POST'])
def index():
    global all_themes
    all_themes = Theme.query.all()
    #print(all_themes)
    for i in range(len(all_themes)):
        #print(int(time.time())-all_themes[i].date)
        #print(all_themes[i].relevant)
        if all_themes[i].relevant and int(time.time()) - all_themes[i].date > time_to_update:
            print('CHANGING')
            all_themes[i].rating -= 5
            all_themes[i].relevant = 0
    all_themes.sort(key=lambda x: x.rating, reverse=True)
    if request.method == 'GET':
        return render_template('index.html', all_themes=all_themes)
    elif session.get('is_logged_in', False) and request.method == 'POST':
        theme = Markup.escape(request.form.get('theme')) if request.form.get('theme') else None
        description = Markup.escape(request.form.get('description')) if request.form.get('description') else None
        if theme and description:
            check_theme = Theme.query.filter_by(theme=theme).first()
            check_description = Theme.query.filter_by(description=description).first()
            if not check_theme and not check_description:
                new_theme = Theme(theme=theme, description=description)
                db.session.add(new_theme)
                db.session.commit()
                flash('Successfully added new theme')
                return redirect('/' + theme)
            else:
                if check_theme:
                    flash('There is theme with such name')
                    return redirect('/')
                else:
                    flash('There is theme with such description')
                    return redirect('/')
        else:
            flash('All fields are required')
            return redirect('/')
    else:
        redirect('/')


@app.route("/login", methods=['GET', 'POST'])
def login():
    if session.get('is_logged_in', False):
        return redirect('/')
    if request.method == 'GET':
        return render_template('login.html')
    else:
        if session.get('is_logged_in', False):
            flash('You are already logged in')
            return redirect('/')
        else:
            login = Markup.escape(request.form.get('login')) if request.form.get('login') else None
            password = Markup.escape(request.form.get('password')) if request.form.get('password') else None
            hashed_password = bcrypt.hashpw(base64.b64encode(hashlib.sha256(password.encode()).digest()), salt=salt)
            query_with_email = User.query.filter_by(email=login).first()
            query_with_login = User.query.filter_by(login=login).first()
            # print(query_with_email)
            # print(query_with_login)
            if query_with_email:
                if query_with_email.password == hashed_password:
                    session['id'] = query_with_email.id
                    session['login'] = query_with_email.login
                    session['is_logged_in'] = True
                    flash('Successfully logged in')
                    return redirect('/')
                else:
                    flash('Incorrect credentials')
                    return redirect('/login')
            if query_with_login:
                if query_with_login.password == hashed_password:
                    session['id'] = query_with_login.id
                    session['login'] = query_with_login.login
                    session['is_logged_in'] = True
                    flash('Successfully logged in')
                    return redirect('/')
                else:
                    flash('Incorrect credentials')
                    return redirect('/login')
            flash('Incorrect credentials')
            return redirect('/login')


@app.route("/signup", methods=['GET', 'POST'])
def signup():
    if session.get('is_logged_in', False):
        return redirect('/')
    if request.method == 'GET':
        return render_template('signup.html')
    login = Markup.escape(request.form.get('login')) if request.form.get('login') else None
    email = Markup.escape(request.form.get('email')) if request.form.get('email') else None
    password = Markup.escape(request.form.get('password')) if request.form.get('password') else None
    password_confirm = Markup.escape(request.form.get('password_confirm')) if request.form.get('password_confirm') else None
    if login and email and password and password_confirm:
        print(login, email, password, password_confirm)
        if password != password_confirm:
            flash('Passwords are not same, please, try to register again')
            return redirect('/signup')
        else:
            hashed_password = bcrypt.hashpw(base64.b64encode(hashlib.sha256(password.encode()).digest()), salt=salt)
            new_user = User(login=login, password=hashed_password, email=email)
            check_login = User.query.filter_by(login=new_user.login).all()
            print(check_login)
            if len(check_login) == 0:
                check_email = User.query.filter_by(email=new_user.email).all()
                print(check_email)
                if len(check_email) == 0:
                    db.session.add(new_user)
                    db.session.commit()
                    app.logger.info((User.query.filter_by().all()))
                    session['id'] = new_user.id
                    session['login'] = new_user.login
                    session['is_logged_in'] = True
                    print(check_login)
                    flash('Successfully registered')
                    return redirect('/')
                else:
                    flash('There is user with such email, try new one')
                    return redirect('/signup')
            else:
                flash('There is user with such login, try new one')
                return redirect('/signup')
    else:
        flash('All fields are required')
        return redirect('/signup')


@app.route('/settings', methods=['GET', 'POST'])
def settings():
    if request.method == 'GET' and session.get('is_logged_in', False):
        return render_template('settings.html')
    elif request.method == 'GET':
        flash('Log in to access this page')
        return redirect('/login')
    elif request.method == 'POST' and session.get('is_logged_in', False):
        new_nickname = Markup.escape(request.form.get('new_nickname')) if request.form.get('new_nickname') else None
        old_email = Markup.escape(request.form.get('old_email')) if request.form.get('old_email') else None
        new_email = Markup.escape(request.form.get('new_email'))if request.form.get('new_email') else None
        confirm_email = Markup.escape(request.form.get('confirm_email')) if request.form.get('confirm_email') else None
        old_password = Markup.escape(request.form.get('old_password')) if request.form.get('old_password') else None
        new_password = Markup.escape(request.form.get('new_password')) if request.form.get('new_password') else None
        confirm_password = Markup.escape(request.form.get('confirm_password')) if request.form.get('confirm_password') else None
        if new_nickname:
            user = User.query.filter_by(login=session['login']).first()
            is_available = User.query.filter_by(login=new_nickname).first()
            if not is_available:
                user.login = new_nickname
                db.session.commit()
                session['login'] = new_nickname
                app.logger.info((User.query.all()))
                flash('Settings were successfully changed')
                return redirect('/')
            else:
                flash('This nickname is not available')
                return redirect('/settings')
        elif old_email and new_email and confirm_email:
            if new_email != confirm_email:
                flash('Emails are not the same')
                return redirect('/settings')
            else:
                user = User.query.filter_by(login=session['login']).first()
                is_available = User.query.filter_by(email=new_email).first()
                print(user.email,old_email)
                if user.email != old_email:
                    flash('Incorrect old email')
                    return redirect('/settings')
                else:
                    if not is_available:
                        user.email = new_email
                        db.session.commit()
                        app.logger.info((User.query.filter_by().all()))
                        flash('Settings were successfully changed')
                        return redirect('/')
                    else:
                        flash('This email is not available')
                        return redirect('/settings')
        elif old_password and new_password and confirm_password:
            user = User.query.filter_by(login=session['login']).first()
            if new_password != confirm_password:
                flash('Passwords are not the same')
                return redirect('/settings')
            else:
                hashed_old_password = bcrypt.hashpw(base64.b64encode(hashlib.sha256(old_password.encode()).digest()), salt=salt)
                if user.password != hashed_old_password:
                    flash('Incorrect old password')
                    return redirect('/settings')
                else:
                    hashed_new_password = bcrypt.hashpw(base64.b64encode(hashlib.sha256(new_password.encode()).digest()),
                                                        salt=salt)
                    user.password = hashed_new_password
                    db.session.commit()
                    app.logger.info((User.query.filter_by().all()))
                    flash('Settings were successfully changed')
                    return redirect('/')
        else:
            flash('All fields in the form are required')
            return redirect('/settings')
    else:
        flash('Log in to access this page')
        return redirect('/login')


@app.route('/<req_theme>', methods=['GET', 'POST'])
def theme(req_theme):
    theme = Theme.query.filter_by(theme=req_theme).first()
    if theme:
        # print(theme)
        if theme.relevant and int(time.time()) - theme.date > time_to_update:
            print('CHANGING')
            theme.rating -= 5
            theme.relevant = 0
        all_comments_for_theme = Comment.query.filter_by(theme_id=theme.id).all()
        # print(all_comments_for_theme)
        if request.method == 'GET':
            return render_template('theme.html', theme=theme, all_comments_for_theme=all_comments_for_theme)
        else:
            if not session['is_logged_in']:
                return redirect('/login')
            comment = Markup.escape(request.form.get('comment')) if request.form.get('comment') else None
            up = request.form.get('up')
            down = request.form.get('down')
            file = request.files.get('image', False)
            # print(request.files)
            # print(request.form)
            filename = ''
            print(file)
            if up or down:
                check = Vote.query.filter_by(theme_id=theme.id, vote_author=session['login']).first()
                if not check:
                    coef = 1
                    if up:
                        theme.rating += coef
                        new_vote = Vote(theme_id=theme.id, vote_author=session['login'], up_down=coef)
                        db.session.add(new_vote)
                        db.session.commit()
                    else:
                        theme.rating -= coef
                        new_vote = Vote(theme_id=theme.id, vote_author=session['login'], up_down=-coef)
                        db.session.add(new_vote)
                        db.session.commit()
                    flash('Successfully voted')
                    return redirect('/' + req_theme)
                else:
                    flash('You have already voted')
                    return redirect('/' + req_theme)
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                print(filename)
                print(path)
                file.save(path)
            if comment:
                theme_id = theme.id
                new_comment = Comment(theme_id=theme_id, author=session['login'], comment=comment, image_path=filename)
                print(new_comment)
                db.session.add(new_comment)
                db.session.commit()
                flash('Successfully added new comment')
                return redirect('/' + req_theme)
            else:
                flash('All fields are required')
                return redirect('/' + req_theme)
    else:
        abort(404)


@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


@app.route('/logout')
def logout():
    session['is_logged_in'] = False
    return redirect('/')


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8000, debug=True)

    # db.create_all()
# user = User(login='asfdasfdasdf',password='afdsadsfafds',email='afsdsfadasfd@mail.ru')
# db.session.add(user)
# db.session.commit()
# print(User.query.all())
