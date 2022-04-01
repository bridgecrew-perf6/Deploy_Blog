import werkzeug.security
from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Table, Column, Integer, ForeignKey, String, Text
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegistertForm, LogForm, CommentForm
from flask_gravatar import Gravatar
from functools import wraps
from dotenv import load_dotenv
import os

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")
ckeditor = CKEditor(app)
Bootstrap(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# CREATE LOGIN INSTANCE
login_manager= LoginManager()
login_manager.init_app(app)
# sent the user to the "name_page_function", here "login" if not log in
login_manager.login_view = "login"

# INITIALIZE GRAVATAR
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

#CONFIGURE TABLES

Base = declarative_base()


class User(UserMixin, db.Model, Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String(100), nullable=False, unique=True)
    password = Column(String(100), nullable=False)
    name = Column(String(1000), nullable=False)
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="commentator")

class BlogPost(db.Model, Base):
    __tablename__ = "blog_posts"
    id = Column(Integer, primary_key=True)
    title = Column(String(250), unique=True, nullable=False)
    subtitle = Column(String(250), nullable=False)
    date = Column(String(250), nullable=False)
    body = Column(Text, nullable=False)
    img_url = Column(String(250), nullable=False)
    author_id = Column(Integer, ForeignKey("users.id"))
    author = relationship("User", back_populates="posts")
    blog_comments = relationship("Comment", back_populates="blog")

class Comment(db.Model, Base):
    __tablename__ = "comments"
    id = Column(Integer, primary_key=True)
    text = Column(String(400), nullable=False)
    commentator_id = Column(Integer, ForeignKey("users.id"))
    commentator = relationship("User", back_populates="comments")
    blog_id = Column(Integer, ForeignKey("blog_posts.id"))
    blog = relationship("BlogPost", back_populates="blog_comments")

# db.create_all()

# CREATE A SESSION FOR THE LOGGED USER
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def only_admin(function):
    @wraps(function)
    def wrapper_function(*args, **kwargs):
        try:
            user_id = int(current_user.get_id())
        except AttributeError:
            return abort(403)
        except TypeError:
            return abort(403)
        else:
            if user_id == 1:
                return function(*args, **kwargs)
            else:
                return abort(403)
    return wrapper_function


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    is_admin = False
    if current_user.is_authenticated:
        user_id = int(current_user.get_id())
        if user_id == 1:
            is_admin = True
    return render_template("index.html",
                           all_posts=posts,
                           logged_in=current_user.is_authenticated,
                           is_admin=is_admin
                           )


@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegistertForm()
    if form.validate_on_submit():
        new_user_email = form.email.data
        search_email = User.query.filter_by(email=new_user_email).first()
        if search_email == None:
            new_user = User(
                email=form.email.data,
                password=werkzeug.security.generate_password_hash(
                    password=form.password.data,
                    method="pbkdf2:sha256",
                    salt_length=8
                ),
                name=form.name.data.title()
            )
            db.session.add(new_user)
            db.session.commit()
            flash("You have successfully registered !")
            search_email = User.query.filter_by(email=new_user_email).first()
            login_user(search_email)
            return redirect(url_for("get_all_posts"))
        else:
            flash("You have already registered with this email! Log in instead!")
            return redirect(url_for("login"))
    return render_template("register.html", form=form)


@app.route('/login', methods=["GET", "POST"])
def login():
    form = LogForm()
    if form.validate_on_submit():
        user_email = form.email.data
        search_user = User.query.filter_by(email=user_email).first()
        if search_user:
            if check_password_hash(search_user.password, form.password.data):
                login_user(search_user)
                return redirect(url_for("get_all_posts"))
            else:
                flash("Your password is incorrect!")
                return redirect(url_for("login"))
        else:
            flash("Your email is not registered yet!")
            return redirect(url_for("login"))
    else:
        return render_template("login.html", form=form, logged_in=current_user.is_authenticated)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
@login_required
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    is_admin = False
    form = CommentForm()
    if current_user.is_authenticated:
        user_id = int(current_user.get_id())
        if user_id == 1:
            is_admin = True
    if form.validate_on_submit():
        new_comment = Comment(
            text=form.comment.data,
            commentator=current_user,
            blog=requested_post
        )
        db.session.add(new_comment)
        db.session.commit()
    return render_template("post.html",
                           post=requested_post,
                           logged_in=current_user.is_authenticated,
                           is_admin=is_admin,
                           form=form
                           )


@app.route("/about")
def about():
    return render_template("about.html", logged_in=current_user.is_authenticated)


@app.route("/contact")
def contact():
    return render_template("contact.html", logged_in=current_user.is_authenticated)


@app.route("/new-post", methods=["GET", "POST"])
@only_admin
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, logged_in=current_user.is_authenticated)


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@only_admin
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form, logged_in=current_user.is_authenticated)


@app.route("/delete/<int:post_id>")
@only_admin
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))

if __name__ == "__main__":
    app.run(debug=True)
