from datetime import date
from tokenize import Comment

from flask import Flask, abort, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user, login_manager, login_required
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Text, ForeignKey
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
# Import your forms from the forms.py
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap5(app)

# TODO: Configure Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


# CREATE DATABASE
class Base(DeclarativeBase):
    pass
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///posts.db'
db = SQLAlchemy(model_class=Base)
db.init_app(app)


# CONFIGURE TABLES
class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    subtitle: Mapped[str] = mapped_column(String(250), nullable=False)
    date: Mapped[str] = mapped_column(String(250), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    img_url: Mapped[str] = mapped_column(String(250), nullable=False)

    author_id: Mapped[int] = mapped_column(
        ForeignKey("blog_users.id"),
        nullable=False
    )
    author: Mapped["BlogUser"] = relationship(back_populates="posts")

    comments: Mapped[list["CommentPost"]] = relationship(
        back_populates="post",
        cascade="all, delete-orphan"
    )

class BlogUser(UserMixin, db.Model):
    __tablename__ = "blog_users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(250), nullable=False)
    email: Mapped[str] = mapped_column(String(250), nullable=False)
    password: Mapped[str] = mapped_column(String(250), nullable=False)

    posts: Mapped[list["BlogPost"]] = relationship(
        back_populates="author",
        cascade="all, delete-orphan"
    )

    comments: Mapped[list["CommentPost"]] = relationship(
        back_populates="author",
        cascade="all, delete-orphan"
    )

class CommentPost(db.Model):
    __tablename__ = "comment"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    text: Mapped[str] = mapped_column(Text, nullable=False)

    author_id: Mapped[int] = mapped_column(
        ForeignKey("blog_users.id"),
        nullable=False
    )
    author: Mapped["BlogUser"] = relationship(back_populates="comments")

    post_id: Mapped[int] = mapped_column(
        ForeignKey("blog_posts.id"),
        nullable=False
    )
    post: Mapped["BlogPost"] = relationship(back_populates="comments")


with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    try:
        return db.session.get(BlogUser, int(user_id))
    except ValueError:
        return None

class RegisterUser:
    def __init__(self, db_session):
        self.db_session = db_session

    def register_user(self, email: str, password: str, name: str) -> BlogUser:
        email = (email or "").strip().lower()
        name = (name or "").strip()
        password = password or ""

        existing = (self.db_session.
                    query(BlogUser).
                    filter_by(email=email).
                    first())
        if existing:
            raise ValueError("This email is already registered")

        hashed = generate_password_hash(password,
                                        method='pbkdf2:sha256',
                                        salt_length=16)

        user = BlogUser(email=email,
                        username=name,
                        password=hashed)
        self.db_session.add(user)
        self.db_session.commit()
        return user

def admin_only():
    if not current_user.is_authenticated or current_user.id != 1:
        abort(403)

@app.route('/register', methods=['GET','POST'])
def register():
    form = RegisterForm()
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        name = request.form.get('name')

        service = RegisterUser(db.session)

        try:
            user = service.register_user(
                email=email,
                password=password,
                name=name)
            login_user(user)
            return redirect(url_for('get_all_posts'))
        except ValueError as e:
            flash(str(e))
            return redirect(url_for('login'))
    return render_template("register.html", form=form)

# TODO: Retrieve a user from the database based on their email. 
@app.route('/login', methods=['GET','POST'])
def login():
    form = LoginForm()
    if request.method == 'POST':
        email = (request.form.get('email') or "").strip().lower()
        password = request.form.get('password') or ""

        user = db.session.query(BlogUser).filter_by(email=email).first()
        if not user:
            flash("Invalid username or password")
            return redirect(url_for('login'))
        if not check_password_hash(user.password, password):
            flash("Invalid username or password")
            return redirect(url_for('login'))

        login_user(user)
        next_url = request.args.get('next')
        return redirect(next_url or url_for('get_all_posts'))

    return render_template("login.html", form = form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))

@app.route('/')
def get_all_posts():
    result = db.session.execute(db.select(BlogPost))
    posts = result.scalars().all()
    return render_template("index.html", all_posts=posts)


# TODO: Allow logged-in users to comment on posts
@app.route("/post/<int:post_id>",  methods=["GET", "POST"])
def show_post(post_id):
    requested_post = db.get_or_404(BlogPost, post_id)

    form = CommentForm()
    if form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You need to login or register to comment")
            return redirect(url_for('login', next=url_for('show_post', post_id=post_id)))

        new_comment = CommentPost(
            text = form.comment_text.data,
            author = current_user,
            post = requested_post
        )
        db.session.add(new_comment)
        db.session.commit()
        return redirect(url_for('show_post', post_id=post_id))

    return render_template("post.html", post=requested_post, form=form, current_user=current_user)

@app.route("/new-post", methods=["GET", "POST"])
@login_required
def add_new_post():
    admin_only()
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
    return render_template("make-post.html", form=form)

@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@login_required
def edit_post(post_id):
    admin_only()
    post = db.get_or_404(BlogPost, post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = current_user
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form, is_edit=True)

@app.route("/delete/<int:post_id>")
@login_required
def delete_post(post_id):
    admin_only()
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


if __name__ == "__main__":
    app.run(debug=True, port=5002)
