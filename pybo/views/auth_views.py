from flask import Blueprint, url_for, request, render_template, flash, session, g
from werkzeug.utils import redirect
from werkzeug.security import generate_password_hash, check_password_hash
from ..forms import UserCreateForm, LoginForm

from pybo.models import User
from pybo import db

import functools

bp = Blueprint('auth', __name__, url_prefix='/auth')

@bp.route('/signup/', methods=('GET', 'POST'))
def signup():
    form = UserCreateForm()
    if request.method == 'POST' and form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if not user:
            user = User(
                username=form.username.data,
                password=generate_password_hash(form.password1.data),
                email=form.email.data
            )
            db.session.add(user)
            db.session.commit()
            return redirect(url_for('main.index'))
        else:
            flash('이미 존재하는 사용자입니다.')
    return render_template('auth/signup.html', form=form)

@bp.route('/login/', methods=('GET', 'POST'))
def login():
    form = LoginForm()
    if request.method == 'POST' and form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if not user:
            flash('존재하지 않는 사용자입니다.')
        elif not check_password_hash(user.password, form.password.data):
            flash('비밀번호가 올바르지 않습니다.')
        else:
            session.clear()
            session['user_id'] = user.id
            return redirect(url_for('main.index'))
    return render_template('auth/login.html', form=form)


@bp.route('/logout/', methods=('GET',))
def logout():
    session.clear()
    return redirect(url_for('main.index'))


@bp.before_app_request
def load_logged_in_user():
    user_id = session.get('user_id')
    if user_id is None:
        g.user = None
    else:
        g.user = User.query.get(user_id)

def login_required(view):
    @functools.wraps(view)
    def wrapped_view(*args, **kwargs):
        if g.user is None:
            return redirect(url_for('auth.login'))
        return view(*args, **kwargs)
    return wrapped_view