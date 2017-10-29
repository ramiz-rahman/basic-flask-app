from datetime import datetime
from flask import render_template, session, redirect, url_for, current_app, abort
from . import main
from .. import db, moment
from ..models import User
from ..email import send_email


@main.route('/', methods=['GET', 'POST'])
def index():
    return render_template('index.html')
    
@main.route('/user/<username>')
def user(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        abort(404)
    return render_template('user.html', user=user)