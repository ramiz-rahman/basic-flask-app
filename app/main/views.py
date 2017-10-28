from datetime import datetime
from flask import render_template, session, redirect, url_for, current_app, abort
from . import main
from .. import db
from ..models import User
from ..email import send_email


@main.route('/', methods=['GET', 'POST'])
def index():
    return render_template('index.html')
    