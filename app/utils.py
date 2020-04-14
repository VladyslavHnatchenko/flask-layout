from . import mail, db
from flask import render_template
from threading import Thread
from app import app
from flask_mail import Message


def async_send_mail(app, msg):
    with app.app_context():
        mail.send(msg)


def send_mail(subject, recipient, template, **kwargs):
    msg = Message(subject, sender=app.config['MAIL_DEFAULT_SENDER'],  recipients=[recipient])
    msg.html = render_template(template, **kwargs)
    thread_ = Thread(target=async_send_mail, args=[app,  msg])
    thread_.start()
    return thread_
