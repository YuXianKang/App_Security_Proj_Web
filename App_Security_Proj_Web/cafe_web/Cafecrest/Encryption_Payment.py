from flask import session
from cryptography.fernet import Fernet
from Models import User


def encrypt_data(data):
    user = User.query.filter_by(username=session['username']).first()

    if user and user.Key:
        cipher_suite = Fernet(user.Key)
        cipher_text = cipher_suite.encrypt(data.encode())
        return cipher_text


def decrypt_data(encrypted_data):
    user = User.query.filter_by(username=session['username']).first()

    if user and user.Key:
        cipher_suite = Fernet(user.Key)
        plain_text = cipher_suite.decrypt(encrypted_data).decode()
        return plain_text
