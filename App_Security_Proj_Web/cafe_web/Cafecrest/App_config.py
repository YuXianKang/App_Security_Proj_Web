from datetime import timedelta


class Config(object):
    SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://cafecrest:Oscar1oscar1@localhost/cafecrest'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SECRET_KEY = 'Cafe_@_Crest'
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=7)
    SESSION_PERMANENT = False
    SESSION_COOKIE_SAMESITE = 'Lax'
    SESSION_COOKIE_SECURE = True


config = Config()
