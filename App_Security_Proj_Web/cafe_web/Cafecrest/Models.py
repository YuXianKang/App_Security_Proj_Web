from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'pdf', 'webp'}
UPLOAD_FOLDER = 'static'


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    firstn = db.Column(db.String(50), nullable=False)
    lastn = db.Column(db.String(50), nullable=False)
    mobile = db.Column(db.String(8), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    Key = db.Column(db.LargeBinary, nullable=True)
    role = db.Column(db.String(5), nullable=False)
    login_attempts = db.Column(db.Integer, default=0)
    lockout_time = db.Column(db.DateTime, nullable=True)

    def __repr__(self):
        return f"User('{self.username}', '{self.firstn}', '{self.lastn}', '{self.mobile}' ,'{self.email}', '{self.role}', '{self.login_attempts}', '{self.default_time}')"


class Payment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    card_number = db.Column(db.String(16), nullable=False)
    expiration_date = db.Column(db.String(10), nullable=False)
    cvv = db.Column(db.String(3), nullable=False)
    card_name = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(20), db.ForeignKey('user.username'), nullable=False)

    def __repr__(self):
        return f"<Payment(card_number={self.card_number}, expiration_date={self.expiration_date}, cvv={self.cvv}, card_name={self.card_name})>"


class Product(db.Model):
    __tablename__ = "prds"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    product = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    price = db.Column(db.Integer, nullable=False)
    photos = db.Column(db.Text, nullable=False)

    def __init__(self, name, product, description, price, photos):
        self.name = name
        self.product = product
        self.description = description
        self.photos = photos
        self.price = price

    def set_product_id(self, value):
        self.id = value

    def get_product_id(self):
        return self.id

    def get_name(self):
        return self.name

    def set_name(self, value):
        self.name = value

    def get_price(self):
        return self.price

    def set_price(self, value):
        self.price = value

    def get_product(self):
        return self.product

    def set_product(self, value):
        self.product = value

    def get_description(self):
        return self.description

    def set_description(self, value):
        self.description = value

    def get_photos(self):
        return self.photos

    def set_photos(self, photos):
        self.photos = photos.filename
        self.save()


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


class Feed_back(db.Model):
    __tablename__ = 'feedback'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    mobile_no = db.Column(db.String(15))
    service = db.Column(db.String(50))
    food = db.Column(db.String(50))
    feedback = db.Column(db.Text)


class Order(db.Model):
    id = db.Column(db.String(64), primary_key=True)
    username = db.Column(db.String(20), nullable=False)
    order_data = db.Column(db.String(120), nullable=False)
    items = db.Column(db.String(500), nullable=False)
    total = db.Column(db.Float, nullable=False)

    def __repr__(self):
        return f"Order('{self.items}')"


class UserPoints(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), db.ForeignKey('user.username'), nullable=False)
    points = db.Column(db.Integer, default=0)

    def __repr__(self):
        return f"<UserPoints {self.username} - {self.points}>"
