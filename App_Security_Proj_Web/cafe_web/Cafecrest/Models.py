from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.sql import func

db = SQLAlchemy()


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    firstn = db.Column(db.String(50), nullable=False)
    lastn = db.Column(db.String(50), nullable=False)
    mobile = db.Column(db.String(8), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(170), nullable=False)
    Key = db.Column(db.LargeBinary, nullable=True)
    role = db.Column(db.String(5), nullable=False)
    login_attempts = db.Column(db.Integer, default=0)
    lockout_time = db.Column(db.DateTime, nullable=True)

    def __repr__(self):
        return f"User('{self.username}', '{self.firstn}', '{self.lastn}', '{self.mobile}' ,'{self.email}', '{self.role}', '{self.login_attempts}', '{self.lockout_time}')"


class Log(db.Model):
    __tablename__ = 'logs'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    message = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.TIMESTAMP, server_default=func.current_timestamp(), nullable=True)


class Payment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    card_number = db.Column(db.String(130), nullable=False)
    expiration_date = db.Column(db.String(10), nullable=False)
    cvv = db.Column(db.String(130), nullable=False)
    card_name = db.Column(db.String(50), nullable=False)
    username = db.Column(db.String(130), db.ForeignKey('user.username'), nullable=False)

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


class Feed_back(db.Model):
    __tablename__ = 'feedback'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50))
    mobile_no = db.Column(db.String(15))
    service = db.Column(db.String(70))
    food = db.Column(db.String(70))
    feedback = db.Column(db.Text)


class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.String(36), unique=True, nullable=False)
    username = db.Column(db.String(50), db.ForeignKey('user.username'), nullable=False)
    collection_type = db.Column(db.String(50), nullable=False)
    items = db.relationship('OrderItem', backref='order', lazy=True, cascade="all, delete-orphan")
    grand_total = db.Column(db.Float, nullable=True)
    created_at = db.Column(db.DateTime, default=db.func.now())

    def __repr__(self):
        return f'<Order {self.order_id}>'


class OrderItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.String(36), db.ForeignKey('order.order_id'), nullable=False)
    item_name = db.Column(db.String(100), nullable=False)
    item_price = db.Column(db.Float, nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    collection_type = db.Column(db.String(50), nullable=False)
    image_path = db.Column(db.String(255))

    def __repr__(self):
        return f'<OrderItem {self.item_name} (Order {self.order_id})>'


class UserPoints(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), db.ForeignKey('user.username'), nullable=False)
    points = db.Column(db.Integer, default=0)

    def __repr__(self):
        return f"<UserPoints {self.username} - {self.points}>"
