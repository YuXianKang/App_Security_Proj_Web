from flask import Flask, render_template, request, redirect, url_for, jsonify, flash, session, send_from_directory
from Forms import CreateFeedbackForm, CreateProductForm, payment
from ChatBot import chatbot_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from sqlalchemy.exc import IntegrityError
import payment_storage
import os
import shelve
import uuid
from Forms import payment, collection_type
from products import food, coffee, non_coffee
from Encryption_Payment import encrypt_data, decrypt_data
from datetime import timedelta

# Initialize Flask application
app = Flask(__name__)

# Configure database URI and secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=7)
app.config['SESSION_PERMANENT'] = False

# Initialize SQLAlchemy database
db = SQLAlchemy(app)

# Define allowed file extensions for uploading
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'pdf', 'webp'}
# Define upload folder for images
UPLOAD_FOLDER = 'static'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Define a dictionary containing all products
all_products = {
    **food,
    **coffee,
    **non_coffee}

# Define a global variable to store new product temporarily
new_product = None


# Define User model for the database
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    firstn = db.Column(db.String(50), nullable=False)
    lastn = db.Column(db.String(50), nullable=False)
    mobile = db.Column(db.String(8), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    role = db.Column(db.String(5), nullable=False)

    def __repr__(self):
        return f"User('{self.username}', '{self.firstn}', '{self.lastn}', '{self.mobile}' ,'{self.email}', '{self.role}')"


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


# Define a route for the home page
@app.route('/')
def home():
    return render_template('home.html')


# Define a route and method to create a staff account
@app.route('/createStaffAccount', methods=["GET", "POST"])
def create_staff_account():
    if request.method == "POST":
        try:
            # Retrieve form data
            username = request.form.get('username')
            firstn = request.form.get('firstn')
            lastn = request.form.get('lastn')
            mobile = request.form.get('mobile')
            email = request.form.get('email')
            password = request.form.get('password')
            hashed_password = generate_password_hash(password)

            # Create a new user instance
            new_user = User(username=username, firstn=firstn, lastn=lastn, mobile=mobile, email=email, password=hashed_password, role="staff")
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('home'))
        except IntegrityError:
            db.session.rollback()
            flash('Email already registered. Please log in or use a different email.')
            return redirect(url_for('login'))
    return render_template('createStaffSignUp.html')


# Route for user signup
@app.route("/createSignUp", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        try:
            # Get user input from form
            username = request.form.get('username')
            firstn = request.form.get('firstn')
            lastn = request.form.get('lastn')
            mobile = request.form.get('mobile')
            email = request.form.get('email')
            password = request.form.get('password')
            hashed_password = generate_password_hash(password)

            # Create a new user object with the provided information
            new_user = User(username=username, firstn=firstn, lastn=lastn, mobile=mobile, email=email, password=hashed_password, role="user")

            # Add the new user to the database
            db.session.add(new_user)
            db.session.commit()

            # Redirect to home page after successful signup
            return redirect(url_for('home'))

        except IntegrityError:
            # If the email already exists, rollback the session and redirect to login page
            db.session.rollback()
            flash('Email already registered. Please log in or use a different email.')
            return redirect(url_for('login'))

    return render_template('createSignUp.html')


# Route for user login
@app.route("/Login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        # Get username and password from form
        username = request.form.get('username')
        password = request.form.get('password')

        # Retrieve user from database based on username
        user = User.query.filter_by(username=username).first()

        # Check if user exists and password is correct
        if user and check_password_hash(user.password, password):
            # Set session variables based on user role
            session['username'] = user.username
            if user.username == "admin":
                session['admin'] = True
            elif user.role == "staff":
                session["staff"] = True
            elif user.role == "user":
                session['logged_in'] = True
            # Set the session cookie to be non-persistent
            response = redirect(url_for('home'))
            response.set_cookie('session', '', max_age=0, httponly=True, secure=True)
            return response
        else:
            # If login is unsuccessful, display error message
            flash('Login Unsuccessful. Please check username and password')

    # Render the login form
    return render_template('Login.html')


# Route for user logout
@app.route('/logout')
def logout():
    # Remove session data and redirect to home page
    session.clear()
    # Set the session cookie to be HTTP-only and non-persistent
    response = redirect(url_for('home'))
    response.set_cookie('session', '', max_age=0, httponly=True, secure=True)
    return response


@app.route('/check-session')
def check_session():
    if 'username' in session:
        return 'Session is active.'
    else:
        return 'No active session found.'


# Route for user account page
@app.route('/account')
def account():
    # Retrieve user data from database based on session username
    user = User.query.filter_by(username=session['username']).first()

    # If user exists, render account page
    if user:
        return render_template('account.html', user=user)
    else:
        # If user doesn't exist, redirect to home page
        return redirect(url_for('home'))


# Route for customer portal
@app.route('/customerPortal/')
def customer_portal():
    if 'username' not in session:
        flash('You must be logged in to view your account portal', 'danger')
        return redirect(url_for('login'))

    # Retrieve user data from database based on session username
    user = User.query.filter_by(username=session['username']).first()

    # If user exists, render customer portal
    if user:
        user_points = UserPoints.query.filter_by(username=session['username']).first()
        if user_points:
            user_points_value = user_points.points
        else:
            user_points_value = 0  # Default to 0 if no points record found

        user_orders_count = db.session.query(Order.id).filter_by(username=session['username']).count()

        if user_points_value >= 1000:
            user_category = "Platinum"
        elif user_points_value >= 500:
            user_category = "Gold"
        elif user_points_value != 0:
            user_category = "Silver"
        else:
            user_category = "Bronze"

        # Pass user points to the template
        return render_template('CustomerPortal.html', user=user, user_orders_count=user_orders_count, user_points_value=user_points_value, user_category=user_category)
    else:
        # If user doesn't exist, redirect to home page
        return redirect(url_for('home'))


# Route for updating user account
@app.route('/account/update', methods=['GET', 'POST'])
def update_account():
    # Retrieve user data from database based on session username
    user = User.query.filter_by(username=session['username']).first()

    if request.method == 'POST':
        # Get updated user information from form
        new_username = request.form['username']
        new_firstn = request.form['firstn']
        new_lastn = request.form['lastn']
        new_mobile = request.form['mobile']
        new_email = request.form['email']
        new_password = request.form['password']
        hashed_password = generate_password_hash(new_password)

        # Check if new username or email already exists for other users
        existing_user = User.query.filter(
            User.id != user.id,
            (User.username == new_username) | (User.firstn == new_firstn) | (User.lastn == new_lastn) | (User.mobile == new_mobile) | (User.email == new_email) | (User.password == hashed_password)
        ).first()

        if existing_user:
            # If username or email already exists, display error message
            flash('Username or email already exists.', 'error')
            return redirect(url_for('update_account'))

        # Update user information in the database
        user.username = new_username
        user.firstn = new_firstn
        user.lastn = new_lastn
        user.mobile = new_mobile
        user.email = new_email
        user.password = hashed_password

        # Update session with new username
        session['username'] = new_username

        db.session.commit()
        flash('Account successfully updated.', 'success')
        return redirect(url_for('account'))

    # Render the update account form
    return render_template('update_account.html', user=user)


# Route for deleting user account and all orders associated with the account
@app.route('/account/delete', methods=['POST'])
def delete_account():
    # Retrieve user data from database based on session username
    user = User.query.filter_by(username=session['username']).first()

    if user:
        # Query for all payment_details associated with the user
        payment_details = Payment.query.filter_by(username=user.username).all()
        # Delete all payment_details associated with the user
        for payment_detail in payment_details:
            db.session.delete(payment_detail)
        # Commit the changes to the database
        db.session.commit()

        # Query for all orders associated with the user
        orders = Order.query.filter_by(username=user.username).all()
        # Delete all orders associated with the user
        for order in orders:
            db.session.delete(order)
        # Commit the changes to the database again
        db.session.commit()

        user_points = UserPoints.query.filter_by(username=user.username).first()
        # Delete the user's points record
        if user_points:
            db.session.delete(user_points)
        db.session.commit()

        # Delete user from database
        db.session.delete(user)
        db.session.commit()

        # Remove session data and display success message
        session.pop('username', None)
        session.pop('logged_in', None)
        flash('Your account has been deleted.', 'success')
    else:
        # If user not found, display error message
        flash('User not found.', 'danger')

    # Redirect to home page
    return redirect(url_for('home'))


# Define a route and method to create a new product
@app.route('/createProduct', methods=['GET', 'POST'])
def create_product():
    # Create a form instance for creating a product
    create_product_form = CreateProductForm(request.form)
    if request.method == 'POST':
        # Retrieve file from the form
        file = request.files['photos']
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        photos = os.path.join(app.config['UPLOAD_FOLDER'], filename)

        # Create a new product instance using form data
        new_product = CreateProductForm.product(
            name=create_product_form.name.data,
            product=create_product_form.product.data,
            description=create_product_form.description.data,
            price=create_product_form.price.data,
            photos=photos
        )

        # Add the new product to the database
        db.session.add(new_product)
        db.session.commit()

        # Retrieve all products from the database
        products_list = CreateProductForm.product.query.all()
        return render_template('retrieveProduct.html', count=len(products_list), products_list=products_list)
    return render_template('createProduct.html', form=create_product_form)


# Define a route to retrieve all products
@app.route('/retrieveProducts')
def retrieve_product():
    products_list = CreateProductForm.product.query.all()
    return render_template('retrieveProduct.html', count=len(products_list), products_list=products_list)


# Define a route and method to update a product
@app.route('/updateProduct/<int:id>', methods=['GET', 'POST'])
def update_product(id):
    # Retrieve product by ID from the database
    product = CreateProductForm.product.query.get_or_404(id)
    update_product_form = CreateProductForm(obj=product)
    if request.method == 'POST' and update_product_form.validate():
        # Update product details with form data
        product.name = request.form['name']
        product.product = request.form['product']
        product.description = request.form['description']
        product.price = request.form['price']

        # If a new photo is provided, save it and update the product's photo path
        if 'photos' in request.files and request.files['photos']:
            photo_filename = secure_filename(request.files['photos'].filename)
            if photo_filename and allowed_file(photo_filename):
                request.files['photos'].save(os.path.join(app.config['UPLOAD_FOLDER'], photo_filename))
                product.photos = photo_filename

        db.session.commit()
        flash('Product updated successfully.')
        return redirect(url_for('retrieve_product'))

    return render_template('updateProduct.html', form=update_product_form, product=product)


# Define a route and method to delete a product
@app.route('/deleteProduct/<int:id>', methods=['POST'])
def delete_product(id):
    product = CreateProductForm.product.query.get_or_404(id)
    db.session.delete(product)
    db.session.commit()

    # Remove the associated photo file
    photo_path = os.path.join(app.config['UPLOAD_FOLDER'], product.photos)
    if os.path.exists(photo_path):
        os.remove(photo_path)

    flash('Product deleted successfully.')
    return redirect(url_for('retrieve_product'))


# Define a route to serve static files
@app.route('/static/<path:filename>')
def serve_image(filename):
    return send_from_directory('static', filename)


@app.route('/payment_details', methods=['GET', 'POST'])
def create_payment():
    if 'username' not in session:
        flash('You must be logged in to add payment details.', 'danger')
        return redirect(url_for('login'))

    user = User.query.filter_by(username=session['username']).first()
    if user:
        form = payment(request.form)
        # Create an instance of the payment form
        if request.method == 'POST' and form.validate():

            encrypted_card_num = encrypt_data(form.card_number.data)
            encrypted_cvv = encrypt_data(form.cvv.data)

            new_payment = Payment(username=session["username"], card_number=encrypted_card_num, expiration_date=form.expiration_date.data, cvv=encrypted_cvv, card_name=form.card_name.data)
            db.session.add(new_payment)
            db.session.commit()

            flash('Payment details added successfully.', 'success')
            return redirect(url_for('retrieve_payment'))
        return render_template('payment_details.html', form=form)


# Define a route for retrieving payment details
@app.route('/retrieve_payment')
def retrieve_payment():
    if 'username' not in session:
        flash('You must be logged in to add payment details.', 'danger')
        return redirect(url_for('login'))
    # Query the database for payment records associated with the current user
    payments = Payment.query.filter_by(username=session['username']).all()

    # Prepare the payment details for rendering
    payment_details_list = []
    for payment in payments:
        # Decrypt the card number before masking & CVV
        decrypted_card_number = decrypt_data(payment.card_number)
        decrypted_cvv = decrypt_data(payment.cvv)
        # Format the credit card number to show only the last 4 digits and mask the rest
        total_digits = len(decrypted_card_number)
        last_four_digits = decrypted_card_number[-4:]
        remaining_digits_masked = "*" * (total_digits - 4)
        formatted_card_number = f"{remaining_digits_masked}{last_four_digits}"

        payment_details_list.append({
            'id': payment.id,
            'card_number': formatted_card_number,
            'expiration_date': payment.expiration_date,
            'cvv': decrypted_cvv,
            'card_name': payment.card_name})

    # Render the payment details retrieval page
    return render_template('view_payment_details.html', count=len(payment_details_list), payment_details_list=payment_details_list)


@app.route('/update_payment/<int:id>/', methods=['POST', 'GET'])
def update_payment(id):
    if request.method == 'POST':
        form = Payment(request.form)

        # Retrieve the payment record to update
        payment = Payment.query.get(id)

        # Update the payment details
        payment.card_number = form.card_number.data
        payment.expiration_date = form.expiration_date.data
        payment.cvv = form.cvv.data
        payment.card_name = form.card_name.data

        db.session.commit()

        flash("Payment details updated successfully", "success")
        return redirect(url_for('retrieve_payment'))  # Assuming retrieve_payment is a valid endpoint
    else:
        # Retrieve the payment record to pre-fill the form
        payment = Payment.query.get_or_404(id)
        form = Payment(card_number=payment.card_number, expiration_date=payment.expiration_date,  cvv=payment.cvv,  card_name=payment.card_name)

    return render_template('update_payment_details.html', form=form, id=id)


# Define a route for deleting payment details
@app.route('/delete_payment/<int:id>', methods=['POST'])
def delete_payment(id):
    payment = Payment.query.get(id)
    db.session.delete(payment)
    db.session.commit()
    flash("Payment details deleted successfully", "success")
    return redirect(url_for('retrieve_payment'))


# Define a route for selecting order collection type
@app.route('/order', methods=['POST', 'GET'])
def order_collection():
    # Create an instance of the collection type form
    collection_Type = collection_type(request.form)
    session['started_order_process'] = True

    # Check if the form is submitted and valid
    if request.method == 'POST' and collection_Type.validate():
        # Generate a unique order ID using UUID
        order_id = str(uuid.uuid4())
        order_data = {
            'order_id': order_id,
            'collection_type': collection_Type.collection_type.data
        }

        # Store order data in the order database
        with shelve.open('order.db', 'c') as db:
            orders = db.get('orders', {})
            orders[order_id] = order_data
            db['orders'] = orders

        # Initialize an empty cart for the order in the cart database
        with shelve.open('order.db', 'c') as db:
            cart = db.get('cart', {})
            cart[order_id] = []
            db['cart'] = cart

        # Redirect to the product page
        return redirect(url_for('show_products'))

    # Render the order collection type form
    return render_template('order_collection.html', form=collection_Type)


@app.route('/products', endpoint='show_products')
def show_products():
    try:
        # Retrieve the order details from the shelves database
        with shelve.open('order.db', 'c') as order_db:
            orders = order_db.get('orders', {})

            # Check if there are any orders
            if not orders:
                return render_template('error.html', error_message="Order not found")

            # Retrieve the last order ID (or choose the appropriate order ID based on your logic)
            order_id = list(orders.keys())[-1]  # Assuming you want the latest order, adjust as needed

            # Retrieve the cart from the shelves database
            cart = order_db.get('cart', {})
            order_cart = cart.get(order_id, [])

        return render_template('products.html', food=food, coffee=coffee, non_coffee=non_coffee, cart=order_cart)

    except Exception as e:
        # You can customize the error template or redirect to an error page
        return render_template('error.html', error_message=f"An error occurred: {str(e)}")


# Define a route for adding products to the cart
@app.route('/add_to_cart/<product_id>', methods=['POST'], endpoint='add_to_cart')
def add_to_cart(product_id):
    # Retrieve the selected product from the products dictionary
    product = all_products.get(product_id)

    # Check if the product exists
    if not product:
        flash("Product not found", "error")
        return redirect(url_for('show_products'))

    # Retrieve order details from the shelve database
    order_db = shelve.open('order.db', 'r')
    orders = order_db.get('orders', {})

    # Check if there are any orders
    if not orders:
        flash("Order not found", "error")
        order_db.close()
        return redirect(url_for('home'))

    # Retrieve the last order ID (or choose the appropriate order ID based on your logic)
    order_id = list(orders.keys())[-1]  # Assuming you want the latest order, adjust as needed
    collection_types = orders[order_id]['collection_type']
    order_db.close()

    # Create an item to be added to the cart
    item = {
        'product_id': product_id,
        'name': product['name'],
        'price': product['price'],
        'quantity': int(request.form['quantity']),
        'order_id': order_id,
        'collection_type': collection_type,
        'image_path': product['image_path']
    }

    try:
        # Retrieve or initialize the cart from the shelves database
        cart_db = shelve.open('order.db', 'c')
        cart = cart_db.get('cart', {})
        order_cart = cart.get(order_id, [])

        # Check if the item is already in the cart
        for existing_item in order_cart:
            if existing_item['name'] == item['name']:
                # If yes, update the quantity
                existing_item['quantity'] += item['quantity']
                break
        else:
            # If not, add the item to the order cart
            order_cart.append(item)

        # Update the cart in the shelves database
        cart[order_id] = order_cart
        cart_db['cart'] = cart
        cart_db.close()

        flash("Product added to cart successfully", "success")
        return redirect(url_for('show_products'))
    except Exception as e:
        app.logger.error(f"Error in adding product to cart: {str(e)}")
        flash("An error occurred while adding the product to your cart. Please try again later.", "error")
        return redirect(url_for('home'))


def calculate_subtotal(cart):
    subtotal = 0
    for item in cart:
        if isinstance(item, dict) and 'quantity' in item and 'price' in item:
            subtotal += item['quantity'] * item['price']
    subtotal = round(subtotal, 2)
    return subtotal


def calculate_sales_tax(subtotal):
    return round(0.09 * subtotal, 2)


def calculate_delivery_amount(collection_types):
    return 5 if collection_types == 'delivery' else 0


def calculate_grand_total(subtotal, sales_tax, delivery_amount, collection_types):
    if collection_types == 'delivery':
        return round(subtotal + sales_tax + delivery_amount, 2)
    else:
        return round(subtotal + sales_tax, 2)


# Define a route for viewing the cart
@app.route('/view_cart')
def view_cart():
    try:
        # Retrieve order details from the shelves database
        with shelve.open('order.db', 'r') as order_db:
            orders = order_db.get('orders', {})

            # Check if there are any orders
            if not orders:
                return "Order not found"

            # Retrieve the last order ID
            order_id = list(orders.keys())[-1]
            collection_types = orders[order_id]['collection_type']

            # Retrieve the cart from the shelves database
            cart = order_db.get('cart', {})

            # Retrieve the order cart from the cart
            order_cart = cart.get(order_id, [])

            # Calculate various totals for rendering in the template
            subtotal = calculate_subtotal(order_cart)
            sales_tax = calculate_sales_tax(subtotal)
            delivery_amount = calculate_delivery_amount(collection_types)
            grand_total = calculate_grand_total(subtotal, sales_tax, delivery_amount, collection_types)

        # Render the cart view page
        return render_template('view_cart.html', cart=order_cart, subtotal=subtotal, sales_tax=sales_tax,
                               delivery_amount=delivery_amount, grand_total=grand_total)

    except Exception as e:
        return f"An error occurred: {str(e)}"


# Define a route for updating the quantity of a cart item
@app.route('/update_cart_item/<product_id>', methods=['POST', 'GET'])
def update_cart_item(product_id):
    try:
        # Retrieve order details from the shelves database
        order_db = shelve.open('order.db', 'r')
        orders = order_db.get('orders', {})

        # Check if there are any orders
        if not orders:
            flash("Order not found", "error")
            order_db.close()
            return redirect(url_for('home'))

        # Retrieve the last order ID
        order_id = list(orders.keys())[-1]  # Assuming you want the latest order
        order_db.close()

        # Check if order details are available
        if not order_id:
            flash("Order not found", "error")
            return redirect(url_for('home'))

        # Retrieve new quantity from the form
        new_quantity = request.form.get('quantity', '0')
        try:
            # Convert the new_quantity to an integer
            new_quantity = int(new_quantity)
        except ValueError:
            flash("Invalid quantity value", "error")
            return redirect(url_for('view_cart'))

        # Open the shelves database for cart update
        cart_db = shelve.open('order.db', 'c')
        cart = cart_db.get('cart', {})

        # Update the quantity of the specified product in the cart
        for item in cart.get(order_id, []):
            if item['product_id'] == product_id:
                item['quantity'] = new_quantity

        # Save the updated cart back to the database
        cart_db['cart'] = cart
        cart_db.close()

    except Exception as e:
        return f"An error occurred: {str(e)}"

    return redirect(url_for('view_cart'))


# Define a route for removing a product from the cart
@app.route('/remove_from_cart/<product_id>', methods=['POST'])
def remove_from_cart(product_id):
    try:
        # Retrieve order details from the shelves database
        with shelve.open('order.db', 'r') as order_db:
            orders = order_db.get('orders', {})

            # Check if there are any orders
            if not orders:
                # You can customize the error handling, such as redirecting to an error page
                return redirect(url_for('home'))

            # Retrieve the last order ID
            order_id = list(orders.keys())[-1]  # Assuming you want the latest order

        # Check if order details are available
        if not order_id:
            # You can customize the error handling, such as redirecting to an error page
            return redirect(url_for('home'))

        # Open the shelves database for cart update
        with shelve.open('order.db', 'c') as cart_db:
            cart = cart_db.get('cart', {})

            # Use list comprehension to create a new cart excluding the specified product_id
            new_cart = [item for item in cart.get(order_id, []) if item.get('product_id') != product_id]

            # Update the cart in the database
            cart[order_id] = new_cart
            cart_db['cart'] = cart

        return redirect(url_for('view_cart'))

    except Exception as e:
        # Handle the exception - you can customize this based on your requirements
        return f"An error occurred: {str(e)}"


@app.route('/payment', methods=['GET', 'POST'])
def payment_page():

    payment_detail = None

    if 'username' not in session:
        flash('You must be logged in to add payment details.', 'danger')
        return redirect(url_for('login'))

    if 'started_order_process' not in session:
        flash("You must start the order process from the order-collection page.", "error")
        return redirect(url_for('order_collection'))  # Redirect back to the order-collection page

    # Reset the session variable after successful navigation to the payment page
    session.pop('started_order_process', None)

    user = User.query.filter_by(username=session['username']).first()
    payments = Payment.query.filter_by(username=session['username']).all()

    if user:
        if not payments:
            if request.method == 'POST':
                payment_detail = request.form.get('payment_detail')
            return render_template('payment.html', has_payment_details=False, form=payment_detail)
        else:
            payment_details_list = []
            for payment in payments:
                decrypted_card_num = decrypt_data(payment.card_number)
                formatted_card_number = f"**** **** **** {decrypted_card_num[-4:]}"
                payment_details_list.append({
                    'id': payment.id, 'card_number': formatted_card_number, 'expiration_date': payment.expiration_date, 'cvv': payment.cvv, 'card_name': payment.card_name})

            return render_template('payment.html', payment_details_list=payment_details_list, has_payment_details=True)
    else:
        return redirect(url_for('/'))


@app.route('/submit_payment', methods=['POST'])
def submit_payment():
    if 'username' not in session:
        flash('You must be logged in to submit payment.', 'danger')
        return redirect(url_for('login'))

    user = User.query.filter_by(username=session['username']).first()
    if user:
        try:
            payment_detail = request.form.get('payment_detail')

            if payment_detail == 'new_payment' and request.method == 'POST':
                card_number = request.form['card_number']
                expiration_date = request.form['expiration_date']
                cvv = request.form['cvv']
                card_name = request.form['card_name']

                encrypted_card_num = encrypt_data(card_number)
                encrypted_cvv = encrypt_data(cvv)

                if not (card_number and expiration_date and cvv and card_name):
                    flash("Please provide all required card details", "error")
                    return redirect(url_for('payment_page'))

                new_payment = Payment(username=session["username"], card_number=encrypted_card_num,
                                      expiration_date=expiration_date, cvv=encrypted_cvv, card_name=card_name)
                db.session.add(new_payment)
                db.session.commit()

                flash('New payment details added successfully.', 'success')
                return redirect(url_for('success_payment'))

            elif payment_detail:
                selected_payment = Payment.query.get(payment_detail)
                if not selected_payment:
                    flash("Selected payment not found.", "error")
                    return redirect(url_for('payment_page'))

                flash('Payment processed successfully.', 'success')
                return redirect(url_for('success_payment'))

            # If payment_detail is not 'new_payment' and is not null, assume it's an existing payment ID
            if payment_detail:
                selected_payment = Payment.query.get(payment_detail)
                if not selected_payment:
                    flash("Selected payment not found.", "error")
                    return redirect(url_for('payment_page'))

                flash('Payment processed successfully.', 'success')
                return redirect(url_for('success_payment'))

            # Only proceed to the next steps if payment details are provided
            if payment_detail:
                # Retrieve the order details from the shelves database
                with shelve.open('order.db', 'r') as order_db:
                    orders = order_db.get('orders', {})

                    # Check if there are any orders
                    if not orders:
                        flash("Order not found", "error")
                        return redirect(url_for('home'))

                    # Retrieve the last order ID
                    order_id = list(orders.keys())[-1]

                return redirect(url_for('success_payment'))

        except Exception as e:
            # Handle the exception - customize this based on your requirements
            flash(f"An error occurred: {str(e)}", "error")


# Define a route for displaying success payment page
@app.route('/success_payment')
def success_payment():
    user = User.query.filter_by(username=session["username"]).first()
    if user:
        # Retrieve the order details from the order database
        order_db = shelve.open('order.db', 'r')
        orders = order_db.get('orders', {})

        if not orders:
            flash("Order not found", "error")
            order_db.close()
            return redirect(url_for('home'))

        # Retrieve the last order ID
        order_id = list(orders.keys())[-1]

        order_data = orders.get(order_id)
        port = order_data
        collection_type = order_data['collection_type']

        # Retrieve the order cart from the order database
        cart_db = shelve.open('order.db', 'r')
        order_cart = cart_db.get('cart', {}).get(order_id, [])
        cart_db.close()

        # Calculate the totals
        subtotal = calculate_subtotal(order_cart)
        sales_tax = calculate_sales_tax(subtotal)
        delivery_amount = calculate_delivery_amount(collection_type)
        grand_total = calculate_grand_total(subtotal, sales_tax, delivery_amount, collection_type)

        # Convert the grand total to cents for the calculation
        grand_total_cents = int(grand_total * 100)

        # Calculate points earned, giving 5 points per dollar spent
        points_earned = 5 * (grand_total_cents // 100)

        extracted_items = []
        for item in order_cart:
            extracted_items.append({item['name'], item['quantity']})
        itemize_json = str(extracted_items).replace("'", '"')

        # Create a new Order object and add it to the database
        new_order = Order(username=session["username"], id=order_id, order_data=port['collection_type'],
                          items=itemize_json, total=grand_total)
        db.session.add(new_order)
        db.session.commit()

        user_points_record = UserPoints.query.filter_by(username=user.username).first()
        if user_points_record:
            user_points_record.points += points_earned
        else:
            new_points_record = UserPoints(username=user.username, points=points_earned)
            db.session.add(new_points_record)
        db.session.commit()

        # Render the success page with order details
        order_db.close()
        return render_template('success_payment.html', order_id=order_id, order_data=order_data,
                               grand_total=grand_total, collection_type=collection_type, order_cart=order_cart, points_earned=points_earned)


@app.route('/orderHistory', methods=["GET"])
def order_history():
    username = session.get('username')
    orders = Order.query.filter_by(username=username).all()

    if orders:
        return render_template('order_history.html', orders=orders, username=username)
    else:
        return redirect(url_for('home'))


@app.route('/contactUs')
def contact_us():
    return render_template('contactUs.html')


@app.route('/chatbot', methods=['GET'])
def chat_bot_page():
    return render_template('chatbot.html')


@app.route('/ChatBot', methods=['POST'])
def chat_bot_message():
    user_message = request.json.get('message')
    response_message = chatbot_response(user_message)
    return jsonify({"response": response_message})


@app.route('/createFeedback', methods=['GET', 'POST'])
def create_feedback():
    create_feedback_form = CreateFeedbackForm(request.form)
    if request.method == 'POST' and create_feedback_form.validate():
        new_feedback = Feed_back(name=create_feedback_form.name.data, mobile_no=create_feedback_form.mobile_no.data, service=create_feedback_form.service.data, food=create_feedback_form.food.data, feedback=create_feedback_form.feedback.data)

        db.session.add(new_feedback)
        db.session.commit()

        return redirect(url_for('contact_us'))
    return render_template('createFeedback.html', form=create_feedback_form)


@app.route('/retrieveFeedback')
def retrieve_feedback():
    feedbacks = Feed_back.query.all()
    feedbacks_list = []

    for feedback in feedbacks:
        feedbacks_list.append({'id': feedback.id, 'name': feedback.name, 'mobile_no': feedback.mobile_no, 'service': feedback.service, 'food': feedback.food, 'feedback': feedback.feedback})

    return render_template('retrieveFeedback.html', count=len(feedbacks_list), feedbacks_list=feedbacks_list)


@app.route('/deleteFeedback/<int:feedback_id>', methods=['POST'])
def delete_feedback(feedback_id):
    feedback_to_delete = Feed_back.query.get_or_404(feedback_id)

    try:
        db.session.delete(feedback_to_delete)
        db.session.commit()
        flash('Feedback deleted successfully.', 'success')
    except:
        db.session.rollback()
        flash('An error occurred while deleting the feedback.', 'danger')

    return redirect(url_for('retrieve_feedback'))


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run()

