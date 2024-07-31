from flask import *
from Models import *
from Forms import *
from ChatBot import chatbot_response
from cryptography.fernet import Fernet
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from sqlalchemy.exc import IntegrityError
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import timedelta, datetime
from error_handle import eh as errors_bp
from App_config import config
from Account_Lockout import max_attempts, lockout_duration
import re
import payment_storage
import os
import shelve
import uuid
import requests
from products import food, coffee, non_coffee, all_products
from Encryption_Payment import encrypt_data, decrypt_data
from Order_Calculation import calculate_subtotal, calculate_sales_tax, calculate_grand_total, calculate_delivery_amount
app = Flask(__name__)
app.config.from_object(config)
app.register_blueprint(errors_bp)
CORS(app)
limiter = Limiter(key_func=get_remote_address, app=app)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
db.init_app(app)
new_product = None
@app.route('/')
def home():
    return render_template('home.html')
@app.route('/about_us')
def about_us():
    return render_template('about_us.html')
@app.route('/createStaffAccount', methods=["GET", "POST"])
@limiter.limit("10/hour")
def create_staff_account():
    if session.get('role') != 'admin':
        return "Access Denied. This feature requires admin-level access!", 403

    if request.method == "POST":
        username = request.form.get('username')
        firstn = request.form.get('firstn')
        lastn = request.form.get('lastn')
        mobile = request.form.get('mobile')
        email = request.form.get('email')
        password = request.form.get('password')

        # Check for spaces in fields
        if ' ' in username:
            flash('Username cannot contain spaces.')
            return render_template('createStaffSignUp.html')
        if ' ' in firstn:
            flash('First name cannot contain spaces.')
            return render_template('createStaffSignUp.html')
        if ' ' in lastn:
            flash('Last name cannot contain spaces.')
            return render_template('createStaffSignUp.html')
        if ' ' in mobile:
            flash('Mobile number cannot contain spaces.')
            return render_template('createStaffSignUp.html')
        if ' ' in email:
            flash('Email cannot contain spaces.')
            return render_template('createStaffSignUp.html')
        if ' ' in password:
            flash('Password cannot contain spaces.')
            return render_template('createStaffSignUp.html')

        # Password security checks
        if len(password) < 8:
            flash('Password must be at least 8 characters long.')
            return render_template('createStaffSignUp.html')
        if not re.search(r'[A-Z]', password):
            flash('Password must contain at least one uppercase letter.')
            return render_template('createStaffSignUp.html')
        if not re.search(r'[a-z]', password):
            flash('Password must contain at least one lowercase letter.')
            return render_template('createStaffSignUp.html')
        if not re.search(r'[0-9]', password):
            flash('Password must contain at least one digit.')
            return render_template('createStaffSignUp.html')
        if not re.search(r'[\W_]', password):  # Checks for any non-alphanumeric character
            flash('Password must contain at least one special character.')
            return render_template('createStaffSignUp.html')

        # Check for duplicate username or email
        existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
        if existing_user:
            if existing_user.username == username:
                flash('Username already taken. Please choose a different username.')
            if existing_user.email == email:
                flash('Email already registered. Please use a different email.')
            return render_template('createStaffSignUp.html')

        # Hash the password
        hashed_password = generate_password_hash(password)

        # Create and add new user to the database
        new_user = User(
            username=username,
            firstn=firstn,
            lastn=lastn,
            mobile=mobile,
            email=email,
            password=hashed_password,
            role="staff"
        )

        try:
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('home'))
        except IntegrityError:
            db.session.rollback()
            flash('An error occurred while creating the account. Please try again.')
            return render_template('createStaffSignUp.html')

    return render_template('createStaffSignUp.html')


@app.route("/createSignUp", methods=["GET", "POST"])
@limiter.limit("10/hour")
def signup():
    if request.method == "POST":
        recaptcha_response = request.form.get('g-recaptcha-response')
        secret_key = '6LdKdRcqAAAAALvlHvSeepujVfzjSvHoHVjQjcgc'

        # Verify reCAPTCHA
        recaptcha_verification = requests.post('https://www.google.com/recaptcha/api/siteverify', data={
            'secret': secret_key,
            'response': recaptcha_response
        })
        result = recaptcha_verification.json()

        if not result.get('success'):
            flash('reCAPTCHA verification failed. Please try again.')
            return render_template('createSignUp.html')

        # Retrieve form data
        username = request.form.get('username')
        firstn = request.form.get('firstn')
        lastn = request.form.get('lastn')
        mobile = request.form.get('mobile')
        email = request.form.get('email')
        password = request.form.get('password')

        # Check for spaces in fields
        if ' ' in username:
            flash('Username cannot contain spaces.')
            return render_template('createSignUp.html')
        if ' ' in firstn:
            flash('First name cannot contain spaces.')
            return render_template('createSignUp.html')
        if ' ' in lastn:
            flash('Last name cannot contain spaces.')
            return render_template('createSignUp.html')
        if ' ' in mobile:
            flash('Mobile number cannot contain spaces.')
            return render_template('createSignUp.html')
        if ' ' in email:
            flash('Email cannot contain spaces.')
            return render_template('createSignUp.html')
        if ' ' in password:
            flash('Password cannot contain spaces.')
            return render_template('createSignUp.html')

        # Password security checks
        if len(password) < 8:
            flash('Password must be at least 8 characters long.')
            return render_template('createSignUp.html')
        if not re.search(r'[A-Z]', password):
            flash('Password must contain at least one uppercase letter.')
            return render_template('createSignUp.html')
        if not re.search(r'[a-z]', password):
            flash('Password must contain at least one lowercase letter.')
            return render_template('createSignUp.html')
        if not re.search(r'[0-9]', password):
            flash('Password must contain at least one digit.')
            return render_template('createSignUp.html')
        if not re.search(r'[\W_]', password):  # Checks for any non-alphanumeric character
            flash('Password must contain at least one special character.')
            return render_template('createSignUp.html')

        # Check for duplicate username or email
        existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
        if existing_user:
            if existing_user.username == username:
                flash('Username already taken. Please choose a different username.')
            if existing_user.email == email:
                flash('Email already registered. Please log in or use a different email.')
            return render_template('createSignUp.html')

        # Hash the password
        hashed_password = generate_password_hash(password)
        key = Fernet.generate_key()

        # Create and add new user to the database
        new_user = User(
            username=username,
            firstn=firstn,
            lastn=lastn,
            mobile=mobile,
            email=email,
            password=hashed_password,
            Key=key,
            role="user"
        )

        try:
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('home'))
        except IntegrityError:
            db.session.rollback()
            flash('An error occurred while creating the account. Please try again.')
            return render_template('createSignUp.html')

    return render_template('createSignUp.html')
@app.route("/Login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        recaptcha_response = request.form.get('g-recaptcha-response')
        secret_key = '6LdKdRcqAAAAALvlHvSeepujVfzjSvHoHVjQjcgc'

        recaptcha_verification = requests.post('https://www.google.com/recaptcha/api/siteverify', data={
            'secret': secret_key,
            'response': recaptcha_response
        })
        result = recaptcha_verification.json()

        if not result.get('success'):
            flash('reCAPTCHA verification failed. Please try again.')
            return render_template('Login.html')

        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()
        if user:
            if user.lockout_time and datetime.now() < user.lockout_time:
                remaining_time = (user.lockout_time - datetime.now()).seconds
                flash(f'Too many failed login attempts. Please try again in {remaining_time // 60} minutes and {remaining_time % 60} seconds.')
                return render_template('Login.html', lockout_time=remaining_time)

            if check_password_hash(user.password, password):
                user.login_attempts = 0
                user.lockout_time = None
                db.session.commit()
                session['username'] = user.username
                if user.username == "admin":
                    session['admin'] = True
                    session['role'] = 'admin'
                elif user.role == "staff":
                    session["staff"] = True
                    session['role'] = 'staff'
                elif user.role == "user":
                    session['logged_in'] = True
                    session['role'] = 'user'
                response = redirect(url_for('home'))
                response.set_cookie('session', '', max_age=0, httponly=True, secure=True)
                return response
            else:
                user.login_attempts += 1
                if user.login_attempts >= max_attempts:
                    user.lockout_time = datetime.now() + timedelta(minutes=lockout_duration)
                    flash(f'Too many failed login attempts. Please try again in {lockout_duration} minutes')
                else:
                    flash('Login Unsuccessful. Please check username and password.')
        else:
            flash('Login Unsuccessful. Please check username and password')
        db.session.commit()

    return render_template('Login.html')
@app.route('/logout')
def logout():
    session.clear()
    response = redirect(url_for('home'))
    response.set_cookie('session', '', max_age=0, httponly=True, secure=True)
    return response
@app.route('/check-session')
def check_session():
    if 'username' in session:
        return 'Session is active.'
    else:
        return 'No active session found.'
@app.route('/account')
def account():
    user = User.query.filter_by(username=session['username']).first()
    if user:
        return render_template('account.html', user=user)
    else:
        return redirect(url_for('home'))
@app.route('/staff_accounts', methods=["GET"])
@limiter.limit("50/hour")
def show_staff():
    if session.get('role') != 'admin':
        return "Access Denied. This feature requires admin-level access!", 403
    staff = User.query.filter_by(role='staff').all()
    return render_template('staff_accounts.html', staff=staff)
@app.route('/customer_accounts', methods=["GET"])
@limiter.limit("50/hour")
def show_customer():
    if session.get('role') != 'admin':
        return "Access Denied. This feature requires admin-level access!", 403
    customer = User.query.filter_by(role='user').all()
    return render_template('customer_accounts.html', customer=customer)
@app.route('/account/update', methods=['GET', 'POST'])
@limiter.limit("10/hour")
def update_account():
    user = User.query.filter_by(username=session['username']).first()
    if request.method == 'POST':
        new_username = request.form['username']
        new_firstn = request.form['firstn']
        new_lastn = request.form['lastn']
        new_mobile = request.form['mobile']
        new_email = request.form['email']
        new_password = request.form['password']
        hashed_password = generate_password_hash(new_password)
        existing_user = User.query.filter(
            User.id != user.id,
            (User.username == new_username) | (User.firstn == new_firstn) | (User.lastn == new_lastn) | (User.mobile == new_mobile) | (User.email == new_email) | (User.password == hashed_password)
        ).first()
        if existing_user:
            flash('Username or email already exists.', 'error')
            return redirect(url_for('update_account'))
        user.username = new_username
        user.firstn = new_firstn
        user.lastn = new_lastn
        user.mobile = new_mobile
        user.email = new_email
        user.password = hashed_password
        session['username'] = new_username
        db.session.commit()
        flash('Account successfully updated.', 'success')
        return redirect(url_for('account'))
    return render_template('update_account.html', user=user)
@app.route('/account/delete', methods=['POST'])
@limiter.limit("10/hour")
def delete_account():
    user = User.query.filter_by(username=session['username']).first()
    if user:
        payment_details = Payment.query.filter_by(username=user.username).all()
        for payment_detail in payment_details:
            db.session.delete(payment_detail)
        db.session.commit()
        orders = Order.query.filter_by(username=user.username).all()
        for order in orders:
            db.session.delete(order)
        db.session.commit()
        user_points = UserPoints.query.filter_by(username=user.username).first()
        if user_points:
            db.session.delete(user_points)
        db.session.commit()
        db.session.delete(user)
        db.session.commit()
        session.pop('username', None)
        session.pop('logged_in', None)
        flash('Your account has been deleted.', 'success')
    else:
        flash('User not found.', 'danger')
    return redirect(url_for('home'))
@app.route('/customerPortal/')
def customer_portal():
    if 'username' not in session:
        flash('You must be logged in to view your account portal', 'danger')
        return redirect(url_for('login'))
    user = User.query.filter_by(username=session['username']).first()
    if user:
        user_points = UserPoints.query.filter_by(username=session['username']).first()
        if user_points:
            user_points_value = user_points.points
        else:
            user_points_value = 0
        user_orders_count = db.session.query(Order.id).filter_by(username=session['username']).count()
        if user_points_value >= 1000:
            user_category = "Platinum"
        elif user_points_value >= 500:
            user_category = "Gold"
        elif user_points_value >= 100:
            user_category = "Silver"
        else:
            user_category = "Bronze"
        return render_template('CustomerPortal.html', user=user, user_orders_count=user_orders_count, user_points_value=user_points_value, user_category=user_category)
    else:
        return redirect(url_for('home'))
@app.route('/view_points')
def view_points():
    if 'username' not in session:
        flash('You must be logged in to view your points.', 'danger')
        return redirect(url_for('login'))
    username = session['username']
    user_points = UserPoints.query.filter_by(username=username).first()
    if user_points:
        user_points_value = user_points.points
        if user_points_value >= 1000:
            category = "Platinum"
            next_level_threshold = None
        elif user_points_value >= 500:
            category = "Gold"
            next_level_threshold = 1000
        elif user_points_value >= 100:
            category = "Silver"
            next_level_threshold = 500
        else:  # Bronze level
            category = "Bronze"
            next_level_threshold = 100
        points_needed = next_level_threshold - user_points_value
        return render_template('view_points.html', username=username, user_points_value=user_points_value, category=category, next_level_threshold=next_level_threshold, points_needed=points_needed)
    else:
        return redirect(url_for('home'))
@app.route('/createProduct', methods=['GET', 'POST'])
def create_product():
    create_product_form = CreateProductForm(request.form)
    if request.method == 'POST':
        file = request.files['photos']
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        photos = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        new_product = CreateProductForm.product(
            name=create_product_form.name.data,
            product=create_product_form.product.data,
            description=create_product_form.description.data,
            price=create_product_form.price.data,
            photos=photos
        )
        db.session.add(new_product)
        db.session.commit()
        return redirect(url_for('retrieve_product'))
    return render_template('createProduct.html', form=create_product_form)
@app.route('/retrieveProducts')
def retrieve_product():
    products_list = Product.query.all()
    return render_template('retrieveProduct.html', count=len(products_list), products_list=products_list)
@app.route('/updateProduct/<int:id>', methods=['GET', 'POST'])
def update_product(id):
    # Retrieve product by ID from the database
    product = CreateProductForm.product.query.get_or_404(id)
    update_product_form = CreateProductForm(obj=product)
    if request.method == 'POST' and update_product_form.validate():
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
@limiter.limit("10/hour")
def create_payment():
    if 'username' not in session:
        flash('You must be logged in to add payment details.', 'danger')
        return redirect(url_for('login'))
    user = User.query.filter_by(username=session['username']).first()
    if user:
        form = payment(request.form)
        if request.method == 'POST' and form.validate():
            encrypted_card_num = encrypt_data(form.card_number.data)
            encrypted_cvv = encrypt_data(form.cvv.data)
            new_payment = Payment(username=session["username"], card_number=encrypted_card_num, expiration_date=form.expiration_date.data, cvv=encrypted_cvv, card_name=form.card_name.data)
            db.session.add(new_payment)
            db.session.commit()
            flash('Payment details added successfully.', 'success')
            return redirect(url_for('retrieve_payment'))
        return render_template('payment_details.html', form=form)
@app.route('/retrieve_payment')
@limiter.limit("10/hour")
def retrieve_payment():
    if 'username' not in session:
        flash('You must be logged in to add payment details.', 'danger')
        return redirect(url_for('login'))
    payments = Payment.query.filter_by(username=session['username']).all()
    payment_details_list = []
    for payment in payments:
        decrypted_card_number = decrypt_data(payment.card_number)
        decrypted_cvv = decrypt_data(payment.cvv)
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
    return render_template('view_payment_details.html', count=len(payment_details_list), payment_details_list=payment_details_list)
@app.route('/update_payment/<int:id>/', methods=['POST', 'GET'])
@limiter.limit("10/hour")
def update_payment(id):
    if request.method == 'POST':
        form = Payment(request.form)
        payment = Payment.query.get(id)
        payment.card_number = form.card_number.data
        payment.expiration_date = form.expiration_date.data
        payment.cvv = form.cvv.data
        payment.card_name = form.card_name.data
        db.session.commit()

        flash("Payment details updated successfully", "success")
        return redirect(url_for('retrieve_payment'))
    else:
        payment = Payment.query.get_or_404(id)
        form = Payment(card_number=payment.card_number, expiration_date=payment.expiration_date,  cvv=payment.cvv,  card_name=payment.card_name)
    return render_template('update_payment_details.html', form=form, id=id)
@app.route('/delete_payment/<int:id>', methods=['POST'])
@limiter.limit("5/hour")
def delete_payment(id):
    payment = Payment.query.get(id)
    db.session.delete(payment)
    db.session.commit()
    flash("Payment details deleted successfully", "success")
    return redirect(url_for('retrieve_payment'))
@app.route('/order', methods=['POST', 'GET'])
@limiter.limit("10/hour")
def order_collection():
    collection_Type = collection_type(request.form)
    session['started_order_process'] = True
    if request.method == 'POST' and collection_Type.validate():
        order_id = str(uuid.uuid4())
        order_data = {
            'order_id': order_id,
            'collection_type': collection_Type.collection_type.data
        }
        with shelve.open('order.db', 'c') as db:
            orders = db.get('orders', {})
            orders[order_id] = order_data
            db['orders'] = orders
        with shelve.open('order.db', 'c') as db:
            cart = db.get('cart', {})
            cart[order_id] = []
            db['cart'] = cart
        return redirect(url_for('show_products'))
    return render_template('order_collection.html', form=collection_Type)
@app.route('/products', endpoint='show_products')
def show_products():
    try:
        with shelve.open('order.db', 'c') as order_db:
            orders = order_db.get('orders', {})
            if not orders:
                return render_template('error.html', error_message="Order not found")
            order_id = list(orders.keys())[-1]  # Assuming you want the latest order, adjust as needed
            cart = order_db.get('cart', {})
            order_cart = cart.get(order_id, [])
        return render_template('products.html', food=food, coffee=coffee, non_coffee=non_coffee, cart=order_cart)
    except Exception as e:
        return render_template('error.html', error_message=f"An error occurred: {str(e)}")
@app.route('/add_to_cart/<product_id>', methods=['POST'], endpoint='add_to_cart')
def add_to_cart(product_id):
    product = all_products.get(product_id)
    if not product:
        flash("Product not found", "error")
        return redirect(url_for('show_products'))
    order_db = shelve.open('order.db', 'r')
    orders = order_db.get('orders', {})
    if not orders:
        flash("Order not found", "error")
        order_db.close()
        return redirect(url_for('home'))
    order_id = list(orders.keys())[-1]
    collection_types = orders[order_id]['collection_type']
    order_db.close()
    item = {
        'product_id': product_id,
        'name': product['name'],
        'price': product['price'],
        'quantity': int(request.form['quantity']),
        'order_id': order_id,
        'collection_type': collection_type,
        'image_path': product['image_path']}
    try:
        cart_db = shelve.open('order.db', 'c')
        cart = cart_db.get('cart', {})
        order_cart = cart.get(order_id, [])
        for existing_item in order_cart:
            if existing_item['name'] == item['name']:
                existing_item['quantity'] += item['quantity']
                break
        else:
            order_cart.append(item)
        cart[order_id] = order_cart
        cart_db['cart'] = cart
        cart_db.close()
        flash("Product added to cart successfully", "success")
        return redirect(url_for('show_products'))
    except:
        flash("An error occurred while adding the product to your cart. Please try again later.", "error")
        return redirect(url_for('home'))
@app.route('/view_cart')
@limiter.limit("10/hour")
def view_cart():
    if 'username' not in session:
        flash('You must be logged in to add payment details.', 'danger')
        return redirect(url_for('login'))
    if 'started_order_process' not in session:
        flash("You must start the order process from the order-collection page.", "error")
        return redirect(url_for('order_collection'))
    try:
        with shelve.open('order.db', 'r') as order_db:
            orders = order_db.get('orders', {})
            if not orders:
                return "Order not found"
            order_id = list(orders.keys())[-1]
            collection_types = orders[order_id]['collection_type']
            cart = order_db.get('cart', {})
            order_cart = cart.get(order_id, [])
            subtotal = calculate_subtotal(order_cart)
            sales_tax = calculate_sales_tax(subtotal)
            delivery_amount = calculate_delivery_amount(collection_types)
            grand_total = calculate_grand_total(subtotal, sales_tax, delivery_amount, collection_types)
        return render_template('view_cart.html', cart=order_cart, subtotal=subtotal, sales_tax=sales_tax,
                               delivery_amount=delivery_amount, grand_total=grand_total)
    except Exception as e:
        return f"An error occurred: {str(e)}"
@app.route('/update_cart_item/<product_id>', methods=['POST', 'GET'])
@limiter.limit("10/hour")
def update_cart_item(product_id):
    try:
        order_db = shelve.open('order.db', 'r')
        orders = order_db.get('orders', {})
        if not orders:
            flash("Order not found", "error")
            order_db.close()
            return redirect(url_for('home'))
        order_id = list(orders.keys())[-1]  # Assuming you want the latest order
        order_db.close()
        if not order_id:
            flash("Order not found", "error")
            return redirect(url_for('home'))
        new_quantity = request.form.get('quantity', '0')
        try:
            new_quantity = int(new_quantity)
        except ValueError:
            flash("Invalid quantity value", "error")
            return redirect(url_for('view_cart'))
        cart_db = shelve.open('order.db', 'c')
        cart = cart_db.get('cart', {})
        for item in cart.get(order_id, []):
            if item['product_id'] == product_id:
                item['quantity'] = new_quantity
        cart_db['cart'] = cart
        cart_db.close()
    except Exception as e:
        return f"An error occurred: {str(e)}"
    return redirect(url_for('view_cart'))
@app.route('/remove_from_cart/<product_id>', methods=['POST'])
@limiter.limit("10/hour")
def remove_from_cart(product_id):
    try:
        with shelve.open('order.db', 'r') as order_db:
            orders = order_db.get('orders', {})
            if not orders:
                return redirect(url_for('home'))
            order_id = list(orders.keys())[-1]
        if not order_id:
            return redirect(url_for('home'))
        with shelve.open('order.db', 'c') as cart_db:
            cart = cart_db.get('cart', {})
            new_cart = [item for item in cart.get(order_id, []) if item.get('product_id') != product_id]
            cart[order_id] = new_cart
            cart_db['cart'] = cart
        return redirect(url_for('view_cart'))
    except Exception as e:
        return f"An error occurred: {str(e)}"
@app.route('/payment', methods=['GET', 'POST'])
@limiter.limit("10/hour")
def payment_page():
    payment_detail = None
    if 'username' not in session:
        flash('You must be logged in to add payment details.', 'danger')
        return redirect(url_for('login'))
    if 'started_order_process' not in session:
        flash("You must start the order process from the order-collection page.", "error")
        return redirect(url_for('order_collection'))
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
@limiter.limit("10/hour")
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
            if payment_detail:
                selected_payment = Payment.query.get(payment_detail)
                if not selected_payment:
                    flash("Selected payment not found.", "error")
                    return redirect(url_for('payment_page'))
                flash('Payment processed successfully.', 'success')
                return redirect(url_for('success_payment'))
            if payment_detail:
                with shelve.open('order.db', 'r') as order_db:
                    orders = order_db.get('orders', {})
                    if not orders:
                        flash("Order not found", "error")
                        return redirect(url_for('home'))
                    # Retrieve the last order ID
                    order_id = list(orders.keys())[-1]
                return redirect(url_for('success_payment'))
        except Exception as e:
            flash(f"An error occurred: {str(e)}", "error")
@app.route('/success_payment')
@limiter.limit("10/hour")
def success_payment():
    user = User.query.filter_by(username=session["username"]).first()
    if user:
        order_db = shelve.open('order.db', 'r')
        orders = order_db.get('orders', {})
        if not orders:
            flash("Order not found", "error")
            order_db.close()
            return redirect(url_for('home'))
        order_id = list(orders.keys())[-1]
        order_data = orders.get(order_id)
        port = order_data
        collection_type = order_data['collection_type']
        cart_db = shelve.open('order.db', 'r')
        order_cart = cart_db.get('cart', {}).get(order_id, [])
        cart_db.close()
        subtotal = calculate_subtotal(order_cart)
        sales_tax = calculate_sales_tax(subtotal)
        delivery_amount = calculate_delivery_amount(collection_type)
        grand_total = calculate_grand_total(subtotal, sales_tax, delivery_amount, collection_type)
        grand_total_cents = int(grand_total * 100)
        points_earned = 5 * (grand_total_cents // 100)
        extracted_items = []
        for item in order_cart:
            extracted_items.append({item['name'], item['quantity']})
        itemize_json = str(extracted_items).replace("'", '"')
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
        with shelve.open('order.db', 'c') as order_db:
            if 'orders' in order_db and order_id in order_db['orders']:
                del order_db['orders'][order_id]
            if 'cart' in order_db and order_id in order_db['cart']:
                del order_db['cart'][order_id]
        order_db.close()
        return render_template('success_payment.html', order_id=order_id, order_data=order_data, grand_total=grand_total, collection_type=collection_type, order_cart=order_cart, points_earned=points_earned)


@app.route('/orderHistory', methods=["GET"])
# @limiter.limit("20/hour")
def order_history():
    username = session.get('username')
    orders = Order.query.filter_by(username=username).all()
    if orders:
        return render_template('order_history.html', orders=orders, username=username)
    else:
        return redirect(url_for('home'))
@app.route('/customerOrder', methods=["GET"])
@limiter.limit("50/hour")
def customer_order():
    if session.get('role') == 'user':
        return "Access Denied. This feature requires staff & admin level access!", 403
    orders = Order.query.all()
    return render_template('customer_orders.html', orders=orders)
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
@limiter.limit("10/hour")
def create_feedback():
    create_feedback_form = CreateFeedbackForm(request.form)
    if request.method == 'POST' and create_feedback_form.validate():
        new_feedback = Feed_back(name=create_feedback_form.name.data, mobile_no=create_feedback_form.mobile_no.data, service=create_feedback_form.service.data, food=create_feedback_form.food.data, feedback=create_feedback_form.feedback.data)
        db.session.add(new_feedback)
        db.session.commit()
        return redirect(url_for('contact_us'))
    return render_template('createFeedback.html', form=create_feedback_form)
@app.route('/retrieveFeedback')
@limiter.limit("20/hour")
def retrieve_feedback():
    if session.get('role') != 'admin':
        return "Access Denied. This feature requires admin-level access!", 403
    feedbacks = Feed_back.query.all()
    feedbacks_list = []
    for feedback in feedbacks:
        feedbacks_list.append({'id': feedback.id, 'name': feedback.name, 'mobile_no': feedback.mobile_no, 'service': feedback.service, 'food': feedback.food, 'feedback': feedback.feedback})
    return render_template('retrieveFeedback.html', count=len(feedbacks_list), feedbacks_list=feedbacks_list)
@app.route('/deleteFeedback/<int:feedback_id>', methods=['POST'])
@limiter.limit("10/hour")
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