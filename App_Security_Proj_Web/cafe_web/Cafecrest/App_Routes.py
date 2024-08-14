from flask import *
from Models import *
from Order_Product_Payment_Forms import *
from Fedback_Form import CreateFeedbackForm
from ChatBot import chatbot_response
from cryptography.fernet import Fernet
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from sqlalchemy.exc import IntegrityError
from sqlalchemy import and_
from markupsafe import escape
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import timedelta, datetime
from Error_handle_routes import eh as errors_bp
from App_config import config
from Account_Lockout import max_attempts, lockout_duration
import re
import os
import uuid
import requests
from products import food, coffee, non_coffee, all_products
from Encryption_Payment import encrypt_data, decrypt_data
from Order_Calculation import *
from logging_config import configure_logging

app = Flask(__name__)
app.config.from_object(config)
app.register_blueprint(errors_bp)

limiter = Limiter(key_func=get_remote_address, app=app)


@app.after_request
def add_csp_header(response):
    csp = {
        "default-src": "'self'",
        "script-src": [
            "'self'",
            "https://code.jquery.com",
            "https://cdnjs.cloudflare.com",
            "https://cdn.jsdelivr.net",
            "https://www.google.com",
            "https://www.gstatic.com",
            "https://kit.fontawesome.com",
            "'unsafe-inline'",
        ],
        "style-src": [
            "'self'",
            "https://fonts.googleapis.com",
            "https://cdnjs.cloudflare.com",
            "https://cdn.jsdelivr.net",
            "'unsafe-inline'",
        ],
        "img-src": [
            "'self'",
            "data:",
            "https://images.unsplash.com",
            "https://images.pexels.com",
            "https://img.bestrecipes.com.au",
            "https://img.kidspot.com.au",
            "https://coffeeabros.com",
            "https://www.recipegirl.com",
            "https://www.imperialsugar.com",
            "https://cdn.buttercms.com",
            "https://www.tastingtable.com",
            "https://feelgoodfoodie.net",
            "https://images.immediate.co.uk",
            "https://coffeebros.com/cdn/shop/articles/unnamed_be2775a1-186d-40c1-b094-488fa5fa4050.png",  # Removed the query parameter
            "https://images.ctfassets.net/v601h1fyjgba/7cdNOhfEauvOFDfJx91p68/487c04ddacbc8228af9f852eea022397/Iced_Mocha_Hazelnut_Caffe.jpg",
            "https://images.ctfassets.net/v601h1fyjgba/1vlXSpBbgUo9yLzh71tnOT/a1afdbe54a383d064576b5e628035f04/Iced_Americano.jpg"
        ],
        "font-src": [
            "'self'",
            "https://fonts.googleapis.com",
            "https://fonts.gstatic.com",
        ],
        "connect-src": [
            "'self'",
        ],
        "media-src": "'self'",
        "object-src": "'none'",
        "base-uri": "'self'",
        "form-action": "'self'",
        "frame-src": [
            "'self'",
            "https://www.google.com",
        ],
        "frame-ancestors": "'none'",
        "upgrade-insecure-requests": "",
    }

    csp_directive = "; ".join([f"{k} {' '.join(v) if isinstance(v, list) else v}" for k, v in csp.items()])
    response.headers['Content-Security-Policy'] = csp_directive

    return response


def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# Ensure the upload directory exists
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

db.init_app(app)

new_product = None

configure_logging(app)


@app.route('/')
def home():
    if 'started_order_process' in session:
        session.pop('started_order_process', None)

    app.logger.info('Home Page Accessed!')
    return render_template('home.html')


@app.route('/about_us')
def about_us():
    app.logger.info('About Us Page Accessed!')
    return render_template('about_us.html')


@app.route('/createStaffAccount', methods=["GET", "POST"])
@limiter.limit("5/minute")
def create_staff_account():
    if session.get('role') != 'admin':
        app.logger.warning('Access Denied for non-admin user trying to access staff account creation')
        return "Access Denied. This feature requires admin-level access!", 403

    if request.method == "POST":
        try:
            username = request.form.get('username')
            firstn = request.form.get('firstn')
            lastn = request.form.get('lastn')
            mobile = request.form.get('mobile')
            email = request.form.get('email')
            password = request.form.get('password')
            hashed_password = generate_password_hash(password)

            # Validate fields with regular expressions
            if not re.match(r'^[a-zA-Z0-9_]+$', username):
                flash('Username can only contain letters, numbers, and underscores.')
                return render_template('createStaffSignUp.html')
            if not re.match(r'^[a-zA-Z]+$', firstn):
                flash('First name can only contain letters.')
                return render_template('createStaffSignUp.html')
            if not re.match(r'^[a-zA-Z]+$', lastn):
                flash('Last name can only contain letters.')
                return render_template('createStaffSignUp.html')
            if not re.match(r'^\d+$', mobile):
                flash('Mobile number can only contain digits.')
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

            new_user = User(username=username, firstn=firstn, lastn=lastn, mobile=mobile, email=email, password=hashed_password, role="staff")
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('home'))
        except IntegrityError:
            db.session.rollback()
            app.logger.error(f'Failed to sign up user. Email already registered: {email}')
            flash('Email already registered. Please log in or use a different email.')
            return redirect(url_for('login'))
    return render_template('createStaffSignUp.html')


@app.route("/createSignUp", methods=["GET", "POST"])
@limiter.limit("5/minute")
def signup():
    if request.method == "POST":
        recaptcha_response = request.form.get('g-recaptcha-response')

        recaptcha_verification = requests.post('https://www.google.com/recaptcha/api/siteverify', data={
            'secret': config.secret_key,
            'response': recaptcha_response
        })
        result = recaptcha_verification.json()

        if not result.get('success'):
            app.logger.warning('reCAPTCHA verification failed during login')
            flash('reCAPTCHA verification failed. Please try again.')
            return render_template('createSignUp.html')

        try:
            username = request.form.get('username')
            firstn = request.form.get('firstn')
            lastn = request.form.get('lastn')
            mobile = request.form.get('mobile')
            email = request.form.get('email')
            password = request.form.get('password')
            hashed_password = generate_password_hash(password)

            # Validate fields with regular expressions
            if not re.match(r'^[a-zA-Z0-9_]+$', username):
                flash('Username can only contain letters, numbers, and underscores.')
                return render_template('createSignUp.html')
            if not re.match(r'^[a-zA-Z]+$', firstn):
                flash('First name can only contain letters.')
                return render_template('createSignUp.html')
            if not re.match(r'^[a-zA-Z]+$', lastn):
                flash('Last name can only contain letters.')
                return render_template('createSignUp.html')
            if not re.match(r'^\d+$', mobile):
                flash('Mobile number can only contain digits.')
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
            if not re.search(r'[\W_]', password):
                flash('Password must contain at least one special character.')
                return render_template('createSignUp.html')

            # Check for duplicate username or email
            existing_user = User.query.filter(User.username == username).first()
            if existing_user:
                if existing_user.username == username:
                    flash('Username already taken. Please choose a different username.')
                    return render_template('createSignUp.html')

            key = Fernet.generate_key()

            new_user = User(username=username, firstn=firstn, lastn=lastn, mobile=mobile, email=email, password=hashed_password, Key=key, role="user")

            db.session.add(new_user)
            db.session.commit()
            app.logger.info(f'New User Signed Up: {username}')

            return redirect(url_for('home'))

        except IntegrityError:
            db.session.rollback()
            app.logger.error(f'Failed to sign up user. Email already registered: {email}')
            flash('Email already registered. Please log in or use a different email.')
            return redirect(url_for('login'))

    return render_template('createSignUp.html')


@app.route("/Login", methods=["GET", "POST"])
@limiter.limit("5/minute")
def login():
    if request.method == "POST":
        recaptcha_response = request.form.get('g-recaptcha-response')

        recaptcha_verification = requests.post('https://www.google.com/recaptcha/api/siteverify', data={
            'secret': config.secret_key,
            'response': recaptcha_response
        })
        result = recaptcha_verification.json()

        if not result.get('success'):
            app.logger.warning('reCAPTCHA verification failed during login')
            flash('reCAPTCHA verification failed. Please try again.')
            return render_template('Login.html')

        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()
        if user:
            if user.lockout_time and datetime.now() < user.lockout_time:
                remaining_time = (user.lockout_time - datetime.now()).seconds // 60
                username = escape(session.get("username", ""))
                app.logger.warning(f'user: {username} attempted login while locked out. Remaining time: {remaining_time} minutes')
                flash(f'Too many failed login attempts. Please try again in {remaining_time} minutes.')
                return render_template('Login.html')

        if check_password_hash(user.password, password):
            user.login_attempts = 0
            user.lockout_time = None
            db.session.commit()

            session['username'] = user.username
            if user.role == "admin":
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
                app.logger.warning(
                    f'User {username} exceeded login attempts. Locked out until {user.lockout_time}.')
                flash(f'Too many failed login attempts. Please try again in {lockout_duration} minutes')
            else:
                app.logger.info(f'Failed Login attempt for User: {username}')
                flash('Login Unsuccessful. Please check username and password.')
    db.session.commit()
    app.logger.info('Login Page Accessed!')
    return render_template('Login.html')


@app.route('/logout')
def logout():
    session.clear()
    app.logger.info('User logged out')
    response = redirect(url_for('home'))
    response.set_cookie('session', '', max_age=0, httponly=True, secure=True)
    return response


@app.route('/grant_admin/<int:user_id>', methods=['GET', 'POST'])
def grant_admin(user_id):
    if session.get('role') != 'admin':
        app.logger.warning('Access Denied for non-admin user trying to access staff account creation')
        return "Access Denied. This feature requires admin-level access!", 403

    user = User.query.get_or_404(user_id)
    if request.method == 'POST':
        user.role = 'admin'
        db.session.commit()
        flash(f'User {user.username} has been granted admin privileges.', 'success')
        return redirect(url_for('show_staff'))
    return render_template('grant_admin.html', user=user)


@app.route('/account')
def account():
    user = User.query.filter_by(username=session['username']).first()

    if user:
        app.logger.info('Account page accessed by user %s', session['username'])
        return render_template('account.html', user=user)
    else:
        app.logger.info('Account page accessed without a valid session')
        return redirect(url_for('home'))


@app.route('/staff_accounts', methods=['GET'])
@limiter.limit("5/minute")
def show_staff():
    if session.get('role') != 'admin':
        app.logger.warning('Unauthorized access attempt to staff accounts page by user %s',
                           session.get('username', 'unknown'))
        return "Access Denied. This feature requires admin-level access!", 403

    staff = User.query.filter_by(role='staff').all()
    app.logger.info('Staff accounts page accessed by admin %s', session['username'])
    return render_template('staff_accounts.html', staff=staff)


@app.route('/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    app.logger.info('A Staff account deleted by admin')
    flash('User deleted successfully.', 'success')
    return redirect(url_for('show_staff'))


@app.route('/customer_accounts', methods=['GET'])
@limiter.limit("5/minute")
def show_customer():
    if session.get('role') != 'admin':
        app.logger.warning('Unauthorized access attempt to customer accounts page by user %s',
                           session.get('username', 'unknown'))
        return "Access Denied. This feature requires admin-level access!", 403

    customer = User.query.filter_by(role='user').all()
    app.logger.info('Customer accounts page accessed by admin %s', session['username'])
    return render_template('customer_accounts.html', customer=customer)


@app.route('/delete_customer/<int:user_id>', methods=['POST'])
def delete_customer(user_id):
    user = User.query.get_or_404(user_id)

    payment_details = Payment.query.filter_by(username=user.username).all()
    for payment_detail in payment_details:
        db.session.delete(payment_detail)

    orders = Order.query.filter_by(username=user.username).all()
    for order in orders:
        db.session.delete(order)

    UserPoints.query.filter_by(username=user.username).delete()

    db.session.delete(user)
    db.session.commit()
    flash('Customer deleted successfully.', 'success')
    return redirect(url_for('show_customer'))


@app.route('/account/update', methods=['GET', 'POST'])
@limiter.limit("5/minute")
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
            app.logger.warning('Attempt to update account with existing username or email by user %s',
                               session['username'])
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
        app.logger.info('Account updated successfully for user %s', session['username'])
        flash('Account successfully updated.', 'success')
        return redirect(url_for('account'))

    return render_template('update_account.html', user=user)


@app.route('/account/delete', methods=['POST'])
@limiter.limit("1/minute")
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
        app.logger.info('Account deleted for user %s', session.get('username', 'unknown'))
        flash('Your account has been deleted.', 'success')
    else:
        app.logger.warning('Attempt to delete non-existent account by user %s', session.get('username', 'unknown'))
        flash('User not found.', 'danger')

    return redirect(url_for('home'))


@app.route('/customerPortal/')
@limiter.limit("5/minute")
def customer_portal():
    if 'username' not in session:
        app.logger.warning('Unauthorized access attempt to customer portal')
        flash('You must be logged in to view your account portal', 'danger')
        return redirect(url_for('login'))

    if 'started_order_process' in session:
        session.pop('started_order_process', None)

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

        app.logger.info('Customer portal accessed by user %s', session['username'])
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
@limiter.limit("5/minute")
def create_product():
    if session.get('role') == 'user':
        return "Access Denied. This feature requires staff & admin level access!", 403

    create_product_form = CreateProductForm(request.form)
    if request.method == 'POST':
        if 'photos' not in request.files:
            flash('No file part', 'error')
            return redirect(url_for('create_product'))

        file = request.files['photos']
        if file.filename == '':
            flash('No selected file', 'error')
            return redirect(url_for('create_product'))

        if file:
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            photos = file_path

            new_product = Product(
                name=create_product_form.name.data,
                product=create_product_form.product.data,
                description=create_product_form.description.data,
                price=create_product_form.price.data,
                photos=photos
            )

            db.session.add(new_product)
            db.session.commit()

            flash('Product created successfully!', 'success')
            return redirect(url_for('retrieve_product'))

        flash('File upload failed', 'error')
        return redirect(url_for('create_product'))

    return render_template('createProduct.html', form=create_product_form)


@app.route('/retrieveProducts')
def retrieve_product():
    products = Product.query.all()
    return render_template('retrieveProduct.html', products_list=products, count=len(products))


@app.route('/updateProduct/<int:id>', methods=['GET', 'POST'])
@limiter.limit("5/minute")
def update_product(id):
    # Retrieve product by ID from the database
    product = Product.query.get_or_404(id)
    update_product_form = CreateProductForm(obj=product)

    if request.method == 'POST' and update_product_form.validate():
        product.name = request.form['name']
        product.product = request.form['product']
        product.description = request.form['description']
        product.price = request.form['price']

        # If a new photo is provided, save it and update the product's photo path
        if 'photos' in request.files and request.files['photos'].filename:
            photo_filename = secure_filename(request.files['photos'].filename)
            if allowed_file(photo_filename):
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], photo_filename)
                request.files['photos'].save(file_path)
                product.photos = photo_filename

        db.session.commit()
        flash('Product updated successfully.', 'success')
        return redirect(url_for('retrieve_product'))

    return render_template('updateProduct.html', form=update_product_form, product=product)


@app.route('/delete_product/<int:id>', methods=['POST'])
@limiter.limit("1/minute")
def delete_product(id):
    product = Product.query.get_or_404(id)
    db.session.delete(product)
    db.session.commit()

    photo_path = os.path.join(app.config['UPLOAD_FOLDER'], product.photos)
    if os.path.exists(photo_path):
        os.remove(photo_path)

    flash('Product deleted successfully.', 'success')
    return redirect(url_for('retrieve_product'))


# Define a route to serve static files
@app.route('/static/<path:filename>')
def serve_image(filename):
    return send_from_directory('static', filename)


@app.route('/payment_details', methods=['GET', 'POST'])
@limiter.limit("3/minute")
def create_payment():
    if 'username' not in session:
        app.logger.warning('User tried to add payment details without being logged in.')
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
            app.logger.info(f'Payment details added for user: {session["username"]}')
            return redirect(url_for('retrieve_payment'))
        return render_template('payment_details.html', form=form)


@app.route('/retrieve_payment')
@limiter.limit("5/minute")
def retrieve_payment():
    if 'username' not in session:
        app.logger.warning('User tried to view payment details without being logged in.')
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

    app.logger.info(f'Payment details retrieved for user: {session["username"]}')
    return render_template('view_payment_details.html', count=len(payment_details_list), payment_details_list=payment_details_list)


@app.route('/delete_payment/<int:id>', methods=['POST'])
@limiter.limit("3/minute")
def delete_payment(id):
    payment = Payment.query.get(id)

    if not payment:
        flash("Payment not found", "error")
        username = escape(session.get("username", ""))
        app.logger.error(f'Attempt to delete non-existent payment with ID {id} by user: {username}')
        return redirect(url_for('retrieve_payment'))

    db.session.delete(payment)
    db.session.commit()
    flash("Payment details deleted successfully", "success")
    username = escape(session.get("username", ""))
    app.logger.info(f'Payment with ID {id} deleted successfully by user: {username}')
    return redirect(url_for('retrieve_payment'))


@app.route('/order', methods=['POST', 'GET'])
@limiter.limit("10/minute")
def order_collection():
    collection_Type = collection_type(request.form)

    if request.method == 'POST' and collection_Type.validate():
        order_id = str(uuid.uuid4())
        order = Order(order_id=order_id, collection_type=collection_Type.collection_type.data, username=session["username"])
        db.session.add(order)
        db.session.commit()

        session['started_order_process'] = True

        app.logger.info('Order collection started for order_id: %s by user: %s', order_id, session.get('username', 'unknown'))
        return redirect(url_for('show_products'))

    app.logger.info('Order collection page accessed by user: %s', session.get('username', 'unknown'))
    return render_template('order_collection.html', form=collection_Type)


@app.route('/products', endpoint='show_products')
def show_products():
    if 'started_order_process' not in session or not session['started_order_process']:
        flash("You must start the order process from the order-collection page.", "error")
        return redirect(url_for('order_collection'))

    try:
        order = Order.query.order_by(Order.id.desc()).first()
        if not order:
            app.logger.warning('Order not found for user: %s', session.get('username', 'unknown'))
            return render_template('error.html', error_message="Order not found")

        app.logger.info('Products page accessed by user: %s for order_id: %s', session.get('username', 'unknown'), order.order_id)
        return render_template('products.html', food=food, coffee=coffee, non_coffee=non_coffee, cart=order.items)

    except Exception as e:
        return render_template('error.html', error_message=f"An error occurred: {str(e)}")


@app.route('/add_to_cart/<product_id>', methods=['POST'], endpoint='add_to_cart')
def add_to_cart(product_id):
    product = all_products.get(product_id)

    if not product:
        app.logger.warning('Product not found (product_id: %s) for user: %s', product_id,
                           session.get('username', 'unknown'))
        flash("Product not found", "error")
        return redirect(url_for('show_products'))

    order = Order.query.order_by(Order.id.desc()).first()

    if not order:
        app.logger.warning('Order not found for user: %s', session.get('username', 'unknown'))
        flash("Order not found", "error")
        return redirect(url_for('home'))

    order_item = OrderItem(
        order_id=order.order_id,
        item_name=product['name'],
        item_price=product['price'],
        quantity=int(request.form['quantity']),
        collection_type=order.collection_type,
        image_path=product['image_path']
    )

    try:
        db.session.add(order_item)
        db.session.commit()
        app.logger.info('Product added to cart successfully: %s, Order ID: %s', product_id, order.order_id)

        flash("Product added to cart successfully", "success")
        return redirect(url_for('show_products'))

    except Exception as e:
        db.session.rollback()
        flash("An error occurred while adding the product to your cart. Please try again later.", "error")
        app.logger.error(f"Error adding product to cart: {str(e)}")
        return redirect(url_for('home'))


@app.route('/view_cart')
@limiter.limit("10/minute")
def view_cart():
    if 'username' not in session:
        app.logger.warning('Unauthorized access attempt to view cart')
        flash('You must be logged in to add payment details.', 'danger')
        return redirect(url_for('login'))

    if 'started_order_process' not in session or not session['started_order_process']:
        app.logger.warning('Attempt to view cart without starting order process by user: %s',
                           session.get('username', 'unknown'))
        flash("You must start the order process from the order-collection page.", "error")
        return redirect(url_for('order_collection'))

    try:
        order = Order.query.order_by(Order.id.desc()).first()

        if not order:
            return "Order not found"

        order_items = order.items

        subtotal = calculate_subtotal(order_items)
        sales_tax = calculate_sales_tax(subtotal)
        delivery_amount = calculate_delivery_amount(order.collection_type)
        grand_total = calculate_grand_total(subtotal, sales_tax, delivery_amount, order.collection_type)

        return render_template('view_cart.html', cart=order_items, subtotal=subtotal, sales_tax=sales_tax,
                               delivery_amount=delivery_amount, grand_total=grand_total)

    except Exception as e:
        return f"An error occurred: {str(e)}"


@app.route('/update_cart_item/<int:item_id>', methods=['POST', 'GET'])
@limiter.limit("10/minute")
def update_cart_item(item_id):
    try:
        order = Order.query.order_by(Order.id.desc()).first()

        if not order:
            app.logger.warning('Order not found for user: %s', session.get('username', 'unknown'))
            flash("Order not found", "error")
            return redirect(url_for('home'))

        order_item = OrderItem.query.get(item_id)

        if not order_item:
            app.logger.warning('Order item not found for user: %s', session.get('username', 'unknown'))
            flash("Order item not found", "error")
            return redirect(url_for('home'))

        new_quantity = request.form.get('quantity', '0')
        try:
            new_quantity = int(new_quantity)
        except ValueError:
            flash("Invalid quantity value", "error")
            return redirect(url_for('view_cart'))

        order_item.quantity = new_quantity
        db.session.commit()
        app.logger.info('Cart item updated (item_id: %d) for user: %s', item_id, session.get('username', 'unknown'))

    except Exception as e:
        db.session.rollback()
        app.logger.error('Error updating cart item (item_id: %d) for user: %s, Exception: %s', item_id,
                         session.get('username', 'unknown'), str(e))
        return f"An error occurred: {str(e)}"

    return redirect(url_for('view_cart'))


@app.route('/remove_from_cart/<int:item_id>', methods=['POST'])
@limiter.limit("10/minute")
def remove_from_cart(item_id):
    try:
        order_item = OrderItem.query.get(item_id)

        if not order_item:
            app.logger.warning('Order item not found for user: %s', session.get('username', 'unknown'))
            flash("Order item not found", "error")
            return redirect(url_for('home'))

        db.session.delete(order_item)
        db.session.commit()
        app.logger.info('Order item removed (item_id: %d) for user: %s', item_id, session.get('username', 'unknown'))

        return redirect(url_for('view_cart'))

    except Exception as e:
        db.session.rollback()
        return f"An error occurred: {str(e)}"


@app.route('/payment', methods=['GET', 'POST'])
@limiter.limit("10/minute")
def payment_page():

    payment_detail = None

    if 'username' not in session:
        flash('You must be logged in to add payment details.', 'danger')
        return redirect(url_for('login'))

    if 'started_order_process' not in session or not session['started_order_process']:
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
            app.logger.info('Payment details displayed for user: %s', session.get('username', 'unknown'))
            return render_template('payment.html', payment_details_list=payment_details_list, has_payment_details=True)
    else:
        app.logger.warning('User not found while accessing payment page')
        return redirect(url_for('/'))


@app.route('/submit_payment', methods=['POST'])
@limiter.limit("10/minute")
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
                    app.logger.warning('Incomplete payment details provided by user: %s',
                                       session.get('username', 'unknown'))
                    flash("Please provide all required card details", "error")
                    return redirect(url_for('payment_page'))

                new_payment = Payment(username=session["username"], card_number=encrypted_card_num,
                                      expiration_date=expiration_date, cvv=encrypted_cvv, card_name=card_name)
                db.session.add(new_payment)
                db.session.commit()

                app.logger.info('New payment details added successfully for user: %s',
                                session.get('username', 'unknown'))
                flash('New payment details added successfully.', 'success')
                return redirect(url_for('success_payment'))

            elif payment_detail:
                selected_payment = Payment.query.get(payment_detail)
                if not selected_payment:
                    app.logger.warning('Selected payment not found (payment_id: %s) for user: %s', payment_detail,
                                       session.get('username', 'unknown'))
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

        except Exception as e:
            flash(f"An error occurred: {str(e)}", "error")


@app.route('/success_payment')
@limiter.limit("10/minute")
def success_payment():
    user = User.query.filter_by(username=session["username"]).first()
    if user:
        try:
            app.logger.info('Starting payment processing for user: %s', user.username)

            order = Order.query.order_by(Order.id.desc()).first()

            if not order:
                flash("Order not found", "error")
                return redirect(url_for('home'))

            order_items = order.items

            subtotal = calculate_subtotal(order_items)
            sales_tax = calculate_sales_tax(subtotal)
            delivery_amount = calculate_delivery_amount(order.collection_type)
            grand_total = calculate_grand_total(subtotal, sales_tax, delivery_amount, order.collection_type)

            grand_total_cents = int(grand_total * 100)
            points_earned = 5 * (grand_total_cents // 100)

            user_points_record = UserPoints.query.filter_by(username=user.username).first()
            if user_points_record:
                user_points_record.points += points_earned
            else:
                db.session.add(UserPoints(username=user.username, points=points_earned))
            db.session.commit()

            order.grand_total = grand_total
            db.session.commit()

            session.pop('started_order_process', None)
            app.logger.info('Order %s successfully processed and cleared from database', order.order_id)

            return render_template('success_payment.html', order_id=order.order_id, order_data=order.collection_type, grand_total=grand_total, collection_type=order.collection_type, order_cart=order_items, points_earned=points_earned)

        except Exception as e:
            db.session.rollback()
            app.logger.error(f"An unexpected error occurred: {str(e)}", exc_info=True)
            flash("An unexpected error occurred. Please try again later.", "error")
            return redirect(url_for('home'))

    else:
        flash("User not found", "error")
        return redirect(url_for('home'))


@app.route('/orderHistory', methods=["GET"])
@limiter.limit("10/minute")
def order_history():
    username = session.get('username')
    orders = Order.query.filter(and_(Order.username == username, Order.grand_total.isnot(None))).all()

    if orders:
        return render_template('order_history.html', orders=orders, username=username)
    else:
        return redirect(url_for('home'))


@app.route('/customerOrder', methods=["GET"])
@limiter.limit("10/minute")
def customer_order():
    if session.get('role') == 'user':
        app.logger.warning('Unauthorized access attempt to customer order page by user %s',
                           session.get('username', 'unknown'))
        return "Access Denied. This feature requires staff & admin level access!", 403

    orders = Order.query.filter(Order.grand_total.isnot(None)).order_by(Order.created_at.desc()).all()

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
@limiter.limit("5/minute")
def create_feedback():
    create_feedback_form = CreateFeedbackForm(request.form)
    if request.method == 'POST' and create_feedback_form.validate():
        create_feedback_form.sanitize_fields()

        # Create a new feedback instance with sanitized data
        new_feedback = Feed_back(
            name=create_feedback_form.name.data,
            mobile_no=create_feedback_form.mobile_no.data,
            service=create_feedback_form.service.data,
            food=create_feedback_form.food.data,
            feedback=create_feedback_form.feedback.data
        )

        db.session.add(new_feedback)
        db.session.commit()

        return redirect(url_for('contact_us'))
    return render_template('createFeedback.html', form=create_feedback_form)


@app.route('/retrieveFeedback')
@limiter.limit("3/minute")
def retrieve_feedback():
    if session.get('role') != 'admin':
        return "Access Denied. This feature requires admin-level access!", 403

    feedbacks = Feed_back.query.all()
    feedbacks_list = []

    # Compile a list of feedback dictionaries for rendering
    for feedback in feedbacks:
        feedbacks_list.append({
            'id': feedback.id,
            'name': feedback.name,
            'mobile_no': feedback.mobile_no,
            'service': feedback.service,
            'food': feedback.food,
            'feedback': feedback.feedback,
        })

    return render_template('retrieveFeedback.html', count=len(feedbacks_list), feedbacks_list=feedbacks_list)


@app.route('/deleteFeedback/<int:feedback_id>', methods=['POST'])
@limiter.limit("3/minute")
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
