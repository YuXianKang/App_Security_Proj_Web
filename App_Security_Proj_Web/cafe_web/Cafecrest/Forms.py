from wtforms import Form, StringField, validators, SelectField, ValidationError, IntegerField, FileField, SubmitField
from wtforms.validators import DataRequired
import html
import re


class CreateProductForm(Form):
    name = StringField('Product name', [validators.Length(min=1, max=150), validators.DataRequired()])
    product = StringField('Product type (food / coffee / non_coffee)', [validators.Length(min=1, max=150), validators.DataRequired()])
    description = StringField('Description', [validators.DataRequired()])
    price = IntegerField('Enter the price in $')
    photos = FileField('Photos', [validators.DataRequired()])
    submit = SubmitField('Submit')


class payment(Form):
    card_number = StringField('Card Num', [validators.Length(min=19, max=19, message='Card number must be 16 digits with spaces'), validators.Regexp(r'^\d{4} \d{4} \d{4} \d{4}$', message='Invalid card number format (XXXX XXXX XXXX XXXX)'), validators.DataRequired(message='Card number is required')])
    expiration_date = StringField('Expiration Date', [validators.Length(min=5, max=5, message='Invalid expiration date format'), validators.Regexp(r'^(0[1-9]|1[0-2])\/\d{2}$', message='Invalid expiration date format (mm/yy)'), validators.DataRequired(message='Expiration date is required')])
    cvv = StringField('CVV', [validators.Length(min=3, max=3, message='CVV must be 3 digits'), validators.Regexp(r'^\d{3}$', message='CVV must be 3 digits'), validators.DataRequired(message='CVV is required')])
    card_name = StringField('Card Name', [validators.Regexp(r'^[A-Z ]+$', message='Card name should be in all caps and contain only letters and spaces'), validators.DataRequired(message='Card name is required')])


class collection_type (Form):
    collection_type = SelectField('Collection Type', choices=[('pickup', 'In-Store Pickup'), ('dine-in', 'Dine-In')],)

def sanitize_input(user_input):
    # Escape HTML to prevent XSS attacks
    escaped_input = html.escape(user_input)
    # Remove any unwanted characters
    sanitized_input = re.sub(r'[^\w\s.@+-]', '', escaped_input)
    return sanitized_input

def validate_name(form, field):
    if not re.match(r'^[a-zA-Z\s]+$', field.data):
        raise validators.ValidationError('Name can only contain letters and spaces.')

def validate_mobile(form, field):
    if not re.match(r'^\d{8}$', field.data):
        raise validators.ValidationError('Mobile number must be exactly 8 digits long.')

class CreateFeedbackForm(Form):
    name = StringField('Name', [validators.Length(min=1, max=150), validators.DataRequired(), validate_name])
    mobile_no = StringField('Mobile Number', [validators.length(min=8, max=8), validators.DataRequired(), validate_mobile])
    service = StringField('Service', [validators.Length(min=1, max=200), validators.DataRequired()])
    food = StringField('Food', [validators.Length(min=1, max=200), validators.DataRequired()])
    feedback = StringField('Additional Feedback', [validators.Length(min=1, max=200), validators.DataRequired()])

    def sanitize_fields(self):
        self.name.data = sanitize_input(self.name.data)
        self.mobile_no.data = sanitize_input(self.mobile_no.data)
        self.service.data = sanitize_input(self.service.data)
        self.food.data = sanitize_input(self.food.data)
        self.feedback.data = sanitize_input(self.feedback.data)
