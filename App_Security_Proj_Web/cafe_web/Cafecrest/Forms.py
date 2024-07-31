from wtforms import Form, StringField,FloatField, validators, SelectField, ValidationError, IntegerField, FileField, SubmitField
from wtforms.validators import DataRequired

class CreateProductForm(Form):
    name = StringField('Product name', [validators.Length(min=1, max=150), validators.DataRequired()])
    product = StringField('Product type (food / coffee / non_coffee)', [validators.Length(min=1, max=150), validators.DataRequired()])
    description = StringField('Description', [validators.DataRequired()])
    price = IntegerField('Enter the price in $')
    photos = FileField('Photos', [validators.DataRequired()])
    submit = SubmitField('Submit')


class payment(Form):
    card_number = StringField('Card Num (include 1 space after 4 numbers)', [validators.Length(min=19, max=19, message='Card number must be 16 digits with spaces'), validators.Regexp(r'^\d{4} \d{4} \d{4} \d{4}$', message='Invalid card number format (XXXX XXXX XXXX XXXX)'), validators.DataRequired(message='Card number is required')])
    expiration_date = StringField('Expiration Date (mm/yy)', [validators.Length(min=5, max=5, message='Invalid expiration date format'), validators.Regexp(r'^(0[1-9]|1[0-2])\/\d{2}$', message='Invalid expiration date format (mm/yy)'), validators.DataRequired(message='Expiration date is required')])
    cvv = StringField('CVV', [validators.Length(min=3, max=3, message='CVV must be 3 digits'), validators.Regexp(r'^\d{3}$', message='CVV must be 3 digits'), validators.DataRequired(message='CVV is required')])
    card_name = StringField('Card Name (all caps)', [validators.Regexp(r'^[A-Z ]+$', message='Card name should be in all caps and contain only letters and spaces'), validators.DataRequired(message='Card name is required')])


class collection_type (Form):
    collection_type = SelectField('Collection Type', choices=[('pickup', 'In-Store Pickup'), ('dine-in', 'Dine-In')],)



def validate_name(form, field):
    if field.data.isalpha() == 0:
        raise ValidationError('Name must only contain alphabets')


def validate_mobile(form, field):
    if field.data.isdigit() == 0:
        raise ValidationError('Mobile number must only contain numbers')


class CreateFeedbackForm(Form):
    name = StringField('Name', [validators.Length(min=1, max=150), validators.DataRequired(), validate_name])
    mobile_no = StringField('Mobile Number', [validators.length(min=8, max=8), validators.DataRequired(), validate_mobile])
    service = StringField('Service', [validators.Length(min=1, max=200), validators.DataRequired()])
    food = StringField('Food', [validators.Length(min=1, max=200), validators.DataRequired()])
    feedback = StringField('Additional Feedback', [validators.Length(min=1, max=200), validators.DataRequired()])
