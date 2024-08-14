from wtforms import Form, StringField, validators
import html
import re


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
