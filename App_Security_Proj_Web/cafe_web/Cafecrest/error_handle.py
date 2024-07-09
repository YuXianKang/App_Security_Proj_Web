from flask import jsonify, Blueprint

eh = Blueprint('errors', __name__)


def create_error_response(status_code, title=None, detail=None):
    response = {
        "status": status_code,
        "title": title,
        "detail": detail,
    }
    return jsonify(response), status_code


@eh.errorhandler(400)
def bad_request(error):
    return create_error_response(400, title="Bad Request", detail=error.description)


@eh.errorhandler(404)
def not_found():
    return create_error_response(404, title="Not Found", detail="The requested resource does not exist.")


@eh.errorhandler(429)
def rate_limit_handler():
    return create_error_response(429, title="Too Many Requests", detail="Rate limit exceeded. Please try again later.")


@eh.errorhandler(500)
def internal_server_error():
    return create_error_response(500, title="Internal Server Error", detail="An unexpected error occurred on our end.")


@eh.errorhandler(Exception)
def handle_all_errors(e):
    return create_error_response(500, title="Server Error", detail=str(e)), 500
