from flask import jsonify, Blueprint, request

eh = Blueprint('errors', __name__)


def create_error_response(status_code, title=None, detail=None):
    response = {
        "status": status_code,
        "title": title,
        "detail": detail,
        "request_path": request.path,
        "method": request.method,
    }
    return jsonify(response), status_code


@eh.errorhandler(400)
def bad_request(error):
    return create_error_response(400, title="Bad Request", detail=error.description)


@eh.errorhandler(403)
def forbidden():
    return create_error_response(403, title="Forbidden", detail="You do not have permission to access this resource.")


@eh.errorhandler(404)
def not_found():
    return create_error_response(404, title="Not Found", detail="The requested resource does not exist.")


@eh.errorhandler(429)
def rate_limit_handler():
    return create_error_response(429, title="Too Many Requests", detail="Rate limit exceeded. Please try again later.")


@eh.errorhandler(500)
def internal_server_error():
    return create_error_response(500, title="Internal Server Error", detail="An unexpected error occurred on our end.")


@eh.errorhandler(504)
def gateway_timeout():
    return create_error_response(504, title="Gateway Timeout", detail="The server did not receive a timely response from another server it was accessing while attempting to load the web page or fulfill another request by the browser.")


@eh.errorhandler(Exception)
def handle_all_errors(e):
    return create_error_response(500, title="Server Error", detail=str(e)), 500
