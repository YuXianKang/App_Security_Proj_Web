import logging
from mysql_handler_log import MySQLHandler


def configure_logging(app):
    handler = MySQLHandler(
        host='localhost',
        database='cafecrest',
        user='cafecrest',
        password='Oscar1oscar1',
        table='logs'
    )
    handler.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    app.logger.addHandler(handler)
