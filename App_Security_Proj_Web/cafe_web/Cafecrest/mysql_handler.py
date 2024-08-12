import mysql.connector
from mysql.connector import Error
import logging

class MySQLHandler(logging.Handler):
    def __init__(self, host, database, user, password, table):
        super().__init__()
        self.host = host
        self.database = database
        self.user = user
        self.password = password
        self.table = table
        self.connection = None
        self.cursor = None
        self.connect()

    def connect(self):
        try:
            self.connection = mysql.connector.connect(
                host=self.host,
                database=self.database,
                user=self.user,
                password=self.password
            )
            self.cursor = self.connection.cursor()
        except Error as e:
            print(f"Error connecting to MySQL: {e}")

    def emit(self, record):
        try:
            if not self.connection or not self.connection.is_connected():
                self.connect()

            log_entry = self.format(record)
            insert_query = f"INSERT INTO {self.table} (message) VALUES (%s)"
            self.cursor.execute(insert_query, (log_entry,))
            self.connection.commit()
        except Error as e:
            print(f"Error inserting log entry into MySQL: {e}")

    def close(self):
        if self.connection and self.connection.is_connected():
            self.cursor.close()
            self.connection.close()
        super().close()
