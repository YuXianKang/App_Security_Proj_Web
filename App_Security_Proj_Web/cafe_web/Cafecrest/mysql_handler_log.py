import pymysql
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
            self.connection = pymysql.connect(
                host=self.host,
                database=self.database,
                user=self.user,
                password=self.password
            )
            self.cursor = self.connection.cursor()
        except pymysql.Error as e:
            print(f"Error connecting to MySQL: {e}")

    def emit(self, record):
        try:
            if not self.connection or not self.connection.open:
                self.connect()

            if self.connection and self.cursor:
                log_entry = self.format(record)
                insert_query = f"INSERT INTO {self.table} (message) VALUES (%s)"
                self.cursor.execute(insert_query, (log_entry,))
                self.connection.commit()
            else:
                print("Error: MySQL connection or cursor is not available.")
        except pymysql.Error as e:
            print(f"Error inserting log entry into MySQL: {e}")

    def close(self):
        if self.connection and self.connection.open:
            self.cursor.close()
            self.connection.close()
        super().close()
