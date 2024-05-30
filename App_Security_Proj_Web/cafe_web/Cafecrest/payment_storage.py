class payment_details:
    count_id = 0

    def __init__(self, card_number, expiration_date, cvv, card_name):
        payment_details.count_id += 1
        self.__payment_details_id = payment_details.count_id
        self.__card_number = card_number
        self.__expiration_date = expiration_date
        self.__cvv = cvv
        self.__card_name = card_name

    def set_payment_details_id(self, payment_details_id):
        self.__payment_details_id = payment_details_id

    def get_payment_details_id(self):
        return self.__payment_details_id

    def set_card_number(self, card_number):
        self.__card_number = card_number

    def get_card_number(self):
        return self.__card_number

    def set_expiration_date(self, expiration_date):
        self.__expiration_date = expiration_date

    def get_expiration_date(self):
        return self.__expiration_date

    def set_cvv(self, cvv):
        self.__cvv = cvv

    def get_cvv(self):
        return self.__cvv

    def set_card_name(self, card_name):
        self.__card_name = card_name

    def get_card_name(self):
        return self.__card_name
