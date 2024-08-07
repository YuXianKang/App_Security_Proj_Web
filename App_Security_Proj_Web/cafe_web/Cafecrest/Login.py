class Login:
    def __init__(self, mobile_no, password, role):
        self.__mobile_no = mobile_no
        self.__password = password
        self.__role = role

    def get_mobile_no(self):
        return self.__mobile_no

    def get_password(self):
        return self.__password

    def set_mobile_no(self, mobile_no):
        self.__mobile_no = mobile_no

    def set_password(self, password):
        self.__password = password

    def get_role(self):
        return self.__role

    def set_role(self, role):
        self.__role = role

