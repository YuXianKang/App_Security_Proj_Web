from Login import Login


class SignUp(Login):
    count_id = 0

    def __init__(self,first_name,last_name,mobile_no,password,email):
        super().__init__(mobile_no,password)
        self.__role = "Customer"
        SignUp.count_id += 1
        self.__account_id = SignUp.count_id
        self.__first_name = first_name
        self.__last_name = last_name
        self.__email = email

    def get_account_id(self):
        return self.__account_id

    def get_first_name(self):
        return self.__first_name

    def get_last_name(self):
        return self.__last_name

    def get_email(self):
        return self.__email

    def set_account_id(self,account_id):
        self.__account_id = account_id

    def set_first_name(self,first_name):
        self.__first_name = first_name

    def set_last_name(self,last_name):
        self.__last_name = last_name

    def set_email(self,email):
        self.__email = email

    def set_role(self, role):
        self.__role = role

    def get_role(self):
        return self.__role

    def __str__(self):
        return self.__email
