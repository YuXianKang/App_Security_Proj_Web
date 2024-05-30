class Feedback():

    def __init__(self,name,mobile_no,service,food,feedback):
        self.__name = name
        self.__mobile_no = mobile_no
        self.__service = service
        self.__food = food
        self.__feedback = feedback

    def get_name(self):
        return self.__name

    def get_mobile_no(self):
        return self.__mobile_no

    def get_service(self):
        return self.__service

    def get_food(self):
        return self.__food

    def get_feedback(self):
        return self.__feedback

    def set_name(self,name):
        self.__name = name

    def set_mobile_no(self,mobile_no):
        self.__mobile_no = mobile_no

    def set_service(self,service):
        self.__service = service

    def set_food(self,food):
        self.__food = food

    def set_feedback(self,feedback):
        self.__feedback = feedback