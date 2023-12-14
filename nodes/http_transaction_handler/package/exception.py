class SnortHookException(Exception):

    def __init__(self, message="", practice_id=""):
        self.message = message
        self.practice_id = practice_id

    def __str__(self):
        return "{}".format(self.message)
