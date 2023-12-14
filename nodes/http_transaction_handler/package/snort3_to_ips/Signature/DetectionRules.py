from exception import SnortHookException


class DetectionRules:

    def __init__(self):
        self.data = {
            "type": "simple",
            "SSM": "",
            "keywords": "",
            "context": []
        }

    def validate(self):
        if self.data["context"] and (len(self.data["keywords"]) or len(self.data["SSM"])):
            pass
        else:
            raise SnortHookException("No detection rule in the rule")

    def set_default_if_needed(self):
        pass

    def is_key_valid(self, key):
        if key in self.data.keys():
            return True
        return False

    def parse_data(self, key, value):
        self.parse_func_map[key](self, value)

    def parse_keywords_data(self, value):
        if len(self.data["keywords"]) != 0:
            self.data["keywords"] += " "
        self.data["keywords"] += value

    def parse_context_data(self, value):
        if value not in self.data["context"]:
            self.data["context"].append(value)

    def parse_ssm_data(self, value):
        if self.data["SSM"] != "":
            raise SnortHookException("two fast_pattern content")
        self.data["SSM"] += value

    def parse_type_data(self, value):
        raise SnortHookException("DetectionRules of type not implemented")

    parse_func_map = {
        "type": parse_type_data,
        "SSM": parse_ssm_data,
        "keywords": parse_keywords_data,
        "context": parse_context_data
    }
