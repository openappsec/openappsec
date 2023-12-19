class ProtectionMetadata:

    def __init__(self):
        self.data = {
            "protectionName": "",
            "severity": "",
            "confidenceLevel": "",
            "performanceImpact": "",
            "lastUpdate": "",
            "maintrainId": "",
            "tags": ["Snort"],
            "cveList": [],
            "silent": False
        }

    def validate(self):
        if len(self.data["protectionName"]) == 0:
            raise Exception("msg field missing in the snort rule")

    def set_default_if_needed(self):
        if self.data["severity"] == "":
            self.data["severity"] = "Critical"
        if self.data["confidenceLevel"] == "":
            self.data["confidenceLevel"] = "High"
        if self.data["performanceImpact"] == "":
            self.data["performanceImpact"] = "Medium"
        if self.data["lastUpdate"] == "":
            self.data["lastUpdate"] = "20210909"

    def is_key_valid(self, key):
        if key in self.data.keys():
            return True
        return False

    def parse_data(self, key, value):
        self.parse_func_map[key](self, key, value)

    def parse_name_data(self, key, value):
        self.data[key] = value

    def parse_cvelist(self, key, value):
        if value not in self.data[key]:
            self.data[key].append(value)

    def parse_severity(self, key, value):
        self.data[key] = value

    def parse_main_train_id(self, key, value):
        if self.data[key] != "":
            self.data[key] += " "
        self.data[key] += value

    def parse_tags(self, key, value):
        if value not in self.data[key]:
            self.data[key].append(value)

    def not_implemented(self, key, value):
        print("Not implemented for key {} with value {}".format(key, value))

    parse_func_map = {
        "protectionName": parse_name_data,
        "severity": parse_severity,
        "confidenceLevel": not_implemented,
        "performanceImpact": not_implemented,
        "lastUpdate": not_implemented,
        "maintrainId": parse_main_train_id,
        "tags": parse_tags,
        "cveList": parse_cvelist,
        "silent": not_implemented,
    }
