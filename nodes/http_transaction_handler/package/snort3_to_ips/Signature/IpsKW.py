from exception import SnortHookException


class IpsKW:

    def __init__(self, keyword, value, optional_modifier):
        self.keyword = keyword
        self.value = value
        self.optional_modifiers = optional_modifier

    def construct(self):
        return self.construct_func_map[self.keyword](self)

    def construct_name(self):
        return [("protectionName", self.value)]

    def construct_detection_keyword(self):
        constructed_data = []
        optional_modifier_str = ""
        for key in self.optional_modifiers:
            if key in ['nocase', 'relative']:
                optional_modifier_str += ", " + key
            elif key == 'depth':
                optional_modifier_str += ", {} {}".format(key, self.optional_modifiers[key])
            elif key == 'offset':
                if self.optional_modifiers[key] == 0:
                    continue
                optional_modifier_str += ", {} {}".format(key, self.optional_modifiers[key])
            elif key == 'part':
                optional_modifier_str += ", {} {}".format(key, self.optional_modifiers[key])
                constructed_data.append(("context", self.optional_modifiers[key]))
            else:
                raise SnortHookException("Error: Key '{}' is not supported in keywords".format(key))
        constructed_data.append(("keywords", "data: {}{};".format(self.value, optional_modifier_str)))
        return constructed_data

    def construct_pcre(self):
        constructed_data = []
        optional_modifier_str = ""
        for key in self.optional_modifiers:
            if key in ['nocase', 'relative']:
                optional_modifier_str += ", " + key
            elif key in ['offset']:
                if self.optional_modifiers[key] == 0:
                    continue
                optional_modifier_str += ", {} {}".format(key, self.optional_modifiers[key])
            elif key == 'part':
                optional_modifier_str += ", {} {}".format(key, self.optional_modifiers[key])
                constructed_data.append(("context", self.optional_modifiers[key]))
            else:
                raise SnortHookException("Error: Key {} is not supported in pcre".format(key))
        constructed_data.append(("keywords", "pcre: {}{};".format(self.value, optional_modifier_str)))
        return constructed_data

    def construct_SSM_keyword(self):
        constructed_data = []
        for key in self.optional_modifiers:
            if key == 'part':
                constructed_data.append(("context", self.optional_modifiers[key]))
        constructed_data.append(("SSM", self.value.strip("\"")))

        return constructed_data

    def construct_length_keyword(self):
        return [("keywords", "{}: {}, {}, part {};".format(self.keyword, self.optional_modifiers['var'],
                                                           self.value, self.optional_modifiers['part']))]

    def construct_cvelist(self):
        return [(self.keyword, self.value)]

    def construct_severity(self):
        return [(self.keyword, self.value)]

    def construct_tags(self):
        return [(self.keyword, "Vul_Type_{}".format(self.value))]

    def construct_sid_rev(self):
        return [("maintrainId", "{}:{}".format(self.keyword, self.value))]

    construct_func_map = {
        'protectionName': construct_name,
        'keywords': construct_detection_keyword,
        'length': construct_length_keyword,
        'SSM': construct_SSM_keyword,
        'tags': construct_tags,
        'pcre': construct_pcre,
        'cveList': construct_cvelist,
        'severity': construct_severity,
        'sid': construct_sid_rev,
        'rev': construct_sid_rev
    }
