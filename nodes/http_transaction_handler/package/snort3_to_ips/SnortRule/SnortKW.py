from snort3_to_ips.Signature.IpsKW import IpsKW
from snort3_to_ips.utils.utils import is_hex_segment_in_str
from exception import SnortHookException


class SnortKW:

    def __init__(self, keyword, value, optional_modifiers):
        self.keyword = keyword
        self.value = value
        self.optional_modifiers = optional_modifiers

    def convert(self, snort_rule):
        return self.convert_func_map[self.keyword](self, snort_rule)

    def convert_snort_content_kw(self, snort_rule):
        ips_data_modifiers = self.get_ips_modifiers_from_rule(snort_rule)
        if ips_data_modifiers.pop('fast_pattern', False) and not is_hex_segment_in_str(self.value):
            return [IpsKW("SSM", self.value, ips_data_modifiers)]
        return [IpsKW("keywords", self.value, ips_data_modifiers)]

    def convert_snort_pcre_kw(self, snort_rule):
        ips_data_modifiers = snort_rule.get_ips_context()
        return [IpsKW("pcre", self.value, ips_data_modifiers)]

    def convert_snort_flow_kw(self, snort_rule):
        for modifier in self.optional_modifiers:
            if modifier == "to_server" or modifier == "from_client":
                snort_rule.flow = "client_to_server"
            elif modifier == "to_client" or modifier == "from_server":
                snort_rule.flow = "server_to_client"
            elif modifier in ["established", "not_established", "stateless"]:
                pass
            elif modifier in ["no_stream", "only_stream"]:
                pass
            elif modifier in ["no_frag", "only_frag"]:
                pass
            else:
                raise SnortHookException("unsupported modifier for '{}': '{}'".format(self.keyword, modifier))
        return []

    def convert_snort_msg_kw(self, snort_rule):
        return [IpsKW("protectionName", self.value.strip("\""), "")]

    def convert_snort_sticky_buffer(self, snort_rule):
        snort_rule.sticky_buffer = self.keyword
        if self.value != "":
            if self.keyword != "http_header":
                raise SnortHookException("arguments are not supported for '{}' of value '{}'".format(self.keyword, self.value))
            if self.value == "field":
                snort_rule.dynamic_buffer = self.optional_modifiers
            else:
                raise SnortHookException("Unknown argument for '{}', '{}'".format(self.keyword, self.value))
        return []

    def convert_snort_reference(self, snort_rule):
        if self.value == 'bugtraq':
            return [IpsKW("cveList", "BUGTRAQ-{}".format(self.optional_modifiers[self.value]), "")]
        elif self.value == 'cve':
            return [IpsKW("cveList", "CVE-{}".format(self.optional_modifiers[self.value]), "")]
        elif self.value == 'nessus':
            return [IpsKW("cveList", "NESSUS-{}".format(self.optional_modifiers[self.value]), "")]
        elif self.value == 'arachnids':
            return [IpsKW("cveList", "ARACHNIDS-{}".format(self.optional_modifiers[self.value]), "")]
        elif self.value == 'mcafee':
            return [IpsKW("cveList", "MCAFEE-{}".format(self.optional_modifiers[self.value]), "")]
        elif self.value == 'osvdb':
            return [IpsKW("cveList", "OSVDB-{}".format(self.optional_modifiers[self.value]), "")]
        elif self.value == 'msb':
            return [IpsKW("cveList", "MSB-{}".format(self.optional_modifiers[self.value]), "")]
        elif self.value == 'url':
            return [IpsKW("cveList", "http://{}".format(self.optional_modifiers[self.value]), "")]
        else:
            raise SnortHookException("Unknown system in Reference of value: {}".format(self.value))

    def convert_snort_classtype(self, snort_rule):
        return [IpsKW("severity", self.optional_modifiers[self.value], ""),
                IpsKW("tags", self.value.replace("-", " ").title().replace(" ", "_"), "")]

    def convert_snort_priority(self, snort_rule):
        return [IpsKW("severity", self.value, "")]

    def convert_snort_bufferlen_kw(self, snort_rule):
        ips_kw_list = []
        ips_data_modifiers = snort_rule.get_ips_context()
        if "<=>" in self.value:
            left_var, right_var = self.value.split("<=>")
            if not left_var.isnumeric() or not right_var.isnumeric():
                raise SnortHookException("bufferlen - illegal numerical value")
            ips_data_modifiers['var'] = left_var
            ips_kw_list.append(IpsKW("length", "min", ips_data_modifiers))
            ips_data_modifiers = snort_rule.get_ips_context()
            ips_data_modifiers['var'] = right_var
            ips_kw_list.append(IpsKW("length", "max", ips_data_modifiers))
        elif "<>" in self.value:
            left_var, right_var = self.value.split("<>")
            ips_data_modifiers['var'] = left_var
            if not left_var.isnumeric() or not right_var.isnumeric():
                raise SnortHookException("bufferlen - illegal numerical value")
            ips_kw_list.append(IpsKW("length", "min", ips_data_modifiers))
            ips_data_modifiers = snort_rule.get_ips_context()
            ips_data_modifiers['var'] = right_var
            ips_kw_list.append(IpsKW("length", "max", ips_data_modifiers))
        elif "<" in self.value:
            if not self.value.split("<")[1].isnumeric():
                raise SnortHookException("bufferlen - illegal numerical value")
            ips_data_modifiers['var'] = self.value.split("<")[1]
            ips_kw_list.append(IpsKW("length", "max", ips_data_modifiers))
        elif ">" in self.value:
            ips_data_modifiers['var'] = self.value.split(">")[1]
            if not self.value.split(">")[1].isnumeric():
                raise SnortHookException("bufferlen - illegal numerical value")
            ips_kw_list.append(IpsKW("length", "min", ips_data_modifiers))
        elif self.value.isnumeric():
            ips_data_modifiers['var'] = self.value
            ips_kw_list.append(IpsKW("length", "exact", ips_data_modifiers))
        else:
            raise SnortHookException("bufferlen operator is illegal")
        return ips_kw_list

    def convert_sid_kw(self, snort_rule):
        return [IpsKW("sid", self.value, "")]

    def convert_rev_kw(self, snort_rule):
        return [IpsKW("rev", self.value, "")]

    def not_implemented(self, snort_rule):
        return []

    convert_func_map = {
        # Primarily functions
        'content': convert_snort_content_kw,
        'pcre': convert_snort_pcre_kw,
        'bufferlen': convert_snort_bufferlen_kw,
        'flow': convert_snort_flow_kw,
        # metadata functions
        'msg': convert_snort_msg_kw,
        'reference': convert_snort_reference,
        'gid': not_implemented,
        'sid': convert_sid_kw,
        'rev': convert_rev_kw,
        'classtype': convert_snort_classtype,
        'priority': convert_snort_priority,
        'metadata': not_implemented,
        # http functions
        'pkt_data': convert_snort_sticky_buffer,
        'http_uri': convert_snort_sticky_buffer,
        'http_raw_uri': convert_snort_sticky_buffer,
        'http_header': convert_snort_sticky_buffer,
        'http_raw_header': convert_snort_sticky_buffer,
        'http_method': convert_snort_sticky_buffer,
        'http_client_body': convert_snort_sticky_buffer,
        'http_cookie': convert_snort_sticky_buffer,
        'http_raw_cookie': convert_snort_sticky_buffer,
        'http_stat_code': convert_snort_sticky_buffer,
        'http_stat_msg': convert_snort_sticky_buffer,
        'http_encode': convert_snort_sticky_buffer,
        # backward compatibility rules.
        'service': not_implemented
    }

    def get_ips_modifiers_from_rule(self, snort_rule):

        ips_data_modifiers = {}

        for rule in self.optional_modifiers:
            if rule == 'nocase':
                ips_data_modifiers['nocase'] = self.optional_modifiers['nocase']
            elif rule == 'depth':
                ips_data_modifiers['depth'] = self.optional_modifiers['depth']
            elif rule == 'distance':
                if int(self.optional_modifiers['distance']) != 0:
                    ips_data_modifiers['offset'] = self.optional_modifiers['distance']
                ips_data_modifiers['relative'] = True
            elif rule == 'offset':
                if int(self.optional_modifiers['offset']) != 0:
                    ips_data_modifiers['offset'] = self.optional_modifiers['offset']
            elif rule == 'within':
                ips_data_modifiers['depth'] = self.optional_modifiers['within']
                ips_data_modifiers['relative'] = True
            elif rule == 'fast_pattern':
                ips_data_modifiers['fast_pattern'] = True
            else:
                # print("Error: Not supported convert from {}".format(rule))
                raise SnortHookException("For keyword '{}', unsupported modifier '{}'".format(self.keyword, rule))

        ips_data_modifiers.update(snort_rule.get_ips_context())

        return ips_data_modifiers

