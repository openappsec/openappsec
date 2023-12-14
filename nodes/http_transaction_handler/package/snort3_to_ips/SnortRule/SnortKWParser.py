from exception import SnortHookException

class SnortKWParser:

    def __init__(self):
        pass

    def parse_kw_parameters(self, snort_rule):
        tmp_split = snort_rule.split(":")
        keyword = tmp_split[0]
        return self.parse_func_map[keyword](self, snort_rule)

    def simple_rule(self, snort_rule):
        return snort_rule.strip(), "", {}

    def simple_binary_rule(self, snort_rule):
        keyword, value = snort_rule.split(":")
        return keyword, value, {}

    def parse_content(self, snort_rule):
        tmp_split = snort_rule.split(":", 1)
        keyword = tmp_split[0]

        value = tmp_split[1][:tmp_split[1].find("\"", 2) + 1].strip()
        optional_string = tmp_split[1][tmp_split[1].find("\"", 2) + 1:].strip(",").strip()

        if optional_string == "":
            return keyword, value, {}

        optional_modifiers = {}
        for optional_command in optional_string.split(","):
            optional_command = optional_command.strip()
            command = optional_command.strip().split(" ", 1)
            if len(command) == 1:
                optional_modifiers[command[0]] = True
            else:
                optional_modifiers[command[0]] = command[1]
        return keyword, value, optional_modifiers

    def parse_pcre(self, snort_rule):
        tmp_split = snort_rule.split(":", 1)
        keyword = tmp_split[0]

        value = tmp_split[1][:tmp_split[1].rfind("\"", 2) + 1].strip()
        optional_string = tmp_split[1][tmp_split[1].rfind("/", 1) + 1:tmp_split[1].rfind("\"", 1)].strip()
        optional_modifiers = {}

        for modifier in optional_string:
            if modifier in 'ismxGARE':
                pass
            elif modifier in 'O':
                raise SnortHookException("unsupported {} modifier {}".format(keyword, modifier))
            else:
                raise SnortHookException("Unknown {} modifier {}".format(keyword, modifier))

        return keyword, value, optional_modifiers

    def parse_reference(self, snort_rule):
        keyword = snort_rule.split(":")[0]
        value = snort_rule.split(":")[1].split(",")[0]
        optional_modifiers = {value: snort_rule.split(":")[1].split(",")[1]}
        return keyword, value, optional_modifiers

    def parse_classtype(self, snort_rule):
        keyword = snort_rule.split(":")[0]
        value = snort_rule.split(":")[1].strip()
        optional_modifiers = {value: self.snort_default_classifications[value]}
        return keyword, value, optional_modifiers

    def parse_priority(self, snort_rule):
        keyword = snort_rule.split(":")[0]
        value = int(snort_rule.split(":")[1].strip())
        if value > 4:
            value = 4
        return keyword, self.priority_map[value], {}

    def parse_sticky_buffer(self, snort_rule):
        split_rule = snort_rule.split(":", 1)
        if len(split_rule) == 2:
            arguments_split = split_rule[1].split(" ")
            return split_rule[0], arguments_split[0].strip(), {arguments_split[0].strip(): arguments_split[1].strip()}
        return snort_rule.strip(), "", {}

    def parse_metadata(self, snort_rule):
        keyword, value = snort_rule.split(":")
        optional_modifiers = {}
        for metadata in value.split(","):
            key, value = metadata.strip().split(" ", 1)
            if key not in optional_modifiers.keys():
                optional_modifiers[key] = set()
            optional_modifiers[key].add(value)
        return keyword, "", optional_modifiers

    def parse_flow(self, snort_rule):
        keyword, value = snort_rule.split(":")
        optional_modifiers = []
        for modifier in value.split(','):
            optional_modifiers.append(modifier.strip())
        return keyword, value, optional_modifiers

    def parse_service(self, snort_rule):
        keyword, value = snort_rule.split(":")
        return keyword, value, {}

    def not_implemented(self, snort_rule):
        raise SnortHookException("unsupported keyword '{}'".format(snort_rule.split(":")[0]))

    parse_func_map = {
        # Primarily functions
        'content': parse_content,
        'pcre': parse_pcre,
        'flow': parse_flow,
        'bufferlen': simple_binary_rule,
        # metadata functions
        'msg': simple_binary_rule,
        'reference': parse_reference,
        'gid': simple_binary_rule,
        'sid': simple_binary_rule,
        'rev': simple_binary_rule,
        'classtype': parse_classtype,
        'priority': parse_priority,
        'metadata': parse_metadata,
        # http functions
        'pkt_data': simple_rule,
        'http_uri': parse_sticky_buffer,
        'http_raw_uri': parse_sticky_buffer,
        'http_header': parse_sticky_buffer,
        'http_raw_header': parse_sticky_buffer,
        'http_method': parse_sticky_buffer,
        'http_client_body': parse_sticky_buffer,
        'http_cookie': parse_sticky_buffer,
        'http_stat_code': parse_sticky_buffer,
        'http_stat_msg': parse_sticky_buffer,
        'http_raw_cookie': parse_sticky_buffer,
        # Snort 2 functions
        'service': parse_service,
        # Not implemented
        'byte_test': not_implemented,
        'file_data': not_implemented,
        'byte_jump': not_implemented,
        'isdataat': not_implemented,
        'dsize': not_implemented,
        'icode': not_implemented,
        'flowbits': not_implemented,
        'itype': not_implemented,
        'dce_iface': not_implemented,
        'cmp_id': not_implemented,
        'detection_filter': not_implemented,
        'flags': not_implemented,
        'sip_stat_code': not_implemented,
        'ack': not_implemented,
        'ip_proto': not_implemented,
        'sip_method': not_implemented,
        'asn1': not_implemented,
        'ssl_version': not_implemented,
        'base64_decode': not_implemented,
        'ssl_state': not_implemented,
        'sip_header': not_implemented,
        'fragbits': not_implemented,
    }

    priority_map = {
        1: "High",
        2: "Medium",
        3: "Low",
        4: "Very Low"
    }

    # Default snort classification for reference.
    # If needed custom config, we should provide it. (1 being High, 2 Medium, 3 Low, 4 Very Low)
    snort_default_classifications = {
        "attempted-admin": "High",
        "attempted-user": "High",
        "inappropriate-content": "High",
        "policy-violation": "High",
        "shellcode-detect": "High",
        "successful-admin": "High",
        "successful-user": "High",
        "trojan-activity": "High",
        "unsuccessful-user": "High",
        "web-application-attack": "High",
        "attempted-dos": "Medium",
        "attempted-recon": "Medium",
        "bad-unknown": "Medium",
        "default-login-attempt": "Medium",
        "denial-of-service": "Medium",
        "misc-attack": "Medium",
        "non-standard-protocol": "Medium",
        "rpc-portmap-decode": "Medium",
        "successful-dos": "Medium",
        "successful-recon-largescale": "Medium",
        "successful-recon-limited": "Medium",
        "suspicious-filename-detect": "Medium",
        "suspicious-login": "Medium",
        "system-call-detect": "Medium",
        "unusual-client-port-connection": "Medium",
        "web-application-activity": "Medium",
        "icmp-event": "Low",
        "misc-activity": "Low",
        "network-scan": "Low",
        "not-suspicious": "Low",
        "protocol-command-decode": "Low",
        "string-detect": "Low",
        "unknown": "Low",
        "tcp-connection": "Very Low"
    }
