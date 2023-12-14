from exception import SnortHookException

class SnortRuleHeader:
    def __init__(self, rule_header_str):
        self.rules = {}
        rule_list = rule_header_str.split(" ")
        if len(rule_list) == 2:
            # alert http
            self.validate_and_parse_action(rule_list[0])
            self.validate_and_parse_protocol(rule_list[1])
            self.rules['source_ports'] = ""
            self.rules['destination_ports'] = ""
            self.rules['directional_op'] = ""
        elif len(rule_list) == 7:
            # alert http $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS
            self.validate_and_parse_action(rule_list[0])
            self.validate_and_parse_protocol(rule_list[1])
            self.validate_and_parse_directional_operator(rule_list[4])
            self.validate_and_parse_source_ports(rule_list[3])
            self.validate_and_parse_destination_ports(rule_list[6])
        else:
            raise SnortHookException("Invalid Snort rule header")

    def validate_and_parse_action(self, action):
        if action in ['drop']:
            self.rules['action'] = action
        elif action in ['alert', 'log', 'pass', 'reject', 'sdrop']:
            pass
            # print("Header action {} not supported".format(action))
        else:
            raise SnortHookException("Unknown header action {}".format(action))

    def validate_and_parse_protocol(self, protocol):
        if protocol in ['http']:
            self.rules['protocol'] = protocol
        elif protocol in ['tcp', 'udp', 'icmp', 'ip', 'file']:
            self.rules['protocol'] = protocol
        else:
            raise SnortHookException("Error: Unknown header protocol {}".format(protocol))

    def validate_and_parse_directional_operator(self, directional_op):
        if directional_op in ['->', '<>']:
            self.rules['directional_op'] = directional_op
        else:
            raise SnortHookException("Error: Unknown unsupported header directional operator {}".format(directional_op))

    def validate_and_parse_source_ports(self, ports):
        if ports in ['$HTTP_PORTS']:
            self.rules['source_ports'] = ports
        else:
            self.rules['source_ports'] = ""

    def validate_and_parse_destination_ports(self, ports):
        if ports in ['$HTTP_PORTS']:
            self.rules['destination_ports'] = ports
        else:
            self.rules['destination_ports'] = ""

    def is_http_header(self):
        return self.rules['protocol'] == 'http' or self.rules['destination_ports'] == "$HTTP_PORTS"
