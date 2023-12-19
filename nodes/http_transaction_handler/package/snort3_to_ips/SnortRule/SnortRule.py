from snort3_to_ips.SnortRule.SnortRuleHeader import SnortRuleHeader
from snort3_to_ips.SnortRule.SnortKW import SnortKW
from snort3_to_ips.SnortRule.SnortKWParser import SnortKWParser
from snort3_to_ips.Signature.IpsSignature import IpsSignature
from exception import SnortHookException


class SnortRule:

    def __init__(self, rule_header):
        self.header = SnortRuleHeader(rule_header)
        self.keywords = []
        self.sticky_buffer = "Default"
        self.dynamic_buffer = {}
        self.flow = "client_to_server"

    def is_http_rule(self, parsed_body):
        return self.header.is_http_header() or "service:http" in parsed_body

    def add_keyword(self, snort_rule):
        kw_parser = SnortKWParser()
        keyword, value, optional_modifiers = kw_parser.parse_kw_parameters(snort_rule)
        self.keywords.append(SnortKW(keyword, value, optional_modifiers))

    def parse_body(self, input_snort_rule_body):
        for keyword in input_snort_rule_body:
            self.add_keyword(keyword)

    def convert(self):
        signature = IpsSignature()
        for keyword in self.keywords:
            for converted_keyword in keyword.convert(self):
                signature.parse_data(converted_keyword.construct())
        return signature.output_signature()

    def get_ips_context(self):
        return self.convert_http_map[self.sticky_buffer](self)

    def convert_default(self):
        return {"part": "HTTP_RAW"}

    def convert_pkt_data(self):
        raise SnortHookException("Unsupported keyword 'pkt_data'")

    def convert_http_uri(self):
        return {"part": "HTTP_COMPLETE_URL_DECODED"}

    def convert_http_raw_uri(self):
        return {"part": "HTTP_COMPLETE_URL_ENCODED"}

    def convert_http_header(self):
        if self.flow == "client_to_server":
            if 'field' in self.dynamic_buffer.keys():
                return {"part": 'HTTP_REQUEST_HEADER_{}'.format(self.dynamic_buffer['field'].upper())}
            else:
                return {"part": "HTTP_REQUEST_HEADER"}
        elif self.flow == "server_to_client":
            if 'field' in self.dynamic_buffer.keys():
                return {"part": 'HTTP_RESPONSE_HEADER_{}'.format(self.dynamic_buffer['field'].upper())}
            else:
                return {"part": "HTTP_RESPONSE_HEADER"}

        else:
            raise SnortHookException("Unknown Flow {}".format(self.flow))

    def convert_http_raw_header(self):
        if self.flow == "client_to_server":
            return {"part": "HTTP_REQUEST_HEADER"}
        elif self.flow == "server_to_client":
            return {"part": "HTTP_RESPONSE_HEADER"}
        else:
            raise SnortHookException("Unknown Flow {}".format(self.flow))

    def convert_http_method(self):
        return {"part": "HTTP_METHOD"}

    def convert_http_client_body(self):
        return {"part": "HTTP_REQUEST_BODY"}

    def convert_http_cookie(self):
        if self.flow == "client_to_server":
            return {"part": "HTTP_REQUEST_HEADER_COOKIE"}
        elif self.flow == "server_to_client":
            return {"part": "HTTP_RESPONSE_HEADER_COOKIE"}
        else:
            raise SnortHookException("Unknown Flow {}".format(self.flow))

    def convert_http_raw_cookie(self):
        if self.flow == "client_to_server":
            return {"part": "HTTP_REQUEST_HEADER_COOKIE"}
        elif self.flow == "server_to_client":
            return {"part": "HTTP_RESPONSE_HEADER_COOKIE"}
        else:
            raise SnortHookException("Unknown Flow {}".format(self.flow))

    def convert_http_stat_code(self):
        if self.flow == "client_to_server":
            raise SnortHookException("http_stat_code isn't supported with flow: to_server, from_client")
        elif self.flow == "server_to_client":
            return {"part": "HTTP_RESPONSE_CODE"}
        else:
            raise SnortHookException("Unknown Flow {}".format(self.flow))

    def not_implemented(self):
        raise SnortHookException("unsupported keyword '{}'".format(self.sticky_buffer))

    convert_http_map = {
        'Default': convert_default,
        'pkt_data': convert_pkt_data,
        'http_uri': convert_http_uri,
        'http_raw_uri': convert_http_raw_uri,
        'http_header': convert_http_header,
        'http_raw_header': convert_http_raw_header,
        'http_method': convert_http_method,
        'http_client_body': convert_http_client_body,
        'http_cookie': convert_http_cookie,
        'http_raw_cookie': convert_http_raw_cookie,
        'http_stat_code': convert_http_stat_code,
        'http_stat_msg': not_implemented,
        'http_encode': not_implemented
    }
