import json

from snort3_to_ips.SnortRule.SnortRule import SnortRule
from snort3_to_ips.utils.utils import parse_snort_rules_line, is_invalid_line

from exception import SnortHookException


class Signatures:
    def __init__(self):
        self.signatures = []
        self.error_rules = []
        self.error_internal = []

    def load_snort_signatures(self, rules_input):
        line_number = 0
        for line in rules_input.split("\n"):
            line_number += 1
            if is_invalid_line(line):
                continue
            rule = line.strip()
            header, body = parse_snort_rules_line(rule)
            try:
                snort_rule = SnortRule(header)
                if not snort_rule.is_http_rule(body):
                    continue
                snort_rule.parse_body(body)
                self.signatures.append(snort_rule.convert())
            except SnortHookException as se:
                self.error_rules.append({"Error": str(se), "Line": line_number})
            except Exception as e:
                self.error_internal.append({"Error": str(e), "Line": line_number})

    def reset(self):
        self.signatures = []
        self.error_rules = []

    def output_errors(self, output_pf):
        output = {"Errors": self.error_rules}
        with open(output_pf, 'w') as f:
            json.dump(output, f, ensure_ascii=False, indent=4)

    def output_ips_signature_package(self, output_pf):
        output = {"IPSSnortSigs": {"protections": self.signatures}}
        with open(output_pf, 'w') as f:
            json.dump(output, f, ensure_ascii=False, indent=4)

    def get_payload_data(self):
        return self.signatures, self.error_rules, self.error_internal
