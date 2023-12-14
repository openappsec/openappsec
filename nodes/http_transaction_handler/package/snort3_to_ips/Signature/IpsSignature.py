from snort3_to_ips.Signature.ProtectionMetadata import ProtectionMetadata
from snort3_to_ips.Signature.DetectionRules import DetectionRules
from exception import SnortHookException


class IpsSignature:
    def __init__(self):
        self.protectionMetadata = ProtectionMetadata()
        self.detectionRules = DetectionRules()

    def __str__(self):
        return str(self.output_signature())

    def parse_data(self, constructs):
        for json_key, json_value in constructs:
            if self.protectionMetadata.is_key_valid(json_key):
                self.protectionMetadata.parse_data(json_key, json_value)
            elif self.detectionRules.is_key_valid(json_key):
                self.detectionRules.parse_data(json_key, json_value)
            else:
                raise SnortHookException("'{}' is not a valid keyword in snort signature".format(json_key))

    def validate(self):
        self.protectionMetadata.validate()
        self.detectionRules.validate()

    def set_default_if_needed(self):
        self.protectionMetadata.set_default_if_needed()
        self.detectionRules.set_default_if_needed()

    def output_signature(self):
        self.validate()
        self.set_default_if_needed()
        return {"protectionMetadata": self.protectionMetadata.data, "detectionRules": self.detectionRules.data}
