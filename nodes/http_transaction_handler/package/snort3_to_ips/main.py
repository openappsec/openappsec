import snort3_to_ips.Signature.Signatures as Signatures


def convert_incoming_rules(rules):
    signatures = Signatures.Signatures()
    signatures.load_snort_signatures(rules)
    return signatures.get_payload_data()
