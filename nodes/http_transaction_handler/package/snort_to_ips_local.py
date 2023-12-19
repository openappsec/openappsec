import os
import snort3_to_ips.Signature.Signatures as Signatures
import sys


def convert_snort_to_ips_package(input_pf, output_pf, error_pf):
    signatures = Signatures.Signatures()
    with open(input_pf) as f:
        input_data = f.read()
        signatures.load_snort_signatures(input_data)
        signatures.output_ips_signature_package(output_pf)
        signatures.output_errors(error_pf)


if __name__ == '__main__':
    if len(sys.argv) < 4:
        print("Usage: python3 snort_to_ips_local.py <input_file> <output_file> <error_file>")
        exit(1)

    # Path to snort 3 rules file
    in_pf = os.path.join("snort3_to_ips", "data", sys.argv[1])

    # Path to output file (will create one if it does not exist)
    out_pf = os.path.join("snort3_to_ips", "data", sys.argv[2])

    # Path to output errors file (will create one if it does not exist)
    err_pf = os.path.join("snort3_to_ips", "data", sys.argv[3])

    convert_snort_to_ips_package(in_pf, out_pf, err_pf)

