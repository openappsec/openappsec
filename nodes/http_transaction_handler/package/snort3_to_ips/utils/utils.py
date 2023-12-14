import hashlib
import base64

from exception import SnortHookException


def parse_snort_rules_line(line):
    header = line[0:line.find("(")].strip()
    tmp_body = line[line.find("(") + 1:line.rfind(")")].replace("\n", "").strip().split(";")
    body = []
    tmp_body_segment = ""
    for rule in tmp_body:
        if len(rule) == 0:
            continue
        rule = rule.strip()
        if rule[len(rule) - 1] == "\\":
            tmp_body_segment += "{};".format(rule[:len(rule) - 1])
        else:
            body.append(tmp_body_segment + rule)
            tmp_body_segment = ""

    return header, body


def is_hex_segment_in_str(value):
    if value.count("|") - value.count("\\|") > 0:
        return True
    return False


def is_invalid_line(line):
    tmp_line = line.strip()
    return len(tmp_line) == 0 or tmp_line[0] == "#"


def generate_version_id(data, hash_mode="md5", input_mode="decoded_data"):
    if hash_mode == "md5":
        hash_mod = hashlib.md5()
    elif hash_mode == "sha1":
        hash_mod = hashlib.sha1()
    else:
        return ""
    if input_mode == "file":
        with open(data, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_mod.update(chunk)
    elif input_mode == "decoded_data":
        hash_mod.update(data.encode())
    return hash_mod.hexdigest()


def verify_custom_signatures(signatures):
    if signatures is None:
        return False
    return signatures['isFileExist'] and signatures['size'] != 0


def decode_custom_signature(signatures):
    data = signatures.split(",", 1)
    metadata = data[0]
    if metadata == 'data:':
        return ""
    elif metadata != 'data:application/octet-stream;base64':
        raise SnortHookException("Invalid Snort file")
    base64_message = base64.b64decode(data[1])
    return base64_message.decode("utf-8")


def prepare_warnings_log(warnings):
    if not warnings:
        return []
    if len(warnings) <= 10:
        ret_warnings = []
        for warning in warnings:
            if warning['errorType'] == "SnortRule":
                tmp_id = warning['id']
                ret_warnings.append({"id": warning['id'],
                                     "name": "Snort Warning",
                                     "type": "Web Application",
                                     "sub_type": "Snort Conversion",
                                     "message": "Asset {}, skipped line {}: {}".format(warning["assetName"], warning['Line'], warning['Error'])
                                     })
    else:
        assets_errors = {}
        for warning in warnings:
            if warning['errorType'] == "SnortRule":
                tmp_id = warning['id']
                asset_name = warning["assetName"]
                if asset_name not in assets_errors.keys():
                    assets_errors[asset_name] = {}
                if warning['Error'] not in assets_errors[asset_name].keys():
                    assets_errors[asset_name][warning['Error']] = 1
                else:
                    assets_errors[asset_name][warning['Error']] += 1

        ret_warnings = []
        for asset_name in assets_errors.keys():
            for err in assets_errors[asset_name].keys():
                if assets_errors[asset_name][err] == 1:
                    message_format = "Asset {}: skipped {} {} time"
                else:
                    message_format = "Asset {}: skipped {} {} times"
                ret_warnings.append({"id": tmp_id,
                                     "name": "Snort Warning",
                                     "type": "Web Application",
                                     "sub_type": "Snort Conversion",
                                     "message": message_format.format(asset_name, err, assets_errors[asset_name][err])
                                     })
    for warning in warnings:
        if warning['errorType'] != "SnortRule":
            tmp_id = warning['id']
            ret_warnings.append({"id": warning['id'],
                                 "name": "Snort Warning",
                                 "type": "Web Application",
                                 "sub_type": "Snort Conversion",
                                 "message": warning['Error']
                                 })
    if len(ret_warnings) == 1:
        final_message_format = "To remove warning, please edit the Snort signatures file"
    else:
        final_message_format = "To remove warnings, please edit the Snort signatures file"
    ret_warnings.append({"id": tmp_id,
                         "name": "Snort Warning",
                         "type": "Web Application",
                         "sub_type": "Snort Conversion",
                         "message": final_message_format
                         })
    return ret_warnings

