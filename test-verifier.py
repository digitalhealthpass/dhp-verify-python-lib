#
# (c) Copyright Merative US L.P. and others 2020-2022 
#
# SPDX-Licence-Identifier: Apache 2.0


# Usage: python3 ./verifier.py
# Environment Variables:
#       SERVER (optional) - [release1|release3|release4|staging02|dev1|dev2|sandbox1|sandbox2] default sandbox1
#       CREDENTIAL_PATH (optional) - default: current directory
#       EXPORT_RESULTS (optional) = [true|false] default: false
#       EXPORT_RESULTS_PATH (optional) - default: current directory
#       DCC  (optional) - [true|false] default: true
#       GHP  (optional) - [true|false] default: true
#       IDHP (optional) - [true|false] default: true
#       SHC  (optional) - [true|false] default: true
#       VC   (optional) - [true|false] default: true

import os
from PIL import Image
from pyzbar.pyzbar import decode
import glob
import csv
import time

from multi_cred_verifier_python.verifier.credential_verifier_builder import CredentialVerifierBuilder
from multi_cred_verifier_python.verifier.verification_result import VerificationResult

builder: CredentialVerifierBuilder = None

healthpass_host = os.environ.get("SERVER", "sandbox1")
healthpass_valid_hosts = ["release1", "release3", "release4", "staging02", "dev1", "dev2", "sandbox1",
                          "sandbox2"]
healthpass_host_url = f"https://{healthpass_host}.wh-hpass.dev.acme.com"

credential_extension = ".jpg"
pattern_to_exclude = "verifierlogin"
credential_list = []
export_results_rows = []
credential_path = os.environ.get("CREDENTIAL_PATH", "./")
export_path = os.environ.get("EXPORT_RESULTS_PATH", "./")
export_results = os.environ.get("EXPORT_RESULTS", "false")
credential_type_dcc = os.environ.get("DCC", "true")
credential_type_ghp = os.environ.get("GHP", "true")
credential_type_idhp = os.environ.get("IDHP", "true")
credential_type_shc = os.environ.get("SHC", "true")
credential_type_vc = os.environ.get("VC", "true")

def set_variables():
    global credential_path, export_results, export_path, credential_list, credential_type_dcc, \
        credential_type_ghp, credential_type_idhp, credential_type_shc, credential_type_vc

    if not credential_path.endswith("/"):
        credential_path += '/'

    if export_path.endswith("/"):
        export_path += '/'

    def string_to_boolean(value):
        return value.lower() == "true"

    export_results = string_to_boolean(export_results)
    credential_type_dcc = string_to_boolean(credential_type_dcc)
    credential_type_ghp = string_to_boolean(credential_type_ghp)
    credential_type_idhp = string_to_boolean(credential_type_idhp)
    credential_type_shc = string_to_boolean(credential_type_shc)
    credential_type_vc = string_to_boolean(credential_type_vc)

    credential_list = filter(lambda path: not pattern_to_exclude in path, sorted(
        glob.iglob(f"{credential_path}*{credential_extension}")))

def check_skip_test(credential):
    return ('_dcc_' in credential and not credential_type_dcc) or \
        ('_ghp_' in credential and not credential_type_ghp) or \
        ('_idhp_' in credential and not credential_type_idhp) or \
        ('_shc_' in credential and not credential_type_shc) or \
        ('_vc_' in credential and not credential_type_vc)


def get_builder(credential, new_instance=False):
    global builder

    if builder is None or new_instance:
        builder = CredentialVerifierBuilder() \
            .set_healthpass_host_url(healthpass_host_url) \
            .set_verifier_credential(credential) \
            .set_return_credential(True) \
            .set_return_metadata(True)
    return builder

def test_login(setting, file_name):
    global credential_path

    print(f"Login for Credential Configuration: {setting}", file_name)
    path = f"{credential_path}/{file_name}"

    img = Image.open(path)
    result = decode(img)

    decoded = result[0].data.decode("utf-8")

    response = get_builder(decoded, True).init()

    assert response.success == True, response.message


def test_credential(file_name):
    global credential_path, export_results_rows

    path = f"{credential_path}/{file_name}"

    img = Image.open(path)
    img_result = decode(img)
    decoded = img_result[0].data.decode("utf-8")

    builder = get_builder(decoded, False)
    verify_result = builder.set_credential(decoded).build().verify()

    export_row = {
        "ITEM": file_name,
        "MESSAGE": verify_result.message,
        "SUCCESS": "true" if verify_result.success else "false",
    }

    if "NotVerified" in file_name:
        result = "PASS" if verify_result.success == False else "FAIL"
    else:
        result = "PASS" if verify_result.success == True else "FAIL"
    print(f"{file_name:<80}{result:>10}")
    export_row["TEST_RESULT"] = result
    export_results_rows.append(export_row)


def test_main():
    global credential_list, credential_path, credential_extension

    prev_setting = '??'

    for path in credential_list:
        file_name = path.replace(credential_path, '')

        credential_setting = file_name[0:2]
        if check_skip_test(file_name):
            continue

        if prev_setting != credential_setting:
            login_file_name = f"{credential_setting}__{credential_setting}verifierlogin{credential_extension}"
            test_login(credential_setting, login_file_name)
            prev_setting = credential_setting
        
        test_credential(file_name)

def export_results_to_csv():
    global export_results_rows, export_path

    path = f"{export_path}export.csv"

    headers = ["ITEM", "MESSAGE", "SUCCESS", "TEST_RESULT"]

    with open(path, 'w') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=headers)
        writer.writeheader()
        writer.writerows(export_results_rows)

    print(f"Results exported to {path}")

start = time.time()

set_variables()
test_main()

if export_results:
    export_results_to_csv()

print(f"Test executed in {time.time() - start} seconds")
