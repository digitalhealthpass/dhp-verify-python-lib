#
# (c) Copyright Merative US L.P. and others 2020-2022 
#
# SPDX-Licence-Identifier: Apache 2.0

from jsonpath import JSONPath

from multi_cred_verifier_python.clients.verifier_config_client import VerifierConfigClient
from multi_cred_verifier_python.clients.healthpass_client import HealthPassClient
from multi_cred_verifier_python.constants.constants import ISSUER_ID
from multi_cred_verifier_python.verifier.credential_verifier_params import CredentialVerifierParams
from multi_cred_verifier_python.verifier.verification_result import VerificationResult

def get_display_credential(
    credential,
    cred_type,
    params: CredentialVerifierParams
):
    lang = params.get_metadata_language() or 'en'

    """
    Create display credential by mapping credential with display config
    Args:
        credential: credential dict
        display_config: list
        lang: str
    Returns:
        display credential
    """

    display_config_resp = _get_display_config(cred_type, params)

    if not display_config_resp.success:
        return display_config_resp

    display_config = display_config_resp.message

    mappings = [field for mapping in display_config for field in mapping['fields']]

    if len(mappings) == 0:
        return VerificationResult(True, _flatten_credential(credential))

    display_credential_mapping = {}
    for mapping in mappings:
        expression = "$." + mapping['field']
        found = JSONPath(expression).parse(credential)
        
        if len(found) > 0:
            label = mapping['displayValue'][lang] if ("displayValue" in mapping) and (lang in mapping["displayValue"]) \
                else mapping['displayValue'][list(mapping['displayValue'].keys())[0]]
            display_credential_mapping[label] = found[0]

    return VerificationResult(True, display_credential_mapping)

def _get_display_config(cred_type, params):
    spec_config = params.get_specification_configuration()
    if spec_config:
        return VerificationResult(True, spec_config["display"])

    verifier_config_client = VerifierConfigClient.instance(HealthPassClient.instance(params), params)

    display_config_resp = verifier_config_client.get_display_config(
        ISSUER_ID, cred_type, params
    )

    if not display_config_resp.success:
        return display_config_resp

    return VerificationResult(True, display_config_resp.message)

def _flatten_credential(credential, key = "", flattened = {}):
    if type(credential) == dict:
        key = key + '.' if key else key
        for k in credential:
            _flatten_credential(credential[k], key + str(k), flattened)
    else:
        flattened[key] = credential
    return flattened