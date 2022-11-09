#
# (c) Copyright Merative US L.P. and others 2020-2022 
#
# SPDX-Licence-Identifier: Apache 2.0

from multi_cred_verifier_python.lib.json_logic import jsonLogic, add_operation

import copy
import json
from datetime import datetime, timedelta
import pytz
from dateutil import parser

from multi_cred_verifier_python.clients.healthpass_client import HealthPassClient
from multi_cred_verifier_python.clients.verifier_config_client import VerifierConfigClient
from multi_cred_verifier_python.verifier.verification_result import VerificationResult
from multi_cred_verifier_python.constants.constants import ISSUER_ID

def plus_time_operation(date_time, amount, unit):
    if not date_time or ((type(date_time) is str) and (date_time == "now")):
        date_time = datetime.utcnow().now(pytz.utc)
    elif type(date_time) is str:
        date_time = parser.parse(date_time)

    if unit == "day":
        date_time = date_time + timedelta(days=int(amount))
    elif unit == "hour":
        date_time = date_time + timedelta(hours=int(amount))

    return date_time.strftime('%Y-%m-%dT%H:%M:%SZ')

def less_then_operation(first, second):
    first_float = float(first)
    second_float = float(second)

    result = first_float < second_float
    return result


def before_operation(first, second, third=None):
    if not first or not second:
        return False

    first_date = parser.parse(first) if type(first) is str else first
    second_date = parser.parse(second) if type(second) is str else second

    result = first_date < second_date
    if third is not None:
        third_date = parser.parse(third) if type(third) is str else third
        result = result & (second_date < third_date)

    return result


def not_before_operation(first, second, third=None):
    if not first or not second:
        return False

    first_date = parser.parse(first) if type(first) is str else first
    second_date = parser.parse(second) if type(second) is str else second

    result = first_date >= second_date
    if third is not None:
        third_date = parser.parse(third) if type(third) is str else third
        result = result & (second_date >= third_date)

    return result


def after_operation(first, second, third=None):
    if not first or not second:
        return False

    first_date = parser.parse(first) if type(first) is str else first
    second_date = parser.parse(second) if type(second) is str else second

    result = first_date > second_date
    if third is not None:
        third_date = parser.parse(third) if type(third) is str else third
        result = result & (second_date > third_date)

    return result


def not_after_operation(first, second, third=None):
    if not first or not second:
        return False

    first_date = parser.parse(first) if type(first) is str else first
    second_date = parser.parse(second) if type(second) is str else second

    result = first_date <= second_date

    if third is not None:
        third_date = parser.parse(third) if type(third) is str else third
        result = result & (second_date <= third_date)

    return result

def setup_operations():
    add_operation("plusTime", plus_time_operation)
    add_operation("after", after_operation)
    add_operation("not-after", not_after_operation)
    add_operation("before", before_operation)
    add_operation("not-before", not_before_operation)
    add_operation("lessThan", less_then_operation)

def format_data(data):
    data = data if type(data) == dict else json.loads(data)
    data = data if 'payload' in data else {"payload": data}
    if 'external' not in data:
        data["external"] = {"validationClock": datetime.now().utcnow().now(pytz.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}
    elif 'validationClock' not in data["external"]:
        data["external"]["validationClock"] = datetime.now().utcnow().now(pytz.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

    return data

def get_verifier_config(params):
        verifier_config_client = VerifierConfigClient.instance(HealthPassClient.instance(params), params)

        config_resp = verifier_config_client.get_verifier_configuration_contents(ISSUER_ID, params)
        if not config_resp.success:
            return config_resp

        return VerificationResult(True, config_resp.message)

def run_rules(rules, payload, cred_type):
    failures = []
    for rule in rules:
        rule_predicate = json.JSONDecoder().decode(rule["predicate"])
        result = jsonLogic(rule_predicate, payload)
        if not result:
            failures.append(rule["id"])

    if len(failures) > 0:
        error = { "configuration": { "rules": failures } }

        return VerificationResult(
            False, f"Credential is not valid.  Failing rule id(s): {','.join(f for f in failures)}", cred_type, None
        )

    return VerificationResult(True, "Credential is valid", cred_type, None)


def verify_rules_deprecated(payload, cred_type, params):
    verifier_config_client = VerifierConfigClient.instance(HealthPassClient.instance(params), params)
    rules_resp = verifier_config_client.get_rules(ISSUER_ID, cred_type, params)
    if not rules_resp.success:
        return rules_resp

    rules = rules_resp.message

    return run_rules(rules, payload, cred_type)

def verify_rules(data, cred_type, params):
    """
    checks data against business rules specified in rule sets
    Args:
        rule_sets: rule sets specified in verrifier config
        data: credential
    Returns:
        list of failed rule ids
    """

    verifier_config_resp = get_verifier_config(params)
    if not verifier_config_resp.success:
        return verifier_config_resp
    
    verifier_config = verifier_config_resp.message

    payload = copy.deepcopy(data)

    # add custom operations to json logic
    setup_operations()

    # format data
    payload = format_data(payload)

    if verifier_config["deprecated"]:
        return verify_rules_deprecated(payload, cred_type, params)

    spec_config = params.get_specification_configuration()
    payload["external"].update(verifier_config["valueSets"])

    run_rules_resp = run_rules(spec_config["rules"], payload, cred_type)
    run_rules_resp.category = spec_config["credentialCategory"]

    return run_rules_resp

def run_classifier_rules(data, verifier_config):
    payload = format_data(copy.deepcopy(data))
    for spec in verifier_config["specificationConfigurations"]:
        rule_predicate = json.JSONDecoder().decode(spec["classifierRule"]["predicate"])
        result = jsonLogic(rule_predicate, payload)
        if result != False:
            return spec

    return None
