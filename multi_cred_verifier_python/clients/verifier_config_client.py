#
# (c) Copyright Merative US L.P. and others 2020-2022 
#
# SPDX-Licence-Identifier: Apache 2.0

from datetime import datetime, timedelta
from dateutil import parser
import pytz
import requests as py_requests
import traceback

from multi_cred_verifier_python.verifier.verification_result import VerificationResult
from multi_cred_verifier_python.verifier.credential_verifier_params import CredentialVerifierParams
import multi_cred_verifier_python.helper.requests as requests
from multi_cred_verifier_python.constants.constants import \
    VERIFIER_CRED_EXPIRATION_WARNING_PERCENT, \
    CACHE_EXPIRATION_WARNING_PERCENT, \
    VERIFIER_CONFIG_PATH


class VerifierConfigClient:
    _instance = None
    _verifier_config_api_url = None
    _healthpass_client = None

    def __init__(self):
        self._configuration_contents = None

    @classmethod
    def instance(cls, healthpass_client, params: CredentialVerifierParams):
        if cls._instance is None:
            cls._instance = VerifierConfigClient()
            cls._verifier_config_api_url = params.get_healthpass_host_url() + VERIFIER_CONFIG_PATH
            cls._healthpass_client = healthpass_client
        return cls._instance

    @classmethod
    def clear_instance(cls):
        cls._instance = None

    def get_verifier_configurations(self, x_issuer_id, params, bypass_cache = False):
        url = "/verifier-configurations"
        return self._get_verifier_configuration(x_issuer_id, url, params, bypass_cache)

    # cache is bypassed by builder during pre-caching
    def get_verifier_configuration_contents(self, x_issuer_id, params, bypass_cache = False):
        url = "/verifier-configurations/content"
        return self._get_verifier_configuration(x_issuer_id, url, params, bypass_cache, True)

    def get_rules(self, x_issuer_id, cred_type, params):
        config_resp = self.get_verifier_configuration_contents(x_issuer_id, params)

        if not config_resp.success:
            return config_resp

        config = config_resp.message

        if cred_type not in config["configuration"]:
            return VerificationResult(False, "Rules not found for credential type", cred_type, None)

        rule_sets = config["configuration"][cred_type]['rule-sets']
        rules = [rule for rule_set in rule_sets for rule in rule_set["rules"]]

        config_resp.message = rules
        return config_resp

    def get_display_config(self, x_issuer_id, cred_type, params):
        config_resp = self.get_verifier_configuration_contents(x_issuer_id, params)

        if not config_resp.success:
            return config_resp

        config = config_resp.message

        if cred_type not in config["configuration"]:
            return VerificationResult(False, "Display mapping not found for credential type", cred_type, None)

        config_resp.message = config["configuration"][cred_type]['display']
        return config_resp

    def _get_verifier_configuration(
        self, x_issuer_id, url, params: CredentialVerifierParams, bypass_cache = False, contents_request = False):
        try:
            if (not bypass_cache and self._configuration_contents):
                return VerificationResult(True, self._configuration_contents)

            decoded = params.get_verifier_credential_decoded()
            verifier_config_id = decoded["credentialSubject"]["configId"]

            token_resp = self._healthpass_client.get_token(params, bypass_cache)
            if not token_resp.success:
                return token_resp

            token = token_resp.message

            id_and_version = verifier_config_id.split(":")

            headers = {"Authorization": "Bearer " + token, "x-hpass-issuer-id": x_issuer_id}
            req_params = {"id": id_and_version[0], "version": id_and_version[1]}

            # cache is bypassed by builder during pre-caching
            response = py_requests.get(
                self._verifier_config_api_url + url, headers=headers, params=req_params, timeout=params.get_network_timeout())

            if response.status_code == 404:
                return VerificationResult(False, "Verifier configuration error :: configuration not found")

            if response.status_code != 200:
                return VerificationResult(False, "Verifier configuration error :: {0}".format(response.text))

            responseJson = response.json()

            if not 'payload' in responseJson or len(responseJson['payload']) <= 0:
                return VerificationResult(False, 'Verifier configuration not found')

            config = responseJson['payload'][0]

            config['deprecated'] = "configuration" in config

            if not config['deprecated'] and contents_request:
                config = self._remove_disabled_specs_and_rules(self._reduce_valueset_items(config))

            if bypass_cache and contents_request:
                self._configuration_contents = config
                self._initialize_from_config(config, params)

            return VerificationResult(True, config)

        except Exception as e:
            traceback.print_exc()
            return VerificationResult(False, "Verifier configuration error :: Network error", error=repr(e))

    def _remove_disabled_specs_and_rules(self, config):
        if not config['disabledSpecifications'] and not config['disabledRules']:
            return config

        if config['disabledSpecifications']:
            disabled_ids = [spec["id"] for spec in config['disabledSpecifications']]
            config['specificationConfigurations'] = [spec for spec in config['specificationConfigurations'] if not spec["id"] in disabled_ids]

        if config['disabledRules']:
            for spec in config['specificationConfigurations']:
                disabled_ids = [rule["id"] for rule in config['disabledRules'] if rule["specID"] == spec["id"]]
                if len(disabled_ids) > 0:
                    spec['rules'] = [rule for rule in spec['rules'] if not rule["id"] in disabled_ids]

        return config

    def _reduce_valueset_items(self, config):
        if not config["valueSets"]:
            return config

        new_valueset = {}
        for valueset in config["valueSets"]:
            new_valueset[valueset["name"]] = [item["value"] for item in valueset["items"]]

        config["valueSets"] = new_valueset
        return config

    def _initialize_from_config(self, config, params: CredentialVerifierParams):
        now = datetime.now().utcnow().now(pytz.utc)

        requests.cache_expiration_datetime = now + timedelta(seconds=config["refresh"])

        requests.cache_warning_datetime = now \
            + timedelta(seconds=config["refresh"] * CACHE_EXPIRATION_WARNING_PERCENT)

        decoded = params.get_verifier_credential_decoded()
        requests.verifier_config_expiration_datetime = parser.parse(decoded["expirationDate"])

        diff = (requests.verifier_config_expiration_datetime - now).total_seconds()
        refreshEpoch = diff * VERIFIER_CRED_EXPIRATION_WARNING_PERCENT
        requests.verifier_config_warning_datetime = now + timedelta(seconds=refreshEpoch)

        cache_refresh_seconds = (requests.cache_warning_datetime - now).total_seconds()
        requests.start_cache_refresh_handler(config["offline"], cache_refresh_seconds, params)
