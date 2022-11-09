#
# (c) Copyright Merative US L.P. and others 2020-2022 
#
# SPDX-Licence-Identifier: Apache 2.0

import json
import traceback

from multi_cred_verifier_python.clients.healthpass_client import HealthPassClient
from multi_cred_verifier_python.verifier.verification_result import VerificationResult
from multi_cred_verifier_python.verifier.credential_verifier_params import CredentialVerifierParams
from multi_cred_verifier_python.helper.requests import get_requests
from multi_cred_verifier_python.constants.constants import METERING_PATH

class MeteringClient:
    _instance = None
    _metering_api_url = None
    _healthpass_client: HealthPassClient = None

    @classmethod
    def instance(cls, healthpass_client, params: CredentialVerifierParams):
        if cls._instance is None:
            cls._instance = cls.__new__(cls)
            cls._metering_api_url = params.get_healthpass_host_url() + METERING_PATH
            cls._healthpass_client = healthpass_client
        return cls._instance

    @classmethod
    def clear_instance(cls):
        cls._instance = None

    def __init__(self):
        raise RuntimeError('Call instance() to get a singleton')

    def get_health(self, params: CredentialVerifierParams):
        try:
            token_resp = self._healthpass_client.get_token(params)
            if not token_resp.success:
                return token_resp

            token = token_resp.message

            headers = { "Authorization": "Bearer " + token }
            url = self._metering_api_url + "/health"
            
            response = get_requests().get(
                url, headers=headers, timeout=params.get_network_timeout())

            if response.status_code != 200:
                return VerificationResult(False, "Data connectivity error :: {0}".format(response.text))

            return VerificationResult(True, 'OK')
        
        except Exception as e:
            traceback.print_exc()
            return VerificationResult(False, "Data connectivity error :: Network Error", error=repr(e))


    def post_metering(self, payload, params: CredentialVerifierParams):
        try:
            token_resp = self._healthpass_client.get_token(params)
            if not token_resp.success:
                return token_resp

            token = token_resp.message

            headers = {"Content-Type": "application/json", 'accept': 'application/json',
                       "Authorization": "Bearer "+token}

            url = self._metering_api_url + "/metrics/verifier/batch"

            response = get_requests(True, True).post(
                url, data=json.dumps({ "data": payload }), headers=headers, timeout=params.get_network_timeout())

            if response.status_code != 200:
                return VerificationResult(False, "Post data error :: {0}".format(response.text))
            return VerificationResult(True, "OK")
        except Exception as e:
            traceback.print_exc()
            return VerificationResult(False, "Post data error :: Network Error", error=repr(e))
