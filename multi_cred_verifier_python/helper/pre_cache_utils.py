#
# (c) Copyright Merative US L.P. and others 2020-2022 
#
# SPDX-Licence-Identifier: Apache 2.0

from threading import Thread

from multi_cred_verifier_python.verifier.verification_result import VerificationResult
from multi_cred_verifier_python.constants.constants import ISSUER_ID

class PreCacheUtil:
    def __init__(self, healthpass_client, verifier_config_client, params):
        self._params = params
        self._healthpass_client = healthpass_client
        self._verifier_config_client = verifier_config_client
    
    def pre_cache(self, offline):
        config_resp = self._verifier_config_client.get_verifier_configuration_contents(
            ISSUER_ID, self._params, True
        )

        if not config_resp.success:
            return config_resp
            
        config = config_resp.message 

        self._healthpass_client.clear_all_ibm_issuers()
        self._healthpass_client.clear_all_vci_tokens()
        self._healthpass_client.clear_all_eu_tokens()

        if offline:
            pre_cache_resp = self._pre_cache_public_keys_deprecated(config) \
                if config['deprecated'] \
                else self._pre_cache_public_keys(config)
                
            if not pre_cache_resp.success:
                return pre_cache_resp

        return VerificationResult(True, "Pre-caching was successful")

    def _pre_cache_public_keys(self, verifier_config):
        threads = []
        results = []

        ibm_keys = False
        eu_keys = False
        vci_keys = False

        for spec in verifier_config["specificationConfigurations"]:    
            cred_spec = spec["credentialSpec"]

            if (cred_spec == "IDHP" \
                    or cred_spec == "GHP" \
                    or cred_spec == "VC"):
                ibm_keys = True
                continue

            if (cred_spec == "DCC"):
                eu_keys = True
                continue

            if (cred_spec == "SHC"):
                vci_keys = True

        if ibm_keys:
            self._start_thread(
                self._healthpass_client.get_all_ibm_issuers, threads, results)

        if eu_keys:
            self._start_thread(
                self._healthpass_client.get_all_eu_tokens, threads, results)

        if vci_keys:
            self._start_thread(
                self._healthpass_client.get_all_vci_tokens, threads, results)

        return self._process_threads(threads, results)

    def _pre_cache_public_keys_deprecated(self, verifier_config):
        threads = []
        results = []
        if "IDHP" in verifier_config["configuration"] \
                or "GHP" in verifier_config["configuration"] \
                or "VC" in verifier_config["configuration"]:
            self._start_thread(
                self._healthpass_client.get_all_ibm_issuers, threads, results)

        if "DCC" in verifier_config["configuration"]:
            self._start_thread(
                self._healthpass_client.get_all_eu_tokens, threads, results)

        if "SHC" in verifier_config["configuration"]:
            self._start_thread(
                self._healthpass_client.get_all_vci_tokens, threads, results)

        return self._process_threads(threads, results)

    def _start_thread(self, method, threads, results):
            t = Thread(
                target = self._get_all_tokens, args = [
                    method,
                    results,
                ]
            )
            threads.append(t)
            t.start()

    def _get_all_tokens(self, method, results):
        resp = method(ISSUER_ID, self._params)
        results.append(resp)

    def _process_threads(self, threads, results):
        for t in range(len(threads)):
            threads[t].join()

        error_responses = [resp for resp in results if resp.success == False]
        if len(error_responses) > 0:
            return error_responses[0]

        return VerificationResult(True, "OK")
