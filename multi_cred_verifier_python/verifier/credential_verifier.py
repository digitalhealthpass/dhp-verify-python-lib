#
# (c) Copyright Merative US L.P. and others 2020-2022 
#
# SPDX-Licence-Identifier: Apache 2.0

from email import message
from threading import Thread

from multi_cred_verifier_python.verifier.verification_result import VerificationResult
from multi_cred_verifier_python.verifier.credential_verifier_params import CredentialVerifierParams
from multi_cred_verifier_python.constants.constants import CredType
from multi_cred_verifier_python.helper.requests import get_expiration_warnings
from multi_cred_verifier_python.helper.metering import Metering
from multi_cred_verifier_python.helper.rule_utils import run_classifier_rules
from multi_cred_verifier_python.clients.healthpass_client import HealthPassClient
from multi_cred_verifier_python.clients.verifier_config_client import VerifierConfigClient
from multi_cred_verifier_python.constants.constants import ISSUER_ID

class CredentialVerifier:

    """  Class with methods used to verify credential"""
    def __init__(self, plugins, params):
        self._plugins = plugins
        self._params: CredentialVerifierParams = params

    def verify(self):
        """
        Call verifier method for all the plugins
        Returns:
            VerificationResult object
        """

        extract_resp = self._extract_credential()
        if not extract_resp.success:
            return self._increment_metering(extract_resp)

        verifier_config_resp = self._get_verifier_config()
        if not verifier_config_resp.success:
            return verifier_config_resp

        verifier_config = verifier_config_resp.message
        credential = extract_resp.message["credential"]
        cred_type = extract_resp.message["cred_type"]
        plugin = extract_resp.message["plugin"]

        if not verifier_config["deprecated"]:
            set_spec_config_resp = self._set_specification_configuration(credential, cred_type, verifier_config)

            if not set_spec_config_resp.success:
                return VerificationResult(False, "Unknown Credential Type", CredType.UNKNOWN.value)

        verify_resp = plugin.verify(credential)

        return self._increment_metering(verify_resp)

    def _add_warnings(self, result: VerificationResult):
        warnings = get_expiration_warnings()
        if len(warnings) > 0:
            result.warnings = warnings

    def _increment_metering(self, verification_result: VerificationResult):
        cred = verification_result.credential if hasattr(verification_result, "credential") else {}
        cred_type = verification_result.cred_type
        scan_result = "Pass" if verification_result.success else "Fail"

        metering = Metering.instance(self._params)
        metering_resp: VerificationResult = metering.increment_metering(
            cred, cred_type, scan_result, self._params
        )

        if not metering_resp.success:
            return metering_resp.clean_result()

        if not self._params.get_return_credential():
            verification_result.credential = None

        return verification_result.clean_result()

    def _extract_credential(self):
        for plugin in self._plugins:
            decoded_resp: VerificationResult = plugin.decode()
            if decoded_resp.success:
                return VerificationResult(True, {
                    "credential": decoded_resp.credential,
                    "cred_type": decoded_resp.cred_type,
                    "plugin": plugin,
                })
            elif decoded_resp.message:
                return decoded_resp

        return VerificationResult(False, "Unknown Credential Type", CredType.UNKNOWN.value)

    def _get_verifier_config(self):
            verifier_config_client = VerifierConfigClient.instance(HealthPassClient.instance(self._params), self._params)

            config_resp = verifier_config_client.get_verifier_configuration_contents(ISSUER_ID, self._params)

            if not config_resp.success:
                return config_resp

            return VerificationResult(True, config_resp.message)

    def _get_cred_from_raw_cred(self, credential, cred_type):
        if cred_type == CredType.DCC.value:
            return credential["credential"]
        
        if cred_type == CredType.SHC.value:
            return credential["payload"]
        
        return credential

    def _set_specification_configuration(self, credential, cred_type, verifier_config):
        spec_config = run_classifier_rules(self._get_cred_from_raw_cred(credential, cred_type), verifier_config)
        if not spec_config:
            spec = [spec for spec in verifier_config["specificationConfigurations"] if spec["credentialSpec"] == CredType.VC]
            if not spec:
                spec = CredType.UNKNOWN.value

            self._params.set_specification_configuration(spec)

            return VerificationResult(False, "Unknown Credential Type", CredType.UNKNOWN, credential)

        self._params.set_specification_configuration(spec_config)

        return VerificationResult(True, "OK")
