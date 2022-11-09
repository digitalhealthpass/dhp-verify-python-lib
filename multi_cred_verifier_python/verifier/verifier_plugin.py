
#
# (c) Copyright Merative US L.P. and others 2020-2022 
#
# SPDX-Licence-Identifier: Apache 2.0

from abc import ABC, abstractmethod

from multi_cred_verifier_python.verifier.credential_verifier_params import CredentialVerifierParams
from multi_cred_verifier_python.verifier.verification_result import VerificationResult
from multi_cred_verifier_python.clients.healthpass_client import HealthPassClient
from multi_cred_verifier_python.constants.constants import HEALTHPASS_PATH, VERIFIER_CONFIG_PATH
from multi_cred_verifier_python.helper.display_utils import get_display_credential


class VerifierPluginBase(ABC):
    """base class for Verifier Plugin"""

    def __init__(self, params: CredentialVerifierParams):
        self._healthpass_client = HealthPassClient.instance(params)
        self._params = params
    @abstractmethod
    def decode(self) -> VerificationResult:
        """
        Method to decode the credential
        Returns:
            VerificationResult
        """
        raise Exception("decode() method must be implemented")

    @abstractmethod
    def verify(self, credential) -> VerificationResult:
        """
        Method to verify the credential
        Returns:
            VerificationResult
        """
        raise Exception("verify() method must be implemented")

    @classmethod
    @abstractmethod
    def get_name(cls) -> str:
        """
        Method to return name
        Returns:
            String
        """
        raise Exception("get_name() method must be implemented")

    def attach_metadata(self,
        result: VerificationResult, credential, cred_type) -> VerificationResult:
        if not self._params.get_return_metadata():            
            return result

        display_resp = get_display_credential(
            credential,
            cred_type,
            self._params
        )

        if not display_resp.success:
            return display_resp

        result.metadata = display_resp.message
        return result
