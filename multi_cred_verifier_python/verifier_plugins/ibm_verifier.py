#
# (c) Copyright Merative US L.P. and others 2020-2022 
#
# SPDX-Licence-Identifier: Apache 2.0

import json
import copy

from multi_cred_verifier_python.verifier.verifier_plugin import VerifierPluginBase
from multi_cred_verifier_python.verifier.verification_result import VerificationResult

from multi_cred_verifier_python.constants.constants import CredType, ISSUER_ID
from multi_cred_verifier_python.helper.rule_utils import verify_rules
from multi_cred_verifier_python.helper.crypto_utils import verify_signature, check_obfuscation


class IBMCredentialVerifier(VerifierPluginBase):
    """  verifier plugin class"""

    def __init__(self, params):
        super().__init__(params)

    @staticmethod
    def _check_is_ibm_credential(credential):
        """
        Checks if the credential is IBM credential
        Args:
            credential: dict
        Returns:
            boolean
        """
        return (credential is not None) and \
            (type(credential) is dict) and \
            ("proof" in credential) and \
            ("signatureValue" in credential["proof"]) and \
            ("issuer" in credential) and \
            ("type" in credential) and \
            ("VerifiableCredential" in credential["type"])

    @staticmethod
    def _get_cred_type(credential):
        """
        Returns the credential type
        Args:
            credential: dict
        Returns:
            Credential type: str
        """
        if ("type" in credential) & ('IBMDigitalHealthPass' in credential["type"]):
            return CredType.IDHP.value
        if ("type" in credential) & ('GoodHealthPass' in credential["type"]):
            return CredType.GHP.value
        return CredType.VC.value

    def _get_public_key(self, credential) -> VerificationResult:
        """
        Gets the public key for signature verification
        Returns:
            VerificationResult
        """
        key_resp = self._healthpass_client.get_ibm_issuer(
            ISSUER_ID, credential["issuer"], self._params)
        if not key_resp.success:
            return key_resp

        # extract public key
        credential_creator = credential['proof']['creator']
        public_keys = key_resp.message["publicKey"]
        public_key_jwk = None
        for key in public_keys:
            if key["id"] == credential_creator:
                public_key_jwk = key['publicKeyJwk']
                break
        if public_key_jwk is None:
            return VerificationResult(False, "Unknown Issuer")
        return VerificationResult(True, public_key_jwk)

    def _verify_signature(self, credential, public_key, cred_type) -> VerificationResult:
        """
        Verifies signature with the public key and unsigned credential
        Returns:
            VerificationResult
        """
        # TODO: Signature verification
        # extract signature
        signature = credential['proof']['signatureValue']

        # unsigned message
        unsigned_cred = copy.deepcopy(credential)
        if 'signatureValue' in unsigned_cred['proof']:
            del unsigned_cred['proof']['signatureValue']
        if 'obfuscation' in unsigned_cred:
            del unsigned_cred['obfuscation']
        unsigned_cred = json.dumps(unsigned_cred, sort_keys=True, separators=(',', ':'))

        # verify signature
        if not verify_signature(public_key, unsigned_cred, signature):
            return VerificationResult(False, "Signature validation failed", cred_type, None)

        return VerificationResult(True, "Signature Verified", cred_type, None)

    def _is_signature_valid(self, credential, cred_type) -> VerificationResult:
        """
        Checks if the signature is valid
        Returns:
            VerificationResult
        """
        # get public key
        verification = self._get_public_key(credential)
        if not verification.success:
            return verification
        public_key = verification.message

        # verify signature
        verification = self._verify_signature(credential, public_key, cred_type)
        return verification

    def _check_revoke_status(self, credential) -> VerificationResult:
        """
        Checks revoke status
        Returns:
            VerificationResult
        """
        # TODO: verify credential id
        verification = self._healthpass_client.get_revoke_status(
            ISSUER_ID, credential['id'], self._params)
        if verification.success:
            revoke_status = verification.message
            if revoke_status['exists']:
                return VerificationResult(False, "Credential is revoked")
            else:
                return VerificationResult(True, "Credential is not revoked")

        # ignore network errors for offline mode
        return VerificationResult(True, "Unable to determine revoke status")

    def _check_obfuscation(self, credential) -> VerificationResult:
        """
        Checks obfuscation
        Returns:
            VerificationResult
        """
        verification = check_obfuscation(credential)
        return verification

    def _is_credential_valid(self, credential, cred_type) -> VerificationResult:
        """
        Evaluates rules to validate credential
        Returns:
            VerificationResult
        """
        
        return verify_rules(credential, cred_type, self._params)

    def decode(self) -> VerificationResult:
        """
        Decodes the credential
        Returns:
            VerificationResult
        """

        credential = self._params.get_credential()

        if (type(credential) is dict) and \
                (self._check_is_ibm_credential(credential)):
            cred_type = self._get_cred_type(credential)
            return VerificationResult(True, None, cred_type, credential)    

        return VerificationResult(False, None, CredType.IDHP.value, None)

    def verify(self, credential) -> VerificationResult:
        """
        Performs credential verification
        Returns:
            VerificationResult
        """
        cred_type = self._get_cred_type(credential)

        issuer_id = ISSUER_ID
        if (issuer_id is None) | (issuer_id == ''):
            return VerificationResult(False, "Authorization token and issuer ID is required to verify {0} \
                                        credentials".format(cred_type), cred_type, None)

        verification = self._is_signature_valid(credential, cred_type)
        if not verification.success:
            return verification

        verification = self._check_revoke_status(credential)
        if not verification.success:
            return VerificationResult(False, "Revoke status validation failed :: {0}".format(verification.message),
                                        cred_type, None)

        verification = self._check_obfuscation(credential)
        if not verification.success:
            return VerificationResult(False, "Obfuscation validation failed :: {0}".format(verification.message),
                                        cred_type, None)

        verification = self._is_credential_valid(credential, cred_type)

        verification.credential = credential

        return self.attach_metadata(verification, credential, cred_type)

    @classmethod
    def get_name(cls) -> str:
        """
        Returns name of the plugin
        Returns:
            Plugin name: str
        """
        return 'idhp-verifier'
