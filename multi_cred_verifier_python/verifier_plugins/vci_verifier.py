#
# (c) Copyright Merative US L.P. and others 2020-2022 
#
# SPDX-Licence-Identifier: Apache 2.0

import re
import json
import zlib

from multi_cred_verifier_python.verifier.verifier_plugin import VerifierPluginBase
from multi_cred_verifier_python.verifier.verification_result import VerificationResult
from multi_cred_verifier_python.constants.constants import CredType, ISSUER_ID
from multi_cred_verifier_python.helper.crypto_utils import base64_url_decode, base64_url_decode_bytes, decode_public_key, verify_signature
from multi_cred_verifier_python.helper.rule_utils import verify_rules


class VciCredentialVerifier(VerifierPluginBase):

    def __init__(self, params):
        super().__init__(params)

    @staticmethod
    def _decode_shc(raw_cred):
        return ''.join([chr((int(num)+45)) for num in re.compile('(..)').findall(raw_cred[5:])])

    @staticmethod
    def _check_is_vci_credential(cred_parts):
        """
        Checks if the credential is VCI credential
        Args:
            credential: dict
        Returns:
            boolean
        """
        return (cred_parts is not None) and \
            (len(cred_parts) == 3)

    @staticmethod
    def _is_valid_header(header):
        return (type(header) is dict) and \
               ('zip' in header) and \
               (header["zip"] == "DEF") and \
               ('alg' in header) and \
               (header["alg"] == 'ES256') and \
               ('kid' in header)

    def _get_credential(self):
        raw_cred: str = self._params.get_credential()

        if not type(raw_cred) is str:
            return VerificationResult(False, None, CredType.SHC.value, None)

        if raw_cred.startswith("HC1:"):
            return VerificationResult(False, None, CredType.SHC.value, None)

        cred_parts = self._decode_shc(raw_cred).split('.') if raw_cred.startswith("shc:/") else raw_cred.split('.')

        if not self._check_is_vci_credential(cred_parts):
            return VerificationResult(False, None, CredType.SHC.value, None)

        header = json.loads(base64_url_decode(cred_parts[0]))
        if not self._is_valid_header(header):
            return VerificationResult(False, "Header must include a kid, zip = DEF, and alg = ES256",
                                      CredType.SHC.value, None)

        try:
            payload = json.loads(zlib.decompress(base64_url_decode_bytes(cred_parts[1]), -15).decode("utf-8"))
        except Exception as e:
            return VerificationResult(False, "VCI payload inflate failed", CredType.SHC.value, error=repr(e))

        message = cred_parts[0] + '.' + cred_parts[1]
        signature = cred_parts[2]
        result = {"header": header, "payload": payload, "message": message, "signature": signature}
        return VerificationResult(True, result, CredType.SHC.value, None)

    def _get_public_key(self, x_issuer_id, iss, kid):
        return self._healthpass_client.get_vci_token(x_issuer_id, iss, kid, self._params)

    def _is_signature_valid(self, credential):
        verification = self._get_public_key('hpass.issuer1', credential["payload"]["iss"],
                                            credential["header"]["kid"])
        if not verification.success:
            return verification
        public_key = verification.message

        # verifiy signature
        if not verify_signature(public_key, credential["message"], credential["signature"]):
            return VerificationResult(False, "Signature validation failed", CredType.SHC.value, None)

        return VerificationResult(True, "Signature Verified", CredType.SHC.value, None)

    def _is_credential_valid(self, credential, cred_type):
        return verify_rules(credential, cred_type, self._params)
    
    def decode(self) -> VerificationResult:
        """
        Decodes the credential
        Returns:
            VerificationResult
        """
        cred_resp = self._get_credential()
        if not cred_resp.success:
            return cred_resp

        credential = cred_resp.message

        return VerificationResult(True, "Credential Decoded", CredType.SHC.value, credential)

    def verify(self, credential) -> VerificationResult:
        """
        Performs credential verification
        Returns:
            VerificationResult
        """

        verification = self._is_signature_valid(credential)
        if not verification.success:
            return verification

        verification = self._is_credential_valid(credential["payload"], CredType.SHC.value)
        verification.credential = credential["payload"]

        return self.attach_metadata(verification, credential["payload"], CredType.SHC.value)

    @classmethod
    def get_name(cls) -> str:
        """
        Returns name of the plugin
        Returns:
            Plugin name: str
        """
        return 'eu-vci-verifier'
