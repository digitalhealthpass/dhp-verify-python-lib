#
# (c) Copyright Merative US L.P. and others 2020-2022 
#
# SPDX-Licence-Identifier: Apache 2.0

import base64
import zlib
import cbor2
import cwt
from cwt import COSEKey
from Crypto.PublicKey import ECC
import datetime

from multi_cred_verifier_python.verifier.verifier_plugin import VerifierPluginBase
from multi_cred_verifier_python.verifier.verification_result import VerificationResult

from multi_cred_verifier_python.helper.crypto_utils import base45_decode, base64_bytes_decode, base64_url_decode_bytes
from multi_cred_verifier_python.helper.rule_utils import verify_rules
from multi_cred_verifier_python.constants.constants import CredType, EUCredKeys, ISSUER_ID


class EUCredentialVerifier(VerifierPluginBase):

    def __init__(self, params):
        super().__init__(params)

    @staticmethod
    def _check_is_eu_credential(credential):
        """
        Checks if the credential is EU credential
        Args:
            credential: dict/str
        Returns:
            boolean
        """
        return (credential is not None) and \
            (((type(credential) is str) and (credential.startswith("HC1"))) or
                ((type(credential) is dict) and ("proof" in credential) and ("proofValue" in credential["proof"])))

    @staticmethod
    def _decode_kid(kid_map):
        if (type(kid_map) is dict) and (4 in kid_map):
            try:
                kid = base64_bytes_decode(kid_map.get(4))
                return kid
            except Exception as e:
                return None
        return None

    def _get_kid(self, decoded_cbor):
        unprotected_map = decoded_cbor.value[1]

        kid = self._decode_kid(unprotected_map)
        if kid is None:
            protected_map = cbor2.loads(decoded_cbor.value[0])
            kid = self._decode_kid(protected_map)
            encoded_kid = protected_map.get(4)
        else:
            encoded_kid = unprotected_map.get(4)
        return kid, encoded_kid

    def _epochToIso(self, epoch):
        return f"{str(datetime.datetime.utcfromtimestamp(epoch).isoformat())}.000Z"

    def _get_credential(self):
        credential = self._params.get_credential()
        if type(credential) == dict:
            return credential

        to_decode = credential[4:] if credential.startswith("HC1:") else credential[3:]
        decoded = base45_decode(to_decode)

        inflated_cred = zlib.decompress(decoded)

        decoded_cbor = cbor2.loads(inflated_cred)

        # tag 18 - COSE_Sign1 (COSE Single Signer Data Object)
        kid, encoded_kid = self._get_kid(decoded_cbor)

        cred_map = cbor2.loads(decoded_cbor.value[2])

        issuing_country = cred_map.get(EUCredKeys.ISSUING_COUNTRY.value)
        issuance_date = self._epochToIso(cred_map.get(EUCredKeys.ISSUANCEDATE.value))
        expiration_date = self._epochToIso(cred_map.get(EUCredKeys.EXPIRATIONDATE.value))
        credential = cred_map.get(EUCredKeys.CREDENTIAL.value).get(1)

        signature = decoded_cbor.value[3]

        return {"kid": kid, "encoded_kid": encoded_kid, "issuanceDate": issuance_date, "expirationDate": expiration_date,
               "credential": credential, "signature": signature, "cborData": inflated_cred, "issuing_country": issuing_country}

    def _get_public_key(self, credential):
        verification = self._healthpass_client.get_eu_token(
            'hpass.issuer1', credential["kid"], credential["issuing_country"], self._params)
        if not verification.success:
            return verification

        key_der = verification.message

        ecc_key = ECC.import_key(base64_url_decode_bytes(key_der))
        x = base64.b64encode(ecc_key.pointQ.x.to_bytes()).decode("utf-8")
        y = base64.b64encode(ecc_key.pointQ.y.to_bytes()).decode("utf-8")

        pub_key = COSEKey.from_jwk(
            {
                "kty": "EC",
                "crv": "P-256",
                "kid": credential["encoded_kid"],
                "x": x,
                "y": y
            })
        return VerificationResult(True, pub_key)

    def _is_signature_valid(self, credential):
        key_resp = self._get_public_key(credential)
        if not key_resp.success:
            return key_resp

        pub_key = key_resp.message
        try:
            cwt.decode(credential["cborData"], [pub_key], no_verify=True)
        except Exception as e:
            return VerificationResult(
                False, "Certificate's signature is not valid", CredType.DCC.value)
        return VerificationResult(True, "Valid EU Credential", CredType.DCC.value, None)

    def _is_credential_valid(self, credential, cred_type):
        payload = {
            "payload": credential["credential"]
        }
        payload["payload"]["issuanceDate"] = credential["issuanceDate"]
        payload["payload"]["expirationDate"] = credential["expirationDate"]
        return verify_rules(payload, cred_type, self._params)

    def decode(self) -> VerificationResult:
        """
        Decodes the credential
        Returns:
            VerificationResult
        """

        if not self._check_is_eu_credential(self._params.get_credential()):
            return VerificationResult(False, None, CredType.DCC.value, None)

        try:
            credential = self._get_credential()
            return VerificationResult(True, "Credential Decoded", CredType.DCC.value, credential)
        except Exception as e:
            return VerificationResult(False, f"Decode credential error", CredType.DCC.value, error=repr(e))

    def verify(self, credential) -> VerificationResult:
        """
        Performs credential verification
        Returns:
            VerificationResult
        """

        verification = self._is_signature_valid(credential)
        if not verification.success:
            return verification

        verification = self._is_credential_valid(credential, CredType.DCC.value)

        verification.credential = credential["credential"]

        return self.attach_metadata(verification, credential["credential"], CredType.DCC.value)

    @classmethod
    def get_name(cls) -> str:
        """
        Returns name of the plugin
        Returns:
            Plugin name: str
        """
        return 'eu-dcc-verifier'
