#
# (c) Copyright Merative US L.P. and others 2020-2022 
#
# SPDX-Licence-Identifier: Apache 2.0

import json
import jwt
import datetime
from threading import Timer
import traceback

from multi_cred_verifier_python.verifier.verification_result import VerificationResult
from multi_cred_verifier_python.helper.requests import get_requests, is_expired
from multi_cred_verifier_python.verifier.credential_verifier_params import CredentialVerifierParams
from multi_cred_verifier_python.constants.constants import PAGE_SIZE, HEALTHPASS_PATH


class HealthPassClient:
    _instance = None
    _healthpass_host_url = None
    _cached_token = None
    _all_ibm_issuers = None
    _all_vci_tokens = None
    _all_eu_tokens = None
    _token_refresh_timer = None

    def __init__(self):
        raise RuntimeError('Call instance() to get a singleton')

    @classmethod
    def instance(cls, params: CredentialVerifierParams):
        if cls._instance is None:
            cls._instance = cls.__new__(cls)
            cls._instance._healthpass_host_url = params.get_healthpass_host_url() + HEALTHPASS_PATH
        return cls._instance

    @classmethod
    def clear_instance(cls):
        cls._instance = None

    def get_token(self, params, bypass_cache = False):
        # cache is bypassed by _refresh_token_handler
        cached_token = self._get_cached_token(bypass_cache)
        if cached_token:
            return VerificationResult(True, cached_token)

        verifier_credential = params.get_verifier_credential()
        try:
            url = self._healthpass_host_url + "/users/loginWithCredential"
            headers = {"Content-Type": "application/json", 'accept': 'application/json'}
            response = get_requests(True, True).post(
                url, data=json.dumps({ "credential": verifier_credential }), headers=headers, timeout=params.get_network_timeout())

            if response.status_code == 404:
                return VerificationResult(False, "Unknown Issuer")

            if response.status_code != 200:
                return VerificationResult(False, "Get token error :: {0}".format(response.text))

            response_json = response.json()
        except Exception as e:
            traceback.print_exc()
            return VerificationResult(False, "Get token error :: Network error", error=repr(e))

        self._cached_token = response_json['access_token']

        exp = self._get_token_expiration_seconds(self._cached_token)
        self._token_refresh_timer = Timer(exp, self._refresh_token_handler, args=[params])
        self._token_refresh_timer.start()

        return VerificationResult(True, response_json['access_token'])

    def get_ibm_issuer(self, x_issuer_id, issuer_id, params: CredentialVerifierParams):
        if not is_expired() and self._all_ibm_issuers:
            issuers = [issuer for issuer in self._all_ibm_issuers if issuer["id"] == issuer_id]
            if len(issuers) > 0:
                return VerificationResult(True, issuers[0])
            return VerificationResult(False, "Unknown Issuer")

        token_resp = self.get_token(params)
        if not token_resp.success:
            return token_resp

        token = token_resp.message
        try:
            url = self._healthpass_host_url + "/issuers/" + issuer_id
            headers = {"Authorization": "Bearer "+token, "x-hpass-issuer-id": x_issuer_id}
            response = get_requests().get(url, headers=headers, timeout=params.get_network_timeout())

            if response.status_code == 404:
                return VerificationResult(False, "Unknown Issuer")

            if response.status_code != 200:
                return VerificationResult(False, "IDHP public key error :: {0}".format(response.text))

            response_json = response.json()
        except Exception as e:
            traceback.print_exc()
            return VerificationResult(False, "IDHP public key error :: Network error", error=repr(e))

        return VerificationResult(True, response_json["payload"])

    def get_all_ibm_issuers(self, x_issuer_id, params: CredentialVerifierParams):
        token_resp = self.get_token(params)
        if not token_resp.success:
            return token_resp

        token = token_resp.message
        try:
            url = self._healthpass_host_url + "/issuers"
            headers = {"Authorization": "Bearer "+token, "x-hpass-issuer-id": x_issuer_id}
            response = get_requests().get(url, headers=headers, timeout=params.get_network_timeout())

            if response.status_code == 404:
                return VerificationResult(False, "IDHP all public key error :: no keys found")

            if response.status_code != 200:
                return VerificationResult(False, "IDHP all public key error :: {0}".format(response.text))

            response_json = response.json()
        except Exception as e:
            traceback.print_exc()
            return VerificationResult(False, "IDHP all public key error :: Network error", error=repr(e))

        self._all_ibm_issuers = response_json["payload"]
        return VerificationResult(True, response_json["payload"])

    def get_revoke_status(self, x_issuer_id, cred_id, params: CredentialVerifierParams):
        token_resp = self.get_token(params)
        if not token_resp.success:
            return token_resp

        token = token_resp.message
        try:
            encoded_cred_id = cred_id.replace("#", "%23")
            url = self._healthpass_host_url + "/credentials/" + encoded_cred_id + "/revoke_status/optional"
            headers = {"Authorization": "Bearer " + token, "x-hpass-issuer-id": x_issuer_id}
            response = get_requests().get(url, headers=headers, timeout=params.get_network_timeout())
            response_json = response.json()
            if response.status_code != 200:
                return VerificationResult(False, "Revoke status error :: {0}".format(response.text))
        except Exception as e:
            traceback.print_exc()
            return VerificationResult(False, "Revoke status error :: Network error", error=repr(e))

        return VerificationResult(True, response_json['payload'])

    def get_vci_token(self, x_issuer_id, iss, kid, params: CredentialVerifierParams):
        if not is_expired() and self._all_vci_tokens:
            keys = [key for key in self._all_vci_tokens if key["keys"][0]["kid"] == kid]
            if len(keys) > 0:
                return VerificationResult(True, keys[0]["keys"][0])
            return VerificationResult(False, "Unknown Issuer")

        token_resp = self.get_token(params)
        if not token_resp.success:
            return token_resp

        token = token_resp.message
        try:
            url = self._healthpass_host_url + "/generic-issuers/vci/query"
            headers = {"Content-Type": "application/json", 'accept': 'application/json',
                       "Authorization": "Bearer "+token, "x-hpass-issuer-id": x_issuer_id}
            response = get_requests().post(
                url, data=json.dumps({"url": iss}), headers=headers, timeout=params.get_network_timeout())
            
            if response.status_code == 404:
                return VerificationResult(False, "Unknown Issuer")

            if response.status_code != 200:
                return VerificationResult(False, "SHC public key error :: {0}".format(response.text))
            
            response_json = response.json()

            if ("payload" not in response_json) or (len(response_json["payload"]) == 0):
                return VerificationResult(False, "Unknown Issuerr")

            keys = [key for key in response_json["payload"][0]["keys"] if key["kid"] == kid]
            if len(keys) == 0:
                return VerificationResult(False, "Unknown Issuer")
            return VerificationResult(True, keys[0])

        except Exception as e:
            traceback.print_exc()
            return VerificationResult(False, "SHC public key error :: Network error", error=repr(e))

    def get_all_vci_tokens(self, x_issuer_id, params: CredentialVerifierParams):
        token_resp = self.get_token(params)
        if not token_resp.success:
            return token_resp

        token = token_resp.message
        try:
            bookmark = None
            payload = []

            while True:
                url = self._healthpass_host_url + "/generic-issuers/vci"
                headers = {"Content-Type": "application/json", 'accept': 'application/json',
                        "Authorization": "Bearer "+token, "x-hpass-issuer-id": x_issuer_id}
                req_params = { "pagesize": PAGE_SIZE }

                if bookmark:
                    req_params.update({ "bookmark": bookmark })

                response = get_requests().get(
                    url, headers=headers, params=req_params, timeout=params.get_network_timeout())
                
                if response.status_code == 404:
                    return VerificationResult(False, "SHC all public key error :: no keys found")

                if response.status_code != 200:
                    return VerificationResult(False, "SHC all public key error :: {0}".format(response.text))
                
                response_json = response.json()
                payload += response_json["payload"]["payload"]

                if response_json["payload"]["record_count"] < PAGE_SIZE:
                    break

                bookmark = response_json["payload"]["bookmark"]

            self._all_vci_tokens = payload
            return VerificationResult(True, payload)

        except Exception as e:
            traceback.print_exc()
            return VerificationResult(False, "SHC all public key error :: Network error", error=repr(e))

    def get_eu_token(self, x_issuer_id, kid, country, params: CredentialVerifierParams):
        if not is_expired() and self._all_eu_tokens:
            keys = [key for key in self._all_eu_tokens if key["kid"] == kid and key["country"] == country]
            if len(keys) > 0:
                return VerificationResult(True, keys[0]["rawData"])
            return VerificationResult(False, "Unknown Issuer")

        token_resp = self.get_token(params)
        if not token_resp.success:
            return token_resp

        token = token_resp.message
        try:
            url = self._healthpass_host_url + "/generic-issuers/dcc/"

            headers = { "Content-Type": "application/json", 'accept': 'application/json',
                        "Authorization": "Bearer "+token, "x-hpass-issuer-id": x_issuer_id }
            req_params = { "kid": kid }
            response = get_requests().get(
                url, headers=headers, params = req_params, timeout=params.get_network_timeout())
            
            if response.status_code == 404:
                return VerificationResult(False, "Unknown Issuer")

            if response.status_code != 200:
                return VerificationResult(False, "DCC public key error :: {0}".format(response.text))

            response_json = response.json()

            if len(response_json["payload"]["payload"]) == 0:
                return VerificationResult(False, "Unknown Issuerr")

            for key in response_json["payload"]["payload"]:
                if key["kid"] == kid and key["country"] == country:
                    return VerificationResult(True, key["rawData"])

            return VerificationResult(False, "Unknown Issuer")

        except Exception as e:
            traceback.print_exc()
            return VerificationResult(False, "DCC public key error :: Network error", error=repr(e))

    def get_all_eu_tokens(self, x_issuer_id, params: CredentialVerifierParams):
        token_resp = self.get_token(params)
        if not token_resp.success:
            return token_resp

        token = token_resp.message
        try:
            bookmark = None
            payload = []

            while True:
                url = self._healthpass_host_url + "/generic-issuers/dcc/"
                headers = { "Content-Type": "application/json", 'accept': 'application/json',
                            "Authorization": "Bearer "+token, "x-hpass-issuer-id": x_issuer_id }
                req_params = { "pagesize": PAGE_SIZE }

                if bookmark:
                    req_params.update({ "bookmark": bookmark })
                
                response = get_requests().get(
                    url, headers=headers, params = req_params, timeout=params.get_network_timeout())
                
                if response.status_code == 404:
                    return VerificationResult(False, "DCC all public key error :: no keys found")

                if response.status_code != 200:
                    return VerificationResult(False, "DCC all public key error :: {0}".format(response.text))

                response_json = response.json()
                payload += response_json["payload"]["payload"]

                if response_json["payload"]["record_count"] < PAGE_SIZE:
                    break

                bookmark = response_json["payload"]["bookmark"]

            self._all_eu_tokens = payload
            return VerificationResult(True, payload)

        except Exception as e:
            traceback.print_exc()
            return VerificationResult(False, "DCC all public key error :: Network error", error=repr(e))

    def clear_all_ibm_issuers(self):
        global _all_ibm_issuers
        _all_ibm_issuers = None
    
    def clear_all_vci_tokens(self):
        global _all_vci_tokens
        _all_vci_tokens = None
    
    def clear_all_eu_tokens(self):
        global _all_eu_tokens
        _all_eu_tokens = None

    def _get_cached_token(self, bypass_cache):
        if bypass_cache or not self._cached_token:
            return None

        cached_token = self._cached_token
        if self._is_token_expired(cached_token):
            self._stop_refresh_token_handler()
            return None
        return cached_token

    def _refresh_token_handler(self, params):
        token_resp = self.get_token(params, True)
        if token_resp.success:
            self._cached_token = token_resp.message
            return
        self._token_refresh_timer = Timer(10, self._refresh_token_handler)
        self._token_refresh_timer.start()

    def _stop_refresh_token_handler(self):
        if not self._token_refresh_timer:
            return
        self._token_refresh_timer.cancel()
        self._token_refresh_timer = None

    def _get_token_expiration_seconds(self, token):
        expiration = self._get_token_expiration(token)
        now = datetime.datetime.now()
        return (expiration - now).seconds - 60

    def _is_token_expired(self, token):
        expiration = self._get_token_expiration(token)
        now = datetime.datetime.now()
        return now >= expiration

    def _get_token_expiration(self, token):
        decoded = jwt.decode(token, options={"verify_signature": False})
        return datetime.datetime.fromtimestamp(decoded["exp"]) - datetime.timedelta(seconds=30)
