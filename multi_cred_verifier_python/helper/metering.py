#
# (c) Copyright Merative US L.P. and others 2020-2022 
#
# SPDX-Licence-Identifier: Apache 2.0

from jsonpath import JSONPath
import datetime
from threading import Timer
import time
import atexit
import signal
import sys

from multi_cred_verifier_python.clients.metering_client import MeteringClient
from multi_cred_verifier_python.clients.healthpass_client import HealthPassClient
from multi_cred_verifier_python.clients.verifier_config_client import VerifierConfigClient
from multi_cred_verifier_python.verifier.credential_verifier_params import CredentialVerifierParams
from multi_cred_verifier_python.verifier.verification_result import VerificationResult
from multi_cred_verifier_python.constants.constants import \
     ISSUER_ID, CredType, SCANS_BEFORE_SENDING_METERING, \
    SECONDS_BEFORE_SENDING_METERING, RETRY_SECONDS_SENDING_METERING

_params = None

class Metering:
    _instance = None

    def __init__(self):
        raise RuntimeError('Call instance() to get a singleton')

    @classmethod
    def instance(cls, params: CredentialVerifierParams):
        global _params

        if cls._instance is None:
            cls._instance = cls.__new__(cls)
            cls._metering_cache = {}
            cls._total_scans = 0
            cls._send_metering_timer = None
            _params = params
        return cls._instance

    def increment_metering(
        self, cred, cred_type, scan_result, params: CredentialVerifierParams
    ):
        wrapper_resp = self._get_metrics_wrapper(params)
        if not wrapper_resp.success:
            return wrapper_resp

        extract_resp = self._extract_from_json_path(cred, cred_type, params)
        if not extract_resp.success:
            return extract_resp

        wrapper = wrapper_resp.message
        extracted = extract_resp.message
        key = "{}::{}".format(wrapper["customerId"], wrapper["orgId"])

        cache_found_and_updated = self._update_cached_metering(cred_type, scan_result, key, extracted, params)
        if cache_found_and_updated:
            return VerificationResult(True, "OK")

        scan = self._create_metering_scan(cred_type, scan_result, extracted)
        wrapper["scans"].append(scan)

        payload = {
            "value": wrapper,
            "params": params
        }
        self._total_scans += 1

        self._metering_cache[key] = payload
        self._set_metering_trigger(SECONDS_BEFORE_SENDING_METERING, params)

        return VerificationResult(True, "OK")

    def _get_verifier_config_client(params):
        healthpass_client = HealthPassClient.instance(params)
        return VerifierConfigClient.instance(healthpass_client, params)

    def _get_metrics_wrapper(self, params: CredentialVerifierParams):
        config_resp = self._get_verifier_config_client().get_verifier_configuration_contents(
            ISSUER_ID, params)
        if not config_resp.success:
            return config_resp

        config = config_resp.message

        cred = params.get_verifier_credential_decoded()

        wrapper = {
            "customerId": config.get("customerId") or cred["credentialSubject"].get("customerId"),
            "orgId": cred["credentialSubject"].get("organizationId") or config.get("organizationId"),
            "verDID": cred.get("id"),
            "scans": [],
        }

        return VerificationResult(True, wrapper)

    def _extract_from_json_path(
        self, cred, cred_type, params: CredentialVerifierParams
    ):
        if not cred:
            return VerificationResult(True, None)

        # If custom plugin or unknown cred type then use VC for metering
        cred_type = cred_type \
            if (cred_type in CredType._member_names_ and cred_type != CredType.UNKNOWN.value) \
            else CredType.VC.value

        config_resp = self._get_metering_config(cred_type, params)
        if not config_resp:
            return config_resp

        if (cred_type in CredType._member_names_ and cred_type != CredType.UNKNOWN.value):
            extracted = {}
            extract = config_resp.message["extract"]
            for key in extract:
                expression = "$." + extract[key]
                found = JSONPath(expression).parse(cred)
                if len(found) > 0:
                    extracted[key] = found[0]

        return VerificationResult(True, extracted)

    def _get_metering_config(self, cred_type, params):
        spec_config = params.get_specification_configuration()
        if spec_config:
            if spec_config == CredType.UNKNOWN.value:
                # VC spec was not found in the config, so we cannot bill
                return VerificationResult(False, "Unknown Credential Type", CredType.UNKNOWN.value)
            return VerificationResult(True, spec_config["metrics"][0])

        config_resp = self._get_verifier_config_client().get_verifier_configuration_contents(
            ISSUER_ID, params
        )
        if not config_resp.success:
            return config_resp

        config = config_resp.message
        if not config["configuration"][cred_type]:
            return VerificationResult(False, "Metering config not found for {}".format(cred_type))

        return VerificationResult(True, config["configuration"][cred_type]["metrics"][0])

    def _update_cached_metering(self, cred_type, scan_result, key, extracted, params):
        if key not in self._metering_cache:
            return False
        
        cache_hit = self._metering_cache[key]
        scan = None

        for s in cache_hit["value"]["scans"]:
            if s["scanResult"] == scan_result and s["credentialSpec"] == cred_type:
                if extracted:
                    for e in extracted:
                        if s[e] == extracted[e]:
                            scan = s
                            break
                scan = s
        
        if scan:
            now = datetime.datetime.now()
            scan["datetime"] = str(now.utcnow().date())[0: 23] + "T00:00:00.000Z"
            scan["total"] += 1
        else:
            new_scan = self._create_metering_scan(cred_type, scan_result, extracted)
            cache_hit["value"]["scans"].append(new_scan)

        self._metering_cache[key] = cache_hit
        self._total_scans += 1

        if self._total_scans == SCANS_BEFORE_SENDING_METERING:
            self._post_metering_payload(params)

        return True

    def _create_metering_scan(self, cred_type, scan_result, extracted):
        now = datetime.datetime.now()

        scan = {
            "datetime": str(now.utcnow().date())[0: 23] + "T00:00:00.000Z",
            "scanResult": scan_result,
            "credentialSpec": cred_type,
            "total": 1,
        }
        if extracted:
            for e in extracted:
                scan[e] = extracted[e]

        return scan

    def _set_metering_trigger(self, seconds, params, print_error = False):
        if self._send_metering_timer:
            return
        
        self._send_metering_timer = Timer(
            seconds, self._send_metering_handler, args=[params, print_error])
        self._send_metering_timer.start()

    def _send_metering_handler(self, params, print_error, from_exit = False):
        self._send_metering_timer = None

        while True:
            result = self._post_metering_payload(params)
            if result.success:
                if from_exit:
                    sys.exit()
                return
            else:
                if print_error:
                    message = "Unable to finalize sending data.  Retry in {} seconds: " \
                        .format(RETRY_SECONDS_SENDING_METERING, repr(result.error))
                    print(message)
                time.sleep(RETRY_SECONDS_SENDING_METERING)

    def _post_metering_payload(self, params, set_metering_trigger = False):
        payload = []
        for key in self._metering_cache:
            payload.append(self._metering_cache[key]["value"])

        if len(payload) == 0:
            return VerificationResult(True, "OK")

        response = MeteringClient.instance(
                HealthPassClient.instance(params), params).post_metering(payload, params)
        if response.success:
            self._total_scans = 0
            self._metering_cache = {}
            return response

        if set_metering_trigger:
            self._set_metering_trigger(RETRY_SECONDS_SENDING_METERING, params)

        return response

def _exit_handler():
    global _params

    if not _params:
        sys.exit()

    metering = Metering.instance(_params)
    metering._send_metering_handler(_params, True, True)

atexit.register(_exit_handler)
signal.signal(signal.SIGTERM, _exit_handler)
