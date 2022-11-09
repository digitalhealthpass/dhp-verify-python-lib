#
# (c) Copyright Merative US L.P. and others 2020-2022 
#
# SPDX-Licence-Identifier: Apache 2.0

from requests_cache import CachedSession
import requests
import time
from threading import Timer
from datetime import datetime
import pytz

from multi_cred_verifier_python.helper.pre_cache_utils import PreCacheUtil
from multi_cred_verifier_python.verifier.verification_result import VerificationResult
from multi_cred_verifier_python.constants.constants import ISSUER_ID

verifier_config_expiration_datetime = None
verifier_config_warning_datetime = None
cache_expiration_datetime = None
cache_warning_datetime = None
cached_session = None

_realtime = True
_cache_refresh_timer = None
_healthpass_client = None
_verifier_config_client = None
_expiration_ms = None
_cache_refresh_error = None

def init_requests(healthpass_client, verifier_config_client, expiration_ms, offline):
    global _realtime
    global cached_session
    global _healthpass_client
    global _verifier_config_client
    global _expiration_ms

    _healthpass_client = healthpass_client
    _verifier_config_client = verifier_config_client
    _expiration_ms = expiration_ms
    _realtime = not offline if offline != None else True
    _new_cached_session()

def _new_cached_session():
    global cached_session
    global _expiration_ms

    cached_session = CachedSession(
        backend = "memory",
        cache_control = False,
        expire_after = _expiration_ms or 86400, # 1 day default
        allowable_methods = ['GET'],
        allowable_codes = [200],
        stale_if_error = False,
    )

def clear_cache():
    _new_cached_session()

def get_requests(bypass_expiration = False, bypass_cache = False):
    global _realtime
    global cached_session

    if bypass_cache:
        return requests

    if not bypass_expiration:
        response = check_expired_verifier_config()
        if not response.success:
            return ErrorRequest(401, response.message)
        
        response = check_expired_cache()
        if not response.success:
            return ErrorRequest(443, response.message)
    return requests if _realtime or not cached_session else cached_session

def start_cache_refresh_handler(offline, cache_refresh_seconds, params):
    global _realtime
    global _cache_refresh_timer
    global _cache_refresh_timer
    global _cache_refresh_error

    if _cache_refresh_timer:
        _cache_refresh_error = None
        _cache_refresh_timer.cancel()

    _realtime = not offline
    _cache_refresh_timer = Timer(cache_refresh_seconds, _cache_refresh_handler, args=[params])
    _cache_refresh_timer.start()

def get_expiration_warnings():
    global verifier_config_expiration_datetime
    global verifier_config_warning_datetime
    global cache_expiration_datetime
    global cache_warning_datetime

    warnings = []
    
    now = datetime.now().utcnow().now(pytz.utc)

    if now < verifier_config_expiration_datetime and \
            now > verifier_config_warning_datetime:
        msg = "The cache will expire on {}.  Connect to network to refresh " \
            "cache before then to continue verifying credentials." \
            .format(_to_local_datetime(verifier_config_expiration_datetime))
        warnings.append(msg)

    if now < cache_expiration_datetime and \
            now > cache_warning_datetime:
        msg = "Verifier credential will expired on {}.  Set a new verifier credential while " \
            "connected to network before then to continue verifying credentials." \
            .format(_to_local_datetime(cache_expiration_datetime))
        warnings.append(msg)
    
    return warnings

def check_expired_verifier_config():
    global verifier_config_expiration_datetime
    
    now = datetime.now().utcnow().now(pytz.utc)

    if verifier_config_expiration_datetime and now >= verifier_config_expiration_datetime:
        msg = "Verifier credential expired on {}.  Set a new verifier credential " \
            "while connected to network to continue verifying credentials" \
            .format(_to_local_datetime(verifier_config_expiration_datetime))
        return VerificationResult(False, msg)
    
    return VerificationResult(True, "OK")

def check_expired_cache():
    global cache_expiration_datetime

    formatted_error = ""
    if _cache_refresh_error:
        formatted_error = " :: %r" % _cache_refresh_error

    now = datetime.now().utcnow().now(pytz.utc)

    if cache_expiration_datetime and now >= cache_expiration_datetime:
        msg = "Cache expired on {}.  Connect to network to automatically  " \
            "refresh cache to continue verifying credentials{}" \
            .format(_to_local_datetime(cache_expiration_datetime), formatted_error)
        return VerificationResult(False, msg)
    
    return VerificationResult(True, "OK")            

def is_expired():
    global verifier_config_expiration_datetime
    global cache_expiration_datetime

    if not verifier_config_expiration_datetime or \
            not cache_expiration_datetime:
        return False

    now = datetime.now().utcnow().now(pytz.utc)

    return now >= verifier_config_expiration_datetime \
            or now >= cache_expiration_datetime

def _to_local_datetime(dt: datetime):
    t = time.altzone if time.daylight else time.timezone
    time_zone = pytz.timezone('Etc/GMT%+d' % (t / 3600))    
    return dt.astimezone(time_zone).strftime("%m/%d/%Y %H:%M:%S %p")

def _cache_refresh_handler(params):
    global _realtime
    global _healthpass_client
    global _verifier_config_client
    global _cache_refresh_error
    global _expiration_ms

    while True:
        config_response: VerificationResult = _verifier_config_client.get_verifier_configurations(
            ISSUER_ID, params)

        if config_response.success:
            new_expiration_ms = config_response.message["refresh"]
            if _expiration_ms != new_expiration_ms:
                _new_cached_session()

            pre_cach_resp: VerificationResult = PreCacheUtil(
                _healthpass_client,
                _verifier_config_client,
                params
            ).pre_cache(not _realtime)

            if pre_cach_resp.success:
                _cache_refresh_error = None
                break
            _cache_refresh_error = pre_cach_resp.message

        time.sleep(10)
    requests.post

Any = object()

class ErrorRequest:
    def __init__(self, code, message):
        self._code = code
        self._message = message

    def get(
        self,
        url = None,
        params = None,
        data = None,
        headers = None,
        cookies = None,
        files = None,
        auth = None,
        timeout = None,
        allow_redirects = None,
        proxies = None,
        hooks = None,
        stream = None,
        verify = None,
        cert = None,
        json = None,
    ):
        return ErrorResponse(self._code, self._message)
    def post(
        self,
        url = None,
        data = None,
        json = None,
        params = None,
        headers = None,
        cookies = None,
        files = None,
        auth = None,
        timeout = None,
        allow_redirects = None,
        proxies = None,
        hooks = None,
        stream = None,
        verify = None,
        cert = None,
    ):
        return ErrorResponse(self._code, self._message)

class ErrorResponse:
    status_code = None
    text = None
    json = None

    def __init__(self, code, message) -> None:
        self.code = code
        self.text = message
