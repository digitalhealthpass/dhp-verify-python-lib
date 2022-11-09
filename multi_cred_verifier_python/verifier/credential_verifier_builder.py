#
# (c) Copyright Merative US L.P. and others 2020-2022 
#
# SPDX-Licence-Identifier: Apache 2.0

from pkgutil import iter_modules
from importlib import import_module
import inspect
import json
import base64

from multi_cred_verifier_python import verifier_plugins
from multi_cred_verifier_python.verifier.credential_verifier_params import CredentialVerifierParams
from multi_cred_verifier_python.verifier.credential_verifier import CredentialVerifier
from multi_cred_verifier_python.verifier.verifier_plugin import VerifierPluginBase
from multi_cred_verifier_python.clients.healthpass_client import HealthPassClient
from multi_cred_verifier_python.clients.verifier_config_client import VerifierConfigClient
from multi_cred_verifier_python.clients.metering_client import MeteringClient
from multi_cred_verifier_python.verifier.verification_result import VerificationResult
from multi_cred_verifier_python.helper.requests import init_requests
from multi_cred_verifier_python.helper.pre_cache_utils import PreCacheUtil
from multi_cred_verifier_python.constants.constants import ISSUER_ID
from multi_cred_verifier_python.helper.requests import clear_cache

class CredentialVerifierBuilder:
    """ Builder class to configure, instantiate and return CredentialVerifier"""
    def __init__(self):
        self._verification_params = CredentialVerifierParams()
        self._initialized = False
        self._plugins = []
        self._disabled_plugins = []

    def set_credential(self, credential):
        """
        Sets the credential to be verified
        Args:
            credential: string
        Returns:
            builder object
        """
        self._verification_params.set_credential(self._parse_credential_str(credential))
        return self

    def set_verifier_credential(self, verifier_credential):
        decoded, encoded = self._decode_verifier_credential(verifier_credential)
        self._verification_params.set_verifier_credential(encoded)
        self._verification_params.set_verifier_credential_decoded(decoded)
        return self

    def set_healthpass_host_url(self, healthpass_host_url):
        """
        Sets the healthpass host URL
        Args:
            healthpass host url: string
        Returns:
            builder object
        """
        self._verification_params.set_healthpass_host_url(healthpass_host_url)
        return self

    def set_return_credential(self, return_credential):
        """
        Sets the return credential indicator
        Args:
            return credential ind: string
        Returns:
            builder object
        """
        self._verification_params.set_return_credential(return_credential)
        return self

    def set_return_metadata(self, return_metadata):
        """
        Sets the return metadata indicator
        Args:
            return credential ind: json
        Returns:
            builder object
        """
        self._verification_params.set_return_metadata(return_metadata)
        return self

    def set_metadata_language(self, metadata_language):
        """
        Sets the dispaly language
        Args:
            display language: string
        Returns:
            builder object
        """
        self._verification_params.set_metadata_language(metadata_language)
        return self


    def set_network_timeout(self, seconds):
        self._verification_params.set_network_timeout(seconds)
        return self

    def set_additional_plugins(self, additional_plugins):
        """
        Sets the additional plugins
        Args:
            additional_plugins: list of strings containing fully qualified class names
        Returns:
            builder object
        """
        for plugin_class in additional_plugins:
            try:
                module_path, class_name = plugin_class.rsplit('.', 1)
                plugin_class_attribute = getattr(import_module(module_path), class_name)
                if issubclass(plugin_class_attribute, VerifierPluginBase):
                    self._plugins.append(plugin_class_attribute)
                else:
                    raise Exception("Verifier plugins must inherent from VerifierPluginBase")
                if inspect.isabstract(plugin_class_attribute):
                    raise Exception("Verifier plugins must implement verify() and get_name()")
            except (ImportError, AttributeError) as e:
                raise ImportError(plugin_class)
        return self

    def set_disabled_plugins(self, disabled_plugins):
        """
        Sets the disabled plugins
        Args:
            disabled_plugins: list of plug-in names to be disabled
        Returns:
            builder object
        """
        self._disabled_plugins = disabled_plugins
        return self

    def set_extras(self, extras):
        """
        This can be anything that is needed by a custom credential verifier plugin
        Args:
            extras
        Returns:
            builder object
        """
        self._verification_params.set_extras(extras)
        return self

    def init(self):
        self._verify_init_params()
        self.load_plugins()
        
        HealthPassClient.clear_instance()
        VerifierConfigClient.clear_instance()
        MeteringClient.clear_instance()

        healthpass_client = HealthPassClient.instance(self._verification_params)

        verifier_config_client = VerifierConfigClient.instance(
            healthpass_client, self._verification_params
        )

        metering_client = MeteringClient.instance(
            healthpass_client, self._verification_params
        )

        health_resp = metering_client.get_health(self._verification_params)
        if not health_resp.success:
            return health_resp.clean_result()

        config_response: VerificationResult = verifier_config_client.get_verifier_configurations(
            ISSUER_ID, self._verification_params)

        if not config_response.success:
            return config_response.clean_result()

        offline = config_response.message["offline"]
        expiration_ms = config_response.message["refresh"]

        init_requests(healthpass_client, verifier_config_client, expiration_ms, offline)

        util = PreCacheUtil(healthpass_client, verifier_config_client, self._verification_params)
        pre_cache_resp = util.pre_cache(offline)

        # Scanning another verifier config, so clear out cache
        if self._initialized:
            clear_cache()

        if not pre_cache_resp.success:
            return pre_cache_resp.clean_result()

        self._initialized = True
        return VerificationResult(True, "Builder successfully initialized")

    def load_plugins(self):
        # load all the plugins that extend VerifierPluginBase from verifier_plugins module
        plugins = []
        for (_, submodule_name, _) in iter_modules(verifier_plugins.__path__):
            sub_module = import_module(f"multi_cred_verifier_python.verifier_plugins.{submodule_name}")
            for name, obj in inspect.getmembers(sub_module):
                if inspect.isclass(obj) and (obj in VerifierPluginBase.__subclasses__()):
                    instance = obj(self._verification_params)
                    if instance.get_name() not in self._disabled_plugins:
                        plugins.append(instance)
        
        if len(plugins) == 0:
            raise Exception("No verifier plugins found")

        self._plugins = plugins
        
    def build(self) -> CredentialVerifier:
        """
        Build CredentialVerifier instance
        Returns:
            CredentialVerifier object
        """

        if not self._initialized:
            raise Exception("init() must be called at least once on the builder instance before building verifiers")

        self._verify_build_params()
        verifier = CredentialVerifier(self._plugins, self._verification_params)
        return verifier

    def _decode_verifier_credential(self, verifier_credential: str):
        decoded = verifier_credential
        encoded = verifier_credential

        try:
            decoded = json.loads(verifier_credential)
            encoded = base64.b64encode(verifier_credential.encode('ascii')).decode()
        except Exception as e1:
            try:
                decoded = json.loads(base64.b64decode(verifier_credential))
            except Exception as e2:
                pass
        return decoded, encoded

    def _parse_credential_str(self, credential):
        """
        Parse credential string
        Args:
            credential: string
        Returns:
            python dict/ str
        """
        try:
            # load json formatted credential to python dictionary
            return json.loads(credential)
        except Exception as e:
            # if the message doesn't contain "payload" or the whole credential is encoded or not in a valid json format
            # return credential string
            return credential

    def _verify_init_params(self):
        if not self._verification_params.get_healthpass_host_url():
            raise Exception("Healthpass Host URL must be set")
        if not self._verification_params.get_verifier_credential():
            raise Exception("A verifier credential must be supplied")
        self._verify_verifier_credential_decoded()

    def _verify_verifier_credential_decoded(self):
        decoded = self._verification_params.get_verifier_credential_decoded()

        if not "credentialSubject" in decoded:
            raise Exception("Invalid verifier credential.  Missing credentialSubject")
        if not "configId" in decoded["credentialSubject"]:
            raise Exception("Invalid verifier credential.  Missing credentialSubject.configId")
        if not "customerId" in decoded["credentialSubject"]:
            raise Exception("Invalid verifier credential.  Missing credentialSubject.customerId")
        if not "organizationId" in decoded["credentialSubject"]:
            raise Exception("Invalid verifier credential.  Missing credentialSubject.organizationId")

    def _verify_build_params(self):
        """
        Check if required parameters are provided
        """
        if len(self._plugins) == 0:
            raise Exception("No verifier plugins found")

        if self._verification_params.get_credential() is None:
            raise Exception("A Credential must be supplied")
        if self._verification_params.get_healthpass_host_url() is None:
            raise Exception("Healthpass host URL must be set")

