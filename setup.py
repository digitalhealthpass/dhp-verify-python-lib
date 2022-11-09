#
# (c) Copyright Merative US L.P. and others 2020-2022 
#
# SPDX-Licence-Identifier: Apache 2.0

from setuptools import find_packages, setup

setup(
    name='multi_cred_verifier_python',
    packages=find_packages(exclude=['test', 'test.*', 'tests', 'tests.*']),
    version='0.1.0',
    description='DHP Multi-Credential Verifier SDK for Python',
    install_requires=[
        'base45==0.4.3',
        'requests-cache==0.8.0',
        'cbor2==5.4.1',
        'cwt==1.3.2',
        'pycryptodome==3.9.9',
        "pytz==2021.3",
        "jsonpath-python==1.0.5",
        "PyJWT==2.3.0",
        "python-dateutil==2.8.2",
    ],
    setup_requires=['pytest-runner'],
    tests_require=['pytest==4.4.1'],
    test_suite='tests',
    package_data={'pytransform': ['pytransform/_pytransform.dylib']},
    include_package_data=True,
)