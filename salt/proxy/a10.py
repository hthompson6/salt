# -*- coding: utf-8 -*-
'''
A10 Proxy Module
=================
:codeauthor: Hunter Thompson <hthompson@a10networks.com>
:maturity:   new
:depends:    a10_saltstack

Proxy minion to manage ACOS devices via the AXAPI

Pillars
---------
Specify the following information in a given pillar order to connect
to an A10 ACOS Device.

.. code-block:: yaml
    proxy:
      proxytype: a10
      host: <ip or fdqn of host>
      username: <username>
      password: <supersecret>
      port: <port number>
      protocol: <http, https, tcp, etc.>

'''

# Import Python Libraries
from __future__ import absolute_import
import logging

# Import A10 Modules
try:
    from a10_saltstack.client import axapi_http
    from a10_saltstack.client import session
    HAS_A10 = True
except ImportError:
    HAS_A10 = False

# Import Salt Modules
from salt.ext.six.moves import map

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

__proxyenabled__ = ['a10']
__virtualname__ = 'a10'

GRAINS_CACHE = {}
DETAILS = {}

LOG = logging.getLogger(__file__)


def __virtual__():
    '''
    In order for the module to execute properly,
    the a10_salstack library must be present.
    '''
    if not HAS_A10:
        return False, 'Missing dependency: The a10 proxy minion requires the a10-saltstack Python module.'

    return __virtualname__


def proxytype():
    '''
    Returns the name of this proxy
    '''
    return 'a10'


def _validate(**params):
    # Ensure that params contains all the keys.
    requires_one_of = sorted([])
    present_keys = sorted([x for x in requires_one_of if params.get(x)])

    errors = []
    marg = []

    if not len(requires_one_of):
        return REQUIRED_VALID

    if len(present_keys) == 0:
        rc, msg = REQUIRED_NOT_SET
        marg = requires_one_of
    elif requires_one_of == present_keys:
        rc, msg = REQUIRED_MUTEX
        marg = present_keys
    else:
        rc, msg = REQUIRED_VALID

    if not rc:
        errors.append(msg.format(", ".join(marg)))

    return rc, errors


def init(opts):
    '''
    Create a client to a given ACOS device, and launch an
    authenticated session
    '''
    valid = True

    run_errors = []
    proxyinfo = opts['proxy']
    valid, validation_errors = _validate(**opts)
    list(map(run_errors.append, validation_errors))

    if not valid:
        err_msg = "Validation failure\n".join(run_errors)

    http_cli = axapi_http.HttpClient(proxyinfo['host'], proxyinfo['port'], proxyinfo['protocol'])
    DETAILS['ax_session'] = session.Session(http_cli, proxyinfo['username'], proxyinfo['password'])


def get_session():
    return DETAILS['ax_session']


def shutdown(opts):
    '''
    For this proxy shutdown is a no-op
    '''
    LOG.debug('a10 proxy shutdown() called...')
