# -*- coding: utf-8 -*-
'''
A10 Execution Module
=====================
:codeauthor: Hunter Thompson <hthompson@a10networks.com>
:maturity:   new
:depends:    a10_saltstack

Module to manage A10 ACOS devices using the AXAPI
'''

# Import Python Libraries
from __future__ import absolute_import
import logging

# Import A10 Modules
try:
    from a10_saltstack.client import client as a10_client
    from a10_saltstack import a10_saltstack_interface as a10_salt
    HAS_A10 = True
except ImportError:
    HAS_A10 = False

LOG = logging.getLogger(__file__)


__virtualname__ = 'a10'
__proxyenabled__ = ['a10']


def __virtual__():
    '''
    In order for the module to execute properly,
    the a10_salstack library must be present.
    '''

    if HAS_A10 and 'proxy' in __opts__:
        return __virtualname__
    return (False, 'The a10 module could not be loaded: '
                   'proxy could not be loaded.')


def _get_client():
    return a10_client.A10Client(__proxy__['a10.get_session']())


def create(a10_obj, **kwargs):
    '''
    This function creates an ACOS object based upon the
    passed kwargs.

    a10_obj
        The type of ACOS object to be created

    CLI Example:
    .. code-block:: bash
        salt '*' a10.create slb_virtual_server name='vs1' ip_address='192.168.42.1'
    '''

<<<<<<< HEAD
<<<<<<< HEAD
=======
    url = a10_helper.get_url(a10_obj, 'create', **kwargs)
    avail_props = a10_helper.get_props(a10_obj, **kwargs)
    obj_type = a10_helper.get_obj_type(a10_obj)
    post_result = {}
    try:
        payload = _build_json(obj_type, avail_props, **kwargs)
        if payload[obj_type].get('a10-name'):
            payload[obj_type]["name"] = payload[obj_type]["a10-name"]
            del payload[obj_type]["a10-name"]
        client = _get_client()
        post_result['post_resp'] = client.post(url, payload)
        post_result['result'] = True
    except a10_ex.Exists:
        post_result['result'] = False
    except a10_ex.ACOSException as ex:
        post_result['comment'] = ex.msg
    except Exception as gex:
        raise gex
    return post_result
>>>>>>> 481f135... Removed args being passed to client

=======
>>>>>>> 9f3c2c3... Removed merge conflict
    client = _get_client()
    post_result = a10_salt.parse_obj(a10_obj, 'slb', client, **kwargs)
    return post_result

def update(a10_obj, **kwargs):
    '''
    This function updates an ACOS object based upon the
    passed kwargs.

    a10_obj
        The type of ACOS object to be created

    CLI Example:
    .. code-block:: bash
        salt '*' a10.update slb_virtual_server name='vs1' ip_address=192.168.42.1


    url = a10_helper.get_url(a10_obj, 'update', **kwargs)
    avail_props = a10_helper.get_props(a10_obj, **kwargs)
    obj_type = a10_helper.get_obj_type(a10_obj)
    post_result = {}
    try:
        payload = _build_json(obj_type, avail_props, **kwargs)
<<<<<<< HEAD
<<<<<<< HEAD
        if payload[obj_type].get('a10-name'):
            payload[obj_type]["name"] = payload[obj_type]["a10-name"]
            del payload[obj_type]["a10-name"]
=======
>>>>>>> 481f135... Removed args being passed to client
=======
        if payload[obj_type].get('a10-name'):
            payload[obj_type]["name"] = payload[obj_type]["a10-name"]
            del payload[obj_type]["a10-name"]
>>>>>>> 6fb8724... Added logic to utilize name param for module lookup
        client = _get_client()
        post_result = client.put(url, payload)
    except a10_ex.NotFound:
        post_result['result'] = False
    except a10_ex.ACOSException as ex:
        post_result['comment'] = ex.msg
    except Exception as gex:
        raise gex
    return post_result
    '''
    pass

def delete(a10_obj, **kwargs):
    '''
    This function deletes an ACOS object based upon the
    passed kwargs.

    a10_obj
        The type of ACOS object to be deleted

    CLI Example:
    .. code-block:: bash
        salt '*' a10.delete slb_virtual_server name='vs1'
    

    url = a10_helper.get_url(a10_obj, 'delete', **kwargs)
    post_result = {}
    try:
        client = _get_client()
        client.delete(url)
    except a10_ex.NotFound:
        post_result['result'] = False
    except a10_ex.ACOSException as ex:
        post_result['comment'] = ex.msg
    except Exception as gex:
        raise gex
    return post_result
    '''
    pass
