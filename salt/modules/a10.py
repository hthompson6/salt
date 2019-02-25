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
    from a10_saltstack import client as a10_client
    from a10_saltstack.kwbl import KW_OUT, translate_blacklist as translateBlacklist
    from a10_saltstack import errors as a10_ex
    from a10_saltstack.helpers import helper as a10_helper
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


def _build_envelope(title, data):
    return {
        title: data
    }


def _to_axapi(key):
    return translateBlacklist(key, KW_OUT).replace("_", "-")


def _build_dict_from_param(param):
    rv = {}

    for k, v in param.items():
        hk = _to_axapi(k)
        if isinstance(v, dict):
            v_dict = _build_dict_from_param(v)
            rv[hk] = v_dict
        if isinstance(v, list):
            nv = [_build_dict_from_param(x) for x in v]
            rv[hk] = nv
        else:
            rv[hk] = v

    return rv


def _build_json(title, avail_props, **kwargs):
    rv = {}

    for x in avail_props:
        v = kwargs.get(x)
        if v:
            rx = _to_axapi(x)

            if isinstance(v, dict):
                nv = _build_dict_from_param(v)
                rv[rx] = nv
            if isinstance(v, list):
                nv = [_build_dict_from_param(x) for x in v]
                rv[rx] = nv
            else:
                rv[rx] = kwargs[x]

    return _build_envelope(title, rv)


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

    url = a10_helper.get_url(a10_obj, 'create', **kwargs)
    avail_props = a10_helper.get_props(a10_obj, **kwargs)
    obj_type = a10_helper.get_obj_type(a10_obj)
    post_result = {}
    try:
        payload = _build_json(obj_type, avail_props, **kwargs)
        client = _get_client(**kwargs)
        post_result['post_resp'] = client.post(url, payload)
        post_result['result'] = True
    except a10_ex.Exists:
        post_result['result'] = False
    except a10_ex.ACOSException as ex:
        post_result['comment'] = ex.msg
    except Exception as gex:
        raise gex
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
    '''

    url = a10_helper.get_url(a10_obj, 'update', **kwargs)
    avail_props = a10_helper.get_props(a10_obj, **kwargs)
    obj_type = a10_helper.get_obj_type(a10_obj)
    post_result = {}
    try:
        payload = _build_json(obj_type, avail_props, **kwargs)
        client = _get_client(**kwargs)
        post_result = client.put(url, payload)
    except a10_ex.NotFound:
        post_result['result'] = False
    except a10_ex.ACOSException as ex:
        post_result['comment'] = ex.msg
    except Exception as gex:
        raise gex
    return post_result


def delete(a10_obj, **kwargs):
    '''
    This function deletes an ACOS object based upon the
    passed kwargs.

    a10_obj
        The type of ACOS object to be deleted

    CLI Example:
    .. code-block:: bash
        salt '*' a10.delete slb_virtual_server name='vs1'
    '''

    url = a10_helper.get_url(a10_obj, 'delete', **kwargs)
    post_result = {}
    try:
        client = _get_client(**kwargs)
        client.delete(url)
    except a10_ex.NotFound:
        post_result['result'] = False
    except a10_ex.ACOSException as ex:
        post_result['comment'] = ex.msg
    except Exception as gex:
        raise gex
    return post_result
