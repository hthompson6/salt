# -*- coding: utf-8 -*-
'''
A10 State Module
=================
:codeauthor: Hunter Thompson <hthompson@a10networks.com>
:maturity:   new
:depends:    none

State module designed for CRUD logic of A10 ACOS objects.
'''


def _ret_ops(a10_obj, post_result):
    ret = dict(
        name=a10_obj,
        changes={},
        original_message="",
        result=False,
        comment=""
    )

    ret["changes"].update(**post_result.get('post_resp', {}))
    if post_result.get('post_resp'):
        del post_result['post_resp']
    ret.update(post_result)

    return ret


def create(**kwargs):
    '''
    This function deletes an ACOS object based upon the
    passed kwargs.

    a10_obj
        The type of ACOS object to be created

    CLI Example:
    .. code-block:: bash
        salt '*' a10.delete slb_virtual_server name='vs1'
    '''
    a10_obj = kwargs['name']
    post_result = __salt__['a10.create'](a10_obj, **kwargs)
    return _ret_ops(a10_obj, post_result)


def update(**kwargs):
    '''
    This function deletes an ACOS object based upon the
    passed kwargs.

    a10_obj
        The type of ACOS object to be created

    CLI Example:
    .. code-block:: bash
        salt '*' a10.delete slb_virtual_server name='vs1'
    '''
    a10_obj = kwargs['name']
    post_result = __salt__['a10.update'](a10_obj, **kwargs)
    return _ret_ops(a10_obj, post_result)


def delete(**kwargs):
    '''
    This function deletes an ACOS object based upon the
    passed kwargs.

    a10_obj
        The type of ACOS object to be created

    CLI Example:
    .. code-block:: bash
        salt '*' a10.delete slb_virtual_server name='vs1'
    '''
    a10_obj = kwargs['name']
    post_result = __salt__['a10.delete'](a10_obj, **kwargs)
    return _ret_ops(a10_obj, post_result)
