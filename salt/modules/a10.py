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
    from a10_saltstack.client import errors as a10_ex
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


def _apply_config(op_type, **kwargs):
    a10_obj = kwargs['a10_obj']
    del kwargs['a10_obj']
    client = _get_client()

    post_result = {}
    try:
       post_result['post_resp'] = a10_salt.parse_obj(a10_obj, op_type, client, **kwargs)
       post_result['result'] = True
    except a10_ex.ACOSException as ex:
       post_result['result'] = False
       post_result['comment'] = ex.msg
    except Exception as gex:
       raise gex
    return post_result


def aam(**kwargs):
    op_type = 'aam'
    return _apply_config(op_type, **kwargs) 


def access_list(**kwargs):
    op_type = 'access_list'
    return _apply_config(op_type, **kwargs)


def accounting(**kwargs):
    op_type = 'accounting'
    return _apply_config(op_type, **kwargs)


def active_partition(**kwargs):
    op_type = 'active_partition'
    return _apply_config(op_type, **kwargs)


def admin(**kwargs):
    op_type = 'admin'
    return _apply_config(op_type, **kwargs)


def admin_lockout(**kwargs):
    op_type = 'admin_lockout'
    return _apply_config(op_type, **kwargs)


def application_type(**kwargs):
    op_type = 'application_type'
    return _apply_config(op_type, **kwargs)


def audit(**kwargs):
    op_type = 'audit'
    return _apply_config(op_type, **kwargs)


def authentication(**kwargs):
    op_type = 'authentication'
    return _apply_config(op_type, **kwargs)


def authorization(**kwargs):
    op_type = 'authorization'
    return _apply_config(op_type, **kwargs)


def backup_periodic(**kwargs):
    op_type = 'backup_periodic'
    return _apply_config(op_type, **kwargs) 


def banner(**kwargs):
    op_type = 'banner'
    return _apply_config(op_type, **kwargs)


def bgp(**kwargs):
    op_type = 'bgp'
    return _apply_config(op_type, **kwargs)


def bios_prog(**kwargs):
    op_type = 'bios_prog'
    return _apply_config(op_type, **kwargs)


def cgnv6(**kwargs):
    op_type = 'cgnv6'
    return _apply_config(op_type, **kwargs)


def class_list(**kwargs):
    op_type = 'class_list'
    return _apply_config(op_type, **kwargs)


def cloud_services(**kwargs):
    op_type = 'cloud_services'
    return _apply_config(op_type, **kwargs)


def counter(**kwargs):
    op_type = 'counter'
    return _apply_config(op_type, **kwargs)


def delete(**kwargs):
    op_type = 'delete'
    return _apply_config(op_type, **kwargs)


def disable_management(**kwargs):
    op_type = 'disable_management'
    return _apply_config(op_type, **kwargs)


def dnssec(**kwargs):
    op_type = 'dnssec'
    return _apply_config(op_type, **kwargs)


def enable_core(**kwargs):
    op_type = 'enable_core'
    return _apply_config(op_type, **kwargs)


def enable_management(**kwargs):
    op_type = 'enable_management'
    return _apply_config(op_type, **kwargs)


def enviroment(**kwargs):
    op_type = 'enviroment'
    return _apply_config(op_type, **kwargs)


def event(**kwargs):
    op_type = 'event'
    return _apply_config(op_type, **kwargs)


def export_periodic(**kwargs):
    op_type = 'export_periodic'
    return _apply_config(op_type, **kwargs)


def fail_safe(**kwargs):
    op_type = 'fail_safe'
    return _apply_config(op_type, **kwargs)


def fan_speed(**kwargs):
    op_type = 'fan_speed'
    return _apply_config(op_type, **kwargs)


def fw(**kwargs):
    op_type = 'fw'
    return _apply_config(op_type, **kwargs)


def glid(**kwargs):
    op_type = 'glid'
    return _apply_config(op_type, **kwargs)


def glm(**kwargs):
    op_type = 'glm'
    return _apply_config(op_type, **kwargs)


def gslb(**kwargs):
    op_type = 'gslb'
    return _apply_config(op_type, **kwargs)


def hd_monitor(**kwargs):
    op_type = 'hd_monitor'
    return _apply_config(op_type, **kwargs)


def health(**kwargs):
    op_type = 'health'
    return _apply_config(op_type, **kwargs)


def hostname(**kwargs):
    op_type = 'hostname'
    return _apply_config(op_type, **kwargs)


def hsm(**kwargs):
    op_type = 'hsm'
    return _apply_config(op_type, **kwargs)


def import_periodic(**kwargs):
    op_type = 'import_periodic'
    return _apply_config(op_type, **kwargs)


def interface(**kwargs):
    op_type = 'interface'
    return _apply_config(op_type, **kwargs)


def ip(**kwargs):
    op_type = 'ip'
    return _apply_config(op_type, **kwargs)


def ip_list(**kwargs):
    op_type = 'ip_list'
    return _apply_config(op_type, **kwargs)


def ipv4_in_ipv6(**kwargs):
    op_type = 'ipv4_in_ipv6'
    return _apply_config(op_type, **kwargs)


def ipv6(**kwargs):
    op_type = 'ipv6'
    return _apply_config(op_type, **kwargs)


def ipv6_in_ipv4(**kwargs):
    op_type = 'ipv6_in_ipv4'
    return _apply_config(op_type, **kwargs)


def key(**kwargs):
    op_type = 'key'
    return _apply_config(op_type, **kwargs)


def ldap_server(**kwargs):
    op_type = 'ldap_server'
    return _apply_config(op_type, **kwargs)


def license_manager(**kwargs):
    op_type = 'license_manager'
    return _apply_config(op_type, **kwargs)


def locale(**kwargs):
    op_type = 'locale'
    return _apply_config(op_type, **kwargs)


def logging(**kwargs):
    op_type = 'logging'
    return _apply_config(op_type, **kwargs)


def maximum_paths(**kwargs):
    op_type = 'maximum_paths'
    return _apply_config(op_type, **kwargs)


def merge_mode_add(**kwargs):
    op_type = 'merge_mode_add'
    return _apply_config(op_type, **kwargs)


def mirror_port(**kwargs):
    op_type = 'mirror_port'
    return _apply_config(op_type, **kwargs)


def monitor(**kwargs):
    op_type = 'monitor'
    return _apply_config(op_type, **kwargs)


def multi_config(**kwargs):
    op_type = 'multi_config'
    return _apply_config(op_type, **kwargs)


def netflow(**kwargs):
    op_type = 'netflow'
    return _apply_config(op_type, **kwargs)


def network(**kwargs):
    op_type = 'network'
    return _apply_config(op_type, **kwargs)


def ntp(**kwargs):
    op_type = 'ntp'
    return _apply_config(op_type, **kwargs)


def object(**kwargs):
    op_type = 'object'
    return _apply_config(op_type, **kwargs)


def object_group(**kwargs):
    op_type = 'object_group'
    return _apply_config(op_type, **kwargs)


def overlay_mgmt_info(**kwargs):
    op_type = 'overlay_mgmt_info'
    return _apply_config(op_type, **kwargs)


def overlay_tunnel(**kwargs):
    op_type = 'overlay_tunnel'
    return _apply_config(op_type, **kwargs)


def partition(**kwargs):
    op_type = 'partition'
    return _apply_config(op_type, **kwargs)


def partition_group(**kwargs):
    op_type = 'partition_group'
    return _apply_config(op_type, **kwargs)


def pki(**kwargs):
    op_type = 'pki'
    return _apply_config(op_type, **kwargs)


def radius_server(**kwargs):
    op_type = 'radius_server'
    return _apply_config(op_type, **kwargs)


def rate_limit(**kwargs):
    op_type = 'rate_limit'
    return _apply_config(op_type, **kwargs)


def rba(**kwargs):
    op_type = 'rba'
    return _apply_config(op_type, **kwargs)


def remove_upgrade_lock(**kwargs):
    op_type = 'remove_upgrade_lock'
    return _apply_config(op_type, **kwargs)


def report(**kwargs):
    op_type = 'report'
    return _apply_config(op_type, **kwargs)


def route_map(**kwargs):
    op_type = 'route_map'
    return _apply_config(op_type, **kwargs)


def router(**kwargs):
    op_type = 'router'
    return _apply_config(op_type, **kwargs)


def rule_set(**kwargs):
    op_type = 'rule_set'
    return _apply_config(op_type, **kwargs)


def running_config(**kwargs):
    op_type = 'running_config'
    return _apply_config(op_type, **kwargs)


def scaleout(**kwargs):
    op_type = 'scaleout'
    return _apply_config(op_type, **kwargs)


def session_filter(**kwargs):
    op_type = 'session_filter'
    return _apply_config(op_type, **kwargs)


def sflow(**kwargs):
    op_type = 'sflow'
    return _apply_config(op_type, **kwargs)


def slb(**kwargs):
    op_type = 'slb'
    return _apply_config(op_type, **kwargs)


def smtp(**kwargs):
    op_type = 'smtp'
    return _apply_config(op_type, **kwargs)


def snmp_server(**kwargs):
    op_type = 'snmp_server'
    return _apply_config(op_type, **kwargs)


def so_counters(**kwargs):
    op_type = 'so_counters'
    return _apply_config(op_type, **kwargs)


def syn_cookie(**kwargs):
    op_type = 'syn_cookie'
    return _apply_config(op_type, **kwargs)


def system(**kwargs):
    op_type = 'system'
    return _apply_config(op_type, **kwargs)


def system_4x10g_mode(**kwargs):
    op_type = 'system_4x10g_mode'
    return _apply_config(op_type, **kwargs)


def system_buff_debug(**kwargs):
    op_type = 'system_buff_debug'
    return _apply_config(op_type, **kwargs)


def system_jumbo_global(**kwargs):
    op_type = 'system_jumbo_global'
    return _apply_config(op_type, **kwargs)


def system_view(**kwargs):
    op_type = 'system_view'
    return _apply_config(op_type, **kwargs)


def tacacs_server(**kwargs):
    op_type = 'tacacs_server'
    return _apply_config(op_type, **kwargs)


def techreport(**kwargs):
    op_type = 'techreport'
    return _apply_config(op_type, **kwargs)


def techsupport(**kwargs):
    op_type = 'techsupport'
    return _apply_config(op_type, **kwargs)


def terminal(**kwargs):
    op_type = 'terminal'
    return _apply_config(op_type, **kwargs)


def tftp(**kwargs):
    op_type = 'tftp'
    return _apply_config(op_type, **kwargs)


def timezone(**kwargs):
    op_type = 'timezone'
    return _apply_config(op_type, **kwargs)


def vcs(**kwargs):
    op_type = 'vcs'
    return _apply_config(op_type, **kwargs)


def vcs_vblades(**kwargs):
    op_type = 'vcs_vblades'
    return _apply_config(op_type, **kwargs)


def vpn(**kwargs):
    op_type = 'vpn'
    return _apply_config(op_type, **kwargs)


def vrrp_a(**kwargs):
    op_type = 'vrrp_a'
    return _apply_config(op_type, **kwargs)


def waf(**kwargs):
    op_type = 'waf'
    return _apply_config(op_type, **kwargs)


def web_category(**kwargs):
    op_type = 'web_category'
    return _apply_config(op_type, **kwargs)


def web_service(**kwargs):
    op_type = 'web_service'
    return _apply_config(op_type, **kwargs)


def zone(**kwargs):
    op_type = 'zone'
    return _apply_config(op_type, **kwargs)
