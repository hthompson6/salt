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


<<<<<<< HEAD
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
=======
def aam(**kwargs):
    op_type = 'aam'
    a10_obj = kwargs['a10_obj']
    del kwargs['a10_obj']
>>>>>>> 631a9e5... Added first endpoint
    client = _get_client()

    post_result = {}
    try:
<<<<<<< HEAD
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
=======
       post_result['post_resp'] = a10_salt.parse_obj(a10_obj, op_type, client, **kwargs)
       post_result['result'] = True 
>>>>>>> 631a9e5... Added first endpoint
    except a10_ex.ACOSException as ex:
       post_result['result'] = False
        post_result['comment'] = ex.msg
    except Exception as gex:
        raise gex
    return post_result

def access_list(name, **kwargs):
    post_result = __salt__['a10.access_list'](**kwargs)
    return _ret_ops(name, post_result)


def accounting(name, **kwargs):
    post_result = __salt__['a10.accounting'](**kwargs)
    return _ret_ops(name, post_result)


def active_partition(name, **kwargs):
    post_result = __salt__['a10.active_partition'](**kwargs)
    return _ret_ops(name, post_result)


def admin(name, **kwargs):
    post_result = __salt__['a10.admin'](**kwargs)
    return _ret_ops(name, post_result)


def admin_lockout(name, **kwargs):
    post_result = __salt__['a10.admin_lockout'](**kwargs)
    return _ret_ops(name, post_result)


def application_type(name, **kwargs):
    post_result = __salt__['a10.application_type'](**kwargs)
    return _ret_ops(name, post_result)


def audit(name, **kwargs):
    post_result = __salt__['a10.audit'](**kwargs)
    return _ret_ops(name, post_result)


def authentication(name, **kwargs):
    post_result = __salt__['a10.authentication'](**kwargs)
    return _ret_ops(name, post_result)


def authorization(name, **kwargs):
    post_result = __salt__['a10.authorization'](**kwargs)
    return _ret_ops(name, post_result)


def backup_periodic(name, **kwargs):
    post_result = __salt__['a10.backup_periodic'](**kwargs)
    return _ret_ops(name, post_result)


def banner(name, **kwargs):
    post_result = __salt__['a10.banner'](**kwargs)
    return _ret_ops(name, post_result)


def bgp(name, **kwargs):
    post_result = __salt__['a10.bgp'](**kwargs)
    return _ret_ops(name, post_result)


def bios_prog(name, **kwargs):
    post_result = __salt__['a10.bios_prog'](**kwargs)
    return _ret_ops(name, post_result)


def cgnv6(name, **kwargs):
    post_result = __salt__['a10.cgnv6'](**kwargs)
    return _ret_ops(name, post_result)


def class_lsit(name, **kwargs):
    post_result = __salt__['a10.class_list'](**kwargs)
    return _ret_ops(name, post_result)


def cloud_services(name, **kwargs):
    post_result = __salt__['a10.cloud_services'](**kwargs)
    return _ret_ops(name, post_result)


def coutner(name, **kwargs):
    post_result = __salt__['a10.counter'](**kwargs)
    return _ret_ops(name, post_result)


def delete(name, **kwargs):
    post_result = __salt__['a10.delete'](**kwargs)
    return _ret_ops(name, post_result)


def disable_management(name, **kwargs):
    post_result = __salt__['a10.disable_managment'](**kwargs)
    return _ret_ops(name, post_result)


def dnssec(name, **kwargs):
    post_result = __salt__['a10.dnssec'](**kwargs)
    return _ret_ops(name, post_result)


def enable_core(name, **kwargs):
    post_result = __salt__['a10.enable_core'](**kwargs)
    return _ret_ops(name, post_result)


def enable_management(name, **kwargs):
    post_result = __salt__['a10.enable_management'](**kwargs)
    return _ret_ops(name, post_result)


def enviroment(name, **kwargs):
    post_result = __salt__['a10.enviroment'](**kwargs)
    return _ret_ops(name, post_result)


def event(name, **kwargs):
    post_result = __salt__['a10.event'](**kwargs)
    return _ret_ops(name, post_result)


def export_periodic(name, **kwargs):
    post_result = __salt__['a10.export_periodic'](**kwargs)
    return _ret_ops(name, post_result)


def fail_safe(name, **kwargs):
    post_result = __salt__['a10.fail_safe'](**kwargs)
    return _ret_ops(name, post_result)


def fan_speed(name, **kwargs):
    post_result = __salt__['a10.fan_speed'](**kwargs)
    return _ret_ops(name, post_result)


def fw(name, **kwargs):
    post_result = __salt__['a10.fw'](**kwargs)
    return _ret_ops(name, post_result)


def glid(name, **kwargs):
    post_result = __salt__['a10.glid'](**kwargs)
    return _ret_ops(name, post_result)


def glm(name, **kwargs):
    post_result = __salt__['a10.glm'](**kwargs)
    return _ret_ops(name, post_result)


def gslb(name, **kwargs):
    post_result = __salt__['a10.gslb'](**kwargs)
    return _ret_ops(name, post_result)


def hd_monitor(name, **kwargs):
    post_result = __salt__['a10.hd_monitor'](**kwargs)
    return _ret_ops(name, post_result)


def health(name, **kwargs):
    post_result = __salt__['a10.health'](**kwargs)
    return _ret_ops(name, post_result)


def hostname(name, **kwargs):
    post_result = __salt__['a10.hostname'](**kwargs)
    return _ret_ops(name, post_result)


def hsm(name, **kwargs):
    post_result = __salt__['a10.hsm'](**kwargs)
    return _ret_ops(name, post_result)


def import_periodic(name, **kwargs):
    post_result = __salt__['a10.import_periodic'](**kwargs)
    return _ret_ops(name, post_result)


def interface(name, **kwargs):
    post_result = __salt__['a10.interface'](**kwargs)
    return _ret_ops(name, post_result)


def ip(name, **kwargs):
    post_result = __salt__['a10.ip'](**kwargs)
    return _ret_ops(name, post_result)


def ip_list(name, **kwargs):
    post_result = __salt__['a10.ip_list'](**kwargs)
    return _ret_ops(name, post_result)


def ipv4_in_ipv6(name, **kwargs):
    post_result = __salt__['a10.ipv4_in_ipv6'](**kwargs)
    return _ret_ops(name, post_result)


def ipv6(name, **kwargs):
    post_result = __salt__['a10.ipv6'](**kwargs)
    return _ret_ops(name, post_result)


def ipv6_in_ipv4(name, **kwargs):
    post_result = __salt__['a10.ipv6_in_ipv4'](**kwargs)
    return _ret_ops(name, post_result)


def key(name, **kwargs):
    post_result = __salt__['a10.key'](**kwargs)
    return _ret_ops(name, post_result)


def ldap_server(name, **kwargs):
    post_result = __salt__['a10.ldap_server'](**kwargs)
    return _ret_ops(name, post_result)


def license_manager(name, **kwargs):
    post_result = __salt__['a10.license_manager'](**kwargs)
    return _ret_ops(name, post_result)


def locale(name, **kwargs):
    post_result = __salt__['a10.locale'](**kwargs)
    return _ret_ops(name, post_result)


def logging(name, **kwargs):
    post_result = __salt__['a10.logging'](**kwargs)
    return _ret_ops(name, post_result)


def maximum_paths(name, **kwargs):
    post_result = __salt__['a10.maximum_paths'](**kwargs)
    return _ret_ops(name, post_result)


def merge_mode_add(name, **kwargs):
    post_result = __salt__['a10.merge_mode_add'](**kwargs)
    return _ret_ops(name, post_result)


def mirror_port(name, **kwargs):
    post_result = __salt__['a10.mirror_port'](**kwargs)
    return _ret_ops(name, post_result)


def monitor(name, **kwargs):
    post_result = __salt__['a10.monitor'](**kwargs)
    return _ret_ops(name, post_result)


def multi_config(name, **kwargs):
    post_result = __salt__['a10.multi_config'](**kwargs)
    return _ret_ops(name, post_result)


def netflow(name, **kwargs):
    post_result = __salt__['a10.netflow'](**kwargs)
    return _ret_ops(name, post_result)


def network(name, **kwargs):
    post_result = __salt__['a10.network'](**kwargs)
    return _ret_ops(name, post_result)


def ntp(name, **kwargs):
    post_result = __salt__['a10.ntp'](**kwargs)
    return _ret_ops(name, post_result)


def object(name, **kwargs):
    post_result = __salt__['a10.object'](**kwargs)
    return _ret_ops(name, post_result)


def object_group(name, **kwargs):
    post_result = __salt__['a10.object_group'](**kwargs)
    return _ret_ops(name, post_result)


def overlay_mgmt_info(name, **kwargs):
    post_result = __salt__['a10.overlay_mgmt_info'](**kwargs)
    return _ret_ops(name, post_result)


def overlay_tunnel(name, **kwargs):
    post_result = __salt__['a10.overlay_tunnel'](**kwargs)
    return _ret_ops(name, post_result)


def partition(name, **kwargs):
    post_result = __salt__['a10.partition'](**kwargs)
    return _ret_ops(name, post_result)


def partition_group(name, **kwargs):
    post_result = __salt__['a10.partition_group'](**kwargs)
    return _ret_ops(name, post_result)


def pki(name, **kwargs):
    post_result = __salt__['a10.pki'](**kwargs)
    return _ret_ops(name, post_result)


def radius_server(name, **kwargs):
    post_result = __salt__['a10.radius_server'](**kwargs)
    return _ret_ops(name, post_result)


def rate_limit(name, **kwargs):
    post_result = __salt__['a10.rate_limit'](**kwargs)
    return _ret_ops(name, post_result)


def rba(name, **kwargs):
    post_result = __salt__['a10.rba'](**kwargs)
    return _ret_ops(name, post_result)


def remove_upgrade_lock(name, **kwargs):
    post_result = __salt__['a10.remove_upgrade_lock'](**kwargs)
    return _ret_ops(name, post_result)


def report(name, **kwargs):
    post_result = __salt__['a10.report'](**kwargs)
    return _ret_ops(name, post_result)


def route_map(name, **kwargs):
    post_result = __salt__['a10.route_map'](**kwargs)
    return _ret_ops(name, post_result)


def router(name, **kwargs):
    post_result = __salt__['a10.router'](**kwargs)
    return _ret_ops(name, post_result)


def rule_set(name, **kwargs):
    post_result = __salt__['a10.rule_set'](**kwargs)
    return _ret_ops(name, post_result)


def running_config(name, **kwargs):
    post_result = __salt__['a10.running_config'](**kwargs)
    return _ret_ops(name, post_result)


def scaleout(name, **kwargs):
    post_result = __salt__['a10.scaleout'](**kwargs)
    return _ret_ops(name, post_result)


def session_filter(name, **kwargs):
    post_result = __salt__['a10.session_filter'](**kwargs)
    return _ret_ops(name, post_result)


def sflow(name, **kwargs):
    post_result = __salt__['a10.sflow'](**kwargs)
    return _ret_ops(name, post_result)


def slb(name, **kwargs):
    post_result = __salt__['a10.slb'](**kwargs)
    return _ret_ops(name, post_result)


def smtp(name, **kwargs):
    post_result = __salt__['a10.smtp'](**kwargs)
    return _ret_ops(name, post_result)


def snmp_server(name, **kwargs):
    post_result = __salt__['a10.snmp_sever'](**kwargs)
    return _ret_ops(name, post_result)


def so_counters(name, **kwargs):
    post_result = __salt__['a10.so_counters'](**kwargs)
    return _ret_ops(name, post_result)


def syn_cookie(name, **kwargs):
    post_result = __salt__['a10.syn_cookie'](**kwargs)
    return _ret_ops(name, post_result)


def system(name, **kwargs):
    post_result = __salt__['a10.system'](**kwargs)
    return _ret_ops(name, post_result)


def system_4x10g_mode(name, **kwargs):
    post_result = __salt__['a10.system_4x10g_mode'](**kwargs)
    return _ret_ops(name, post_result)


def system_buff_debug(name, **kwargs):
    post_result = __salt__['a10.system_buff_debug'](**kwargs)
    return _ret_ops(name, post_result)


def system_jumbo_global(name, **kwargs):
    post_result = __salt__['a10.system_jumbo_global'](**kwargs)
    return _ret_ops(name, post_result)


def system_view(name, **kwargs):
    post_result = __salt__['a10.system_view'](**kwargs)
    return _ret_ops(name, post_result)


def tacacs_server(name, **kwargs):
    post_result = __salt__['a10.tacacs_server'](**kwargs)
    return _ret_ops(name, post_result)


def techreport(name, **kwargs):
    post_result = __salt__['a10.techreport'](**kwargs)
    return _ret_ops(name, post_result)


def techsupport(name, **kwargs):
    post_result = __salt__['a10.techsupport'](**kwargs)
    return _ret_ops(name, post_result)


def terminal(name, **kwargs):
    post_result = __salt__['a10.terminal'](**kwargs)
    return _ret_ops(name, post_result)


def tftp(name, **kwargs):
    post_result = __salt__['a10.tftp'](**kwargs)
    return _ret_ops(name, post_result)


def timezone(name, **kwargs):
    post_result = __salt__['a10.timezone'](**kwargs)
    return _ret_ops(name, post_result)


def vcs(name, **kwargs):
    post_result = __salt__['a10.vcs'](**kwargs)
    return _ret_ops(name, post_result)


def vcs_vblades(name, **kwargs):
    post_result = __salt__['a10.vcs_vblades'](**kwargs)
    return _ret_ops(name, post_result)


def vpn(name, **kwargs):
    post_result = __salt__['a10.vpn'](**kwargs)
    return _ret_ops(name, post_result)


def vrrp_a(name, **kwargs):
    post_result = __salt__['a10.vrrp_a'](**kwargs)
    return _ret_ops(name, post_result)


def waf(name, **kwargs):
    post_result = __salt__['a10.waf'](**kwargs)
    return _ret_ops(name, post_result)


def web_category(name, **kwargs):
    post_result = __salt__['a10.web_category'](**kwargs)
    return _ret_ops(name, post_result)


def web_service(name, **kwargs):
    post_result = __salt__['a10.web_service'](**kwargs)
    return _ret_ops(name, post_result)


def zone(name, **kwargs):
    post_result = __salt__['a10.zone'](**kwargs)
    return _ret_ops(name, post_result)
