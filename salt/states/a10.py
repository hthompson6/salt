# -*- coding: utf-8 -*-
'''
A10 State Module
=================
:codeauthor: Hunter Thompson <hthompson@a10networks.com>
:maturity:   new
:depends:    none

State module designed for CRUD logic of A10 ACOS objects.
'''

import logging
LOG = logging.getLogger(__file__)

def _ret_ops(name, post_result):
    ret = dict(
        name=name,
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


<<<<<<< HEAD
def aam(name, **kwargs):
    post_result = __salt__['a10.aam'](**kwargs)
    return _ret_ops(name, post_result)


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
=======
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
>>>>>>> 6fb872478f3a14e6ff950d3f3f11f65aea7d83c4
