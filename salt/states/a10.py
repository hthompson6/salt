# -*- coding: utf-8 -*-
'''
A10 State Module
=================
:codeauthor: Hunter Thompson <hthompson@a10networks.com>
:maturity:   new
:depends:    a10_saltstack 

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


def aam(name, **kwargs):
    '''
    Configure Application Access Management settings. AAM optimizes Authentication,
    Authorization, and Accounting (AAA) for client-server traffic.
    '''
    post_result = __salt__['a10.aam'](**kwargs)
    return _ret_ops(name, post_result)


def access_list(name, **kwargs):
    '''
    Configure a standard Access Control List (ACL) to permit or deny
    source IP addresses.
    '''
    post_result = __salt__['a10.access_list'](**kwargs)
    return _ret_ops(name, post_result)


def accounting(name, **kwargs):
    '''
    Configuration for EXEC <shell> accounting.
    '''
    post_result = __salt__['a10.accounting'](**kwargs)
    return _ret_ops(name, post_result)


def active_partition(name, **kwargs):
    '''
    Switch current partition.
    '''
    post_result = __salt__['a10.active_partition'](**kwargs)
    return _ret_ops(name, post_result)


def admin(name, **kwargs):
    '''
    Configure admin user account details for management access
    to the ACOS device.
    '''
    post_result = __salt__['a10.admin'](**kwargs)
    return _ret_ops(name, post_result)


def admin_lockout(name, **kwargs):
    '''
    Set lockout parameters for admin sessions.
    '''
    post_result = __salt__['a10.admin_lockout'](**kwargs)
    return _ret_ops(name, post_result)


def application_type(name, **kwargs):
    '''
    Configure application to be used in partition (ADC/CGNV6).
    '''
    post_result = __salt__['a10.application_type'](**kwargs)
    return _ret_ops(name, post_result)


def audit(name, **kwargs):
    '''
    Configure command auditing.
    '''
    post_result = __salt__['a10.audit'](**kwargs)
    return _ret_ops(name, post_result)


def authentication(name, **kwargs):
    '''
    Configure authentication of admin access.
    '''
    post_result = __salt__['a10.authentication'](**kwargs)
    return _ret_ops(name, post_result)


def authorization(name, **kwargs):
    '''
    Configure authorization for controlling access to functions.
    '''
    post_result = __salt__['a10.authorization'](**kwargs)
    return _ret_ops(name, post_result)


def backup_periodic(name, **kwargs):
    '''
    Configure periodic backups for the system files and the log files.
    '''
    post_result = __salt__['a10.backup_periodic'](**kwargs)
    return _ret_ops(name, post_result)


def banner(name, **kwargs):
    '''
    Set the banners to be displayed when an admin logs onto the CLI
    or accesses the Privileged EXEC mode.
    '''
    post_result = __salt__['a10.banner'](**kwargs)
    return _ret_ops(name, post_result)


def bgp(name, **kwargs):
    '''
    Configure the ACOS device for Border Gateway Protocol (BGP) 4-octet BGP
    Autonomous System Number (ASN) capabilities and BGP nexthop tracking.
    '''
    post_result = __salt__['a10.bgp'](**kwargs)
    return _ret_ops(name, post_result)


def bios_prog(name, **kwargs):
    '''
    Programming for BIOS.
    '''
    post_result = __salt__['a10.bios_prog'](**kwargs)
    return _ret_ops(name, post_result)


def cgnv6(name, **kwargs):
    '''
    Carrier Grade NAT and IPv6 Migration commands. 
    '''
    post_result = __salt__['a10.cgnv6'](**kwargs)
    return _ret_ops(name, post_result)


def class_list(name, **kwargs):
    '''
    Configure classification list.
    '''
    post_result = __salt__['a10.class_list'](**kwargs)
    return _ret_ops(name, post_result)


def cloud_services(name, **kwargs):
    '''
    Cloud Services configuration.
    '''
    post_result = __salt__['a10.cloud_services'](**kwargs)
    return _ret_ops(name, post_result)


def counter(name, **kwargs):
    '''
    Counter configuration for http vport, port diameter, vtep.
    '''
    post_result = __salt__['a10.counter'](**kwargs)
    return _ret_ops(name, post_result)


def delete(name, **kwargs):
    '''
    Delete Configuration file.
    '''
    post_result = __salt__['a10.delete'](**kwargs)
    return _ret_ops(name, post_result)


def disable_management(name, **kwargs):
    '''
    Disable management access to the ACOS device.
    '''
    post_result = __salt__['a10.disable_managment'](**kwargs)
    return _ret_ops(name, post_result)


def dnssec(name, **kwargs):
    '''
    Configure and manage Domain Name System Security Extensions (DNSSEC).
    '''
    post_result = __salt__['a10.dnssec'](**kwargs)
    return _ret_ops(name, post_result)


def enable_core(name, **kwargs):
    '''
    Enable system coredump switch.
    '''
    post_result = __salt__['a10.enable_core'](**kwargs)
    return _ret_ops(name, post_result)


def enable_management(name, **kwargs):
    '''
    Enable management access to the ACOS device.
    '''
    post_result = __salt__['a10.enable_management'](**kwargs)
    return _ret_ops(name, post_result)


def enviroment(name, **kwargs):
    '''
    Confingure environment status colletion parameters.
    '''
    post_result = __salt__['a10.enviroment'](**kwargs)
    return _ret_ops(name, post_result)


def event(name, **kwargs):
    '''
    Generate an event action for the creation or deletion of an existing
    L3V partition.
    '''
    post_result = __salt__['a10.event'](**kwargs)
    return _ret_ops(name, post_result)


def export_periodic(name, **kwargs):
    '''
    Put files to a remote site periodically.
    '''
    post_result = __salt__['a10.export_periodic'](**kwargs)
    return _ret_ops(name, post_result)


def fail_safe(name, **kwargs):
    '''
    Configure fail-safe automatic recovery.
    '''
    post_result = __salt__['a10.fail_safe'](**kwargs)
    return _ret_ops(name, post_result)


def fan_speed(name, **kwargs):
    '''
    Configure FAN Speed setting.
    '''
    post_result = __salt__['a10.fan_speed'](**kwargs)
    return _ret_ops(name, post_result)


def fw(name, **kwargs):
    '''
    Configure firewall parameters.
    '''
    post_result = __salt__['a10.fw'](**kwargs)
    return _ret_ops(name, post_result)


def glid(name, **kwargs):
    '''
    Configure a global set of IP limiting rules for system-wide IP limiting.
    '''
    post_result = __salt__['a10.glid'](**kwargs)
    return _ret_ops(name, post_result)


def glm(name, **kwargs):
    '''
    Configure Global License Manager (GLM) connection values. 
    '''
    post_result = __salt__['a10.glm'](**kwargs)
    return _ret_ops(name, post_result)


def gslb(name, **kwargs):
    '''
    Configure global server load balance settings. 
    '''
    post_result = __salt__['a10.gslb'](**kwargs)
    return _ret_ops(name, post_result)


def hd_monitor(name, **kwargs):
    '''
    Enable hard disk monitoring on the given ACOS device.
    '''
    post_result = __salt__['a10.hd_monitor'](**kwargs)
    return _ret_ops(name, post_result)


def health(name, **kwargs):
    '''
    Configure health monitor parameters.
    '''
    post_result = __salt__['a10.health'](**kwargs)
    return _ret_ops(name, post_result)


def hostname(name, **kwargs):
    '''
    Configure the system’s network name.
    '''
    post_result = __salt__['a10.hostname'](**kwargs)
    return _ret_ops(name, post_result)


def hsm(name, **kwargs):
    '''
    Configures settings for DNSSEC Hardware Security Module (HSM) support.
    '''
    post_result = __salt__['a10.hsm'](**kwargs)
    return _ret_ops(name, post_result)


def import_periodic(name, **kwargs):
    '''
    Configure period files from a remote site periodically.
    '''
    post_result = __salt__['a10.import_periodic'](**kwargs)
    return _ret_ops(name, post_result)


def interface(name, **kwargs):
    '''
    Configure the interface.
    '''
    post_result = __salt__['a10.interface'](**kwargs)
    return _ret_ops(name, post_result)


def ip(name, **kwargs):
    '''
    Configure ip settings. 
    '''
    post_result = __salt__['a10.ip'](**kwargs)
    return _ret_ops(name, post_result)


def ip_list(name, **kwargs):
    '''
    Configure IP address list with group ID's to be used by other GSLB commands.
    '''
    post_result = __salt__['a10.ip_list'](**kwargs)
    return _ret_ops(name, post_result)


def ipv4_in_ipv6(name, **kwargs):
    '''
    Global IPv4-in-IPv6 configuration subcommands.
    '''
    post_result = __salt__['a10.ipv4_in_ipv6'](**kwargs)
    return _ret_ops(name, post_result)


def ipv6(name, **kwargs):
    '''
    Configure ipv6 settings. 
    '''
    post_result = __salt__['a10.ipv6'](**kwargs)
    return _ret_ops(name, post_result)


def ipv6_in_ipv4(name, **kwargs):
    '''
    Global IPv4-in-IPv6 configuration subcommands.
    '''
    post_result = __salt__['a10.ipv6_in_ipv4'](**kwargs)
    return _ret_ops(name, post_result)


def key(name, **kwargs):
    '''
    Configure a key chain for use by RIP or IS-IS MD5 authentication.
    '''
    post_result = __salt__['a10.key'](**kwargs)
    return _ret_ops(name, post_result)


def ldap_server(name, **kwargs):
    '''
    Configure the LDAP server’s hostname or IP address.
    '''
    post_result = __salt__['a10.ldap_server'](**kwargs)
    return _ret_ops(name, post_result)


def license_manager(name, **kwargs):
    '''
    Configure license manager.
    '''
    post_result = __salt__['a10.license_manager'](**kwargs)
    return _ret_ops(name, post_result)


def locale(name, **kwargs):
    '''
    Specify locale for the CLI startup.
    '''
    post_result = __salt__['a10.locale'](**kwargs)
    return _ret_ops(name, post_result)


def logging(name, **kwargs):
    '''
    Configure logging settings.
    '''
    post_result = __salt__['a10.logging'](**kwargs)
    return _ret_ops(name, post_result)


def maximum_paths(name, **kwargs):
    '''
    Change the maximum number of paths a route can have in the
    Forwarding Information Base (FIB).
    '''
    post_result = __salt__['a10.maximum_paths'](**kwargs)
    return _ret_ops(name, post_result)


def merge_mode_add(name, **kwargs):
    '''
    Controls for block-merge mode behavior.
    '''
    post_result = __salt__['a10.merge_mode_add'](**kwargs)
    return _ret_ops(name, post_result)


def mirror_port(name, **kwargs):
    '''
    Configure a port to act as a mirror port and receive copies
    of another port’s traffic.
    '''
    post_result = __salt__['a10.mirror_port'](**kwargs)
    return _ret_ops(name, post_result)


def monitor(name, **kwargs):
    '''
    Specify event thresholds for utilization of resources.
    '''
    post_result = __salt__['a10.monitor'](**kwargs)
    return _ret_ops(name, post_result)


def multi_config(name, **kwargs):
    '''
    Configure simultaneous admin sessions.
    '''
    post_result = __salt__['a10.multi_config'](**kwargs)
    return _ret_ops(name, post_result)


def netflow(name, **kwargs):
    '''
    Configure netflow/ip flow settings.
    '''
    post_result = __salt__['a10.netflow'](**kwargs)
    return _ret_ops(name, post_result)


def network(name, **kwargs):
    '''
    Configure network commands and related settings.
    '''
    post_result = __salt__['a10.network'](**kwargs)
    return _ret_ops(name, post_result)


def ntp(name, **kwargs):
    '''
    Configure Network Time Protocol (NTP) parameters.
    '''
    post_result = __salt__['a10.ntp'](**kwargs)
    return _ret_ops(name, post_result)


def object(name, **kwargs):
    '''
    Configure network object.
    '''
    post_result = __salt__['a10.object'](**kwargs)
    return _ret_ops(name, post_result)


def object_group(name, **kwargs):
    '''
    Configure Network Object Group.
    '''
    post_result = __salt__['a10.object_group'](**kwargs)
    return _ret_ops(name, post_result)


def overlay_mgmt_info(name, **kwargs):
    '''
    Configure the connection strings used by the SCVMM plugin or other
    virtual machine manager plugins on the ACOS device.
    '''
    post_result = __salt__['a10.overlay_mgmt_info'](**kwargs)
    return _ret_ops(name, post_result)


def overlay_tunnel(name, **kwargs):
    '''
    Configure virtual tunnel as well as system and packet behavior related
    to the tunnel configuration
    '''
    post_result = __salt__['a10.overlay_tunnel'](**kwargs)
    return _ret_ops(name, post_result)


def partition(name, **kwargs):
    '''
    Configure an L3V private partition.
    '''
    post_result = __salt__['a10.partition'](**kwargs)
    return _ret_ops(name, post_result)


def partition_group(name, **kwargs):
    '''
    Modify a named set of partitions.
    '''
    post_result = __salt__['a10.partition_group'](**kwargs)
    return _ret_ops(name, post_result)


def pki(name, **kwargs):
    '''
    Configure SCEP Certificate enrollment objects. 
    '''
    post_result = __salt__['a10.pki'](**kwargs)
    return _ret_ops(name, post_result)


def radius_server(name, **kwargs):
    '''
    Configure RADIUS parameters. Used for authenticating administrative
    access to the ACOS device.
    '''
    post_result = __salt__['a10.radius_server'](**kwargs)
    return _ret_ops(name, post_result)


def rate_limit(name, **kwargs):
    '''
    Configure rate limit.
    '''
    post_result = __salt__['a10.rate_limit'](**kwargs)
    return _ret_ops(name, post_result)


def rba(name, **kwargs):
    '''
    Configure Role-Based Access Control (RBA). This feature supports the creation of
    multiple users, groups, and roles with varying degrees of permissions.
    '''
    post_result = __salt__['a10.rba'](**kwargs)
    return _ret_ops(name, post_result)


def remove_upgrade_lock(name, **kwargs):
    '''
    Specify removing of upgrade lock file: mgmt_is_upgrade.
    '''
    post_result = __salt__['a10.remove_upgrade_lock'](**kwargs)
    return _ret_ops(name, post_result)


def report(name, **kwargs):
    '''
    Define report configurations.
    '''
    post_result = __salt__['a10.report'](**kwargs)
    return _ret_ops(name, post_result)


def route_map(name, **kwargs):
    '''
    Configure a rule in a route map. Use route maps to
    provide input to routing commands.
    '''
    post_result = __salt__['a10.route_map'](**kwargs)
    return _ret_ops(name, post_result)


def router(name, **kwargs):
    '''
    Configure routing process.
    '''
    post_result = __salt__['a10.router'](**kwargs)
    return _ret_ops(name, post_result)


def rule_set(name, **kwargs):
    '''
    Configure security policy.
    '''
    post_result = __salt__['a10.rule_set'](**kwargs)
    return _ret_ops(name, post_result)


def running_config(name, **kwargs):
    '''
    Configure the behaviour of show or hide running config to show aFleX scripts.
    '''
    post_result = __salt__['a10.running_config'](**kwargs)
    return _ret_ops(name, post_result)


def scaleout(name, **kwargs):
    '''
    Configure scaleout settings.
    '''
    post_result = __salt__['a10.scaleout'](**kwargs)
    return _ret_ops(name, post_result)


def session_filter(name, **kwargs):
    '''
    Configure a convenience filter used to display/clear sessions.
    '''
    post_result = __salt__['a10.session_filter'](**kwargs)
    return _ret_ops(name, post_result)


def sflow(name, **kwargs):
    '''
    Configure sflow settings used to collect information about ethernet data
    interfaces and send the data to an external sFlow collector.
    '''
    post_result = __salt__['a10.sflow'](**kwargs)
    return _ret_ops(name, post_result)


def slb(name, **kwargs):
    '''
    Configure server loadbalancing (SLB) settings. 
    '''
    post_result = __salt__['a10.slb'](**kwargs)
    return _ret_ops(name, post_result)


def smtp(name, **kwargs):
    '''
    Configure a Simple Mail Transfer Protocol (SMTP) server to use for
    sending emails from the ACOS device.
    '''
    post_result = __salt__['a10.smtp'](**kwargs)
    return _ret_ops(name, post_result)


def snmp_server(name, **kwargs):
    '''
    Configure Simple Network Management Protocol (SNMP) engine parameters.
    '''
    post_result = __salt__['a10.snmp_sever'](**kwargs)
    return _ret_ops(name, post_result)


def so_counters(name, **kwargs):
    '''
    Configure scaleout statistic settings.
    '''
    post_result = __salt__['a10.so_counters'](**kwargs)
    return _ret_ops(name, post_result)


def syn_cookie(name, **kwargs):
    '''
    Configure hardware-based SYN cookies, which protect against TCP SYN flood attacks. 
    '''
    post_result = __salt__['a10.syn_cookie'](**kwargs)
    return _ret_ops(name, post_result)


def system(name, **kwargs):
    '''
    Configure system parameters.
    '''
    post_result = __salt__['a10.system'](**kwargs)
    return _ret_ops(name, post_result)


def system_4x10g_mode(name, **kwargs):
    '''
    Specify 40G port to split into 4x10g ports.
    '''
    post_result = __salt__['a10.system_4x10g_mode'](**kwargs)
    return _ret_ops(name, post_result)


def system_buff_debug(name, **kwargs):
    '''
    Define the system buff debug configuration.
    '''
    post_result = __salt__['a10.system_buff_debug'](**kwargs)
    return _ret_ops(name, post_result)


def system_jumbo_global(name, **kwargs):
    '''
    Configure jumbo frame support. 
    '''
    post_result = __salt__['a10.system_jumbo_global'](**kwargs)
    return _ret_ops(name, post_result)


def system_view(name, **kwargs):
    '''
    Configure system view prameters.
    '''
    post_result = __salt__['a10.system_view'](**kwargs)
    return _ret_ops(name, post_result)


def tacacs_server(name, **kwargs):
    '''
    Configure two TACACS+ servers for authorization and accounting. 
    '''
    post_result = __salt__['a10.tacacs_server'](**kwargs)
    return _ret_ops(name, post_result)


def techreport(name, **kwargs):
    '''
    Configure automated collection of system information.
    '''
    post_result = __salt__['a10.techreport'](**kwargs)
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
<<<<<<< HEAD
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
>>>>>>> 6fb8724... Added logic to utilize name param for module lookup
=======
>>>>>>> 9f3c2c3... Removed merge conflict
