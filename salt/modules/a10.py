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
    client = _get_client()

    post_result = {}
    try:
       sub_result = {}
       for k, v in kwargs.items():
           object_params = v[0].popitem(last=False)
           object_config = object_params[1]
           object_config.append({'a10_name': object_params[0]})
           sub_result[k] = a10_salt.parse_obj(k, op_type, client, *object_config)
       post_result['post_resp'] = sub_result
       post_result['result'] = True
    except a10_ex.ACOSException as ex:
       post_result['result'] = False
       post_result['comment'] = ex.msg
    except Exception as gex:
       raise gex
    return post_result


def aam(**kwargs):
    '''
    Configure Application Access Management settings. AAM optimizes Authentication,
    Authorization, and Accounting (AAA) for client-server traffic.
    '''
    op_type = 'aam'
    return _apply_config(op_type, **kwargs) 


def access_list(**kwargs):
    '''
    Configure a standard Access Control List (ACL) to permit or deny
    source IP addresses.
    '''
    op_type = 'access_list'
    return _apply_config(op_type, **kwargs)


def accounting(**kwargs):
    '''
    Configuration for EXEC <shell> accounting.
    '''
    op_type = 'accounting'
    return _apply_config(op_type, **kwargs)


def active_partition(**kwargs):
    '''
    Switch current partition.
    '''
    op_type = 'active_partition'
    return _apply_config(op_type, **kwargs)


def admin(**kwargs):
    '''
    Configure admin user account details for management access
    to the ACOS device.
    '''
    op_type = 'admin'
    return _apply_config(op_type, **kwargs)


def admin_lockout(**kwargs):
    '''
    Set lockout parameters for admin sessions.
    '''
    op_type = 'admin_lockout'
    return _apply_config(op_type, **kwargs)


def application_type(**kwargs):
    '''
    Configure application to be used in partition (ADC/CGNV6).
    '''
    op_type = 'application_type'
    return _apply_config(op_type, **kwargs)


def audit(**kwargs):
    '''
    Configure command auditing.
    '''
    op_type = 'audit'
    return _apply_config(op_type, **kwargs)


def authentication(**kwargs):
    '''
    Configure authentication of admin access.
    '''
    op_type = 'authentication'
    return _apply_config(op_type, **kwargs)


def authorization(**kwargs):
    '''
    Configure authorization for controlling access to functions.
    '''
    op_type = 'authorization'
    return _apply_config(op_type, **kwargs)


def backup_periodic(**kwargs):
    '''
    Configure periodic backups for the system files and the log files.
    '''
    op_type = 'backup_periodic'
    return _apply_config(op_type, **kwargs) 


def banner(**kwargs):
    '''
    Set the banners to be displayed when an admin logs onto the CLI
    or accesses the Privileged EXEC mode.
    '''
    op_type = 'banner'
    return _apply_config(op_type, **kwargs)


def bgp(**kwargs):
    '''
    Configure the ACOS device for Border Gateway Protocol (BGP) 4-octet BGP
    Autonomous System Number (ASN) capabilities and BGP nexthop tracking.
    '''
    op_type = 'bgp'
    return _apply_config(op_type, **kwargs)


def bios_prog(**kwargs):
    '''
    Programming for BIOS.
    '''
    op_type = 'bios_prog'
    return _apply_config(op_type, **kwargs)


def cgnv6(**kwargs):
    '''
    Carrier Grade NAT and IPv6 Migration commands. 
    '''
    op_type = 'cgnv6'
    return _apply_config(op_type, **kwargs)


def class_list(**kwargs):
    '''
    Configure classification list.
    '''
    op_type = 'class_list'
    return _apply_config(op_type, **kwargs)


def cloud_services(**kwargs):
    '''
    Cloud Services configuration.
    '''
    op_type = 'cloud_services'
    return _apply_config(op_type, **kwargs)


def counter(**kwargs):
    '''
    Counter configuration for http vport, port diameter, vtep.
    '''
    op_type = 'counter'
    return _apply_config(op_type, **kwargs)


def delete(**kwargs):
    '''
    Delete Configuration file.
    '''
    op_type = 'delete'
    return _apply_config(op_type, **kwargs)


def disable_management(**kwargs):
    '''
    Disable management access to the ACOS device.
    '''
    op_type = 'disable_management'
    return _apply_config(op_type, **kwargs)


def dnssec(**kwargs):
    '''
    Configure and manage Domain Name System Security Extensions (DNSSEC).
    '''
    op_type = 'dnssec'
    return _apply_config(op_type, **kwargs)


def enable_core(**kwargs):
    '''
    Enable system coredump switch.
    '''
    op_type = 'enable_core'
    return _apply_config(op_type, **kwargs)


def enable_management(**kwargs):
    '''
    Enable management access to the ACOS device.
    '''
    op_type = 'enable_management'
    return _apply_config(op_type, **kwargs)


def enviroment(**kwargs):
    '''
    Confingure environment status colletion parameters.
    '''
    op_type = 'enviroment'
    return _apply_config(op_type, **kwargs)


def event(**kwargs):
    '''
    Generate an event action for the creation or deletion of an existing
    L3V partition.
    '''
    op_type = 'event'
    return _apply_config(op_type, **kwargs)


def export_periodic(**kwargs):
    '''
    Put files to a remote site periodically.
    '''
    op_type = 'export_periodic'
    return _apply_config(op_type, **kwargs)


def fail_safe(**kwargs):
    '''
    Configure fail-safe automatic recovery.
    '''
    op_type = 'fail_safe'
    return _apply_config(op_type, **kwargs)


def fan_speed(**kwargs):
    '''
    Configure FAN Speed setting.
    '''
    op_type = 'fan_speed'
    return _apply_config(op_type, **kwargs)


def fw(**kwargs):
    '''
    Configure firewall parameters.
    '''
    op_type = 'fw'
    return _apply_config(op_type, **kwargs)


def glid(**kwargs):
    '''
    Configure a global set of IP limiting rules for system-wide IP limiting.
    '''
    op_type = 'glid'
    return _apply_config(op_type, **kwargs)


def glm(**kwargs):
    '''
    Configure Global License Manager (GLM) connection values. 
    '''
    op_type = 'glm'
    return _apply_config(op_type, **kwargs)


def gslb(**kwargs):
    '''
    Configure global server load balance settings. 
    '''
    op_type = 'gslb'
    return _apply_config(op_type, **kwargs)


def hd_monitor(**kwargs):
    '''
    Enable hard disk monitoring on the given ACOS device.
    '''
    op_type = 'hd_monitor'
    return _apply_config(op_type, **kwargs)


def health(**kwargs):
    '''
    Configure health monitor parameters.
    '''
    op_type = 'health'
    return _apply_config(op_type, **kwargs)


def hostname(**kwargs):
    '''
    Configure the system’s network name.
    '''
    op_type = 'hostname'
    return _apply_config(op_type, **kwargs)


def hsm(**kwargs):
    '''
    Configures settings for DNSSEC Hardware Security Module (HSM) support.
    '''
    op_type = 'hsm'
    return _apply_config(op_type, **kwargs)


def import_periodic(**kwargs):
    '''
    Configure period files from a remote site periodically.
    '''
    op_type = 'import_periodic'
    return _apply_config(op_type, **kwargs)


def interface(**kwargs):
    '''
    Configure the interface.
    '''
    op_type = 'interface'
    return _apply_config(op_type, **kwargs)


def ip(**kwargs):
    '''
    Configure ip settings. 
    '''
    op_type = 'ip'
    return _apply_config(op_type, **kwargs)


def ip_list(**kwargs):
    '''
    Configure IP address list with group ID's to be used by other GSLB commands.
    '''
    op_type = 'ip_list'
    return _apply_config(op_type, **kwargs)


def ipv4_in_ipv6(**kwargs):
    '''
    Global IPv4-in-IPv6 configuration subcommands.
    '''
    op_type = 'ipv4_in_ipv6'
    return _apply_config(op_type, **kwargs)


def ipv6(**kwargs):
    '''
    Configure ipv6 settings. 
    '''
    op_type = 'ipv6'
    return _apply_config(op_type, **kwargs)


def ipv6_in_ipv4(**kwargs):
    '''
    Global IPv4-in-IPv6 configuration subcommands.
    '''
    op_type = 'ipv6_in_ipv4'
    return _apply_config(op_type, **kwargs)


def key(**kwargs):
    '''
    Configure a key chain for use by RIP or IS-IS MD5 authentication.
    '''
    op_type = 'key'
    return _apply_config(op_type, **kwargs)


def ldap_server(**kwargs):
    '''
    Configure the LDAP server’s hostname or IP address.
    '''
    op_type = 'ldap_server'
    return _apply_config(op_type, **kwargs)


def license_manager(**kwargs):
    '''
    Configure license manager.
    '''
    op_type = 'license_manager'
    return _apply_config(op_type, **kwargs)


def locale(**kwargs):
    '''
    Specify locale for the CLI startup.
    '''
    op_type = 'locale'
    return _apply_config(op_type, **kwargs)


def logging(**kwargs):
    '''
    Configure logging settings.
    '''
    op_type = 'logging'
    return _apply_config(op_type, **kwargs)


def maximum_paths(**kwargs):
    '''
    Change the maximum number of paths a route can have in the
    Forwarding Information Base (FIB).
    '''
    op_type = 'maximum_paths'
    return _apply_config(op_type, **kwargs)


def merge_mode_add(**kwargs):
    '''
    Controls for block-merge mode behavior.
    '''
    op_type = 'merge_mode_add'
    return _apply_config(op_type, **kwargs)


def mirror_port(**kwargs):
    '''
    Configure a port to act as a mirror port and receive copies
    of another port’s traffic.
    '''
    op_type = 'mirror_port'
    return _apply_config(op_type, **kwargs)


def monitor(**kwargs):
    '''
    Specify event thresholds for utilization of resources.
    '''
    op_type = 'monitor'
    return _apply_config(op_type, **kwargs)


def multi_config(**kwargs):
    '''
    Configure simultaneous admin sessions.
    '''
    op_type = 'multi_config'
    return _apply_config(op_type, **kwargs)


def netflow(**kwargs):
    '''
    Configure netflow/ip flow settings.
    '''
    op_type = 'netflow'
    return _apply_config(op_type, **kwargs)


def network(**kwargs):
    '''
    Configure network commands and related settings.
    '''
    op_type = 'network'
    return _apply_config(op_type, **kwargs)


def ntp(**kwargs):
    '''
    Configure Network Time Protocol (NTP) parameters.
    '''
    op_type = 'ntp'
    return _apply_config(op_type, **kwargs)


def object(**kwargs):
    '''
    Configure network object.
    '''
    op_type = 'object'
    return _apply_config(op_type, **kwargs)


def object_group(**kwargs):
    '''
    Configure Network Object Group.
    '''
    op_type = 'object_group'
    return _apply_config(op_type, **kwargs)


def overlay_mgmt_info(**kwargs):
    '''
    Configure the connection strings used by the SCVMM plugin or other
    virtual machine manager plugins on the ACOS device.
    '''
    op_type = 'overlay_mgmt_info'
    return _apply_config(op_type, **kwargs)


def overlay_tunnel(**kwargs):
    '''
    Configure virtual tunnel as well as system and packet behavior related
    to the tunnel configuration
    '''
    op_type = 'overlay_tunnel'
    return _apply_config(op_type, **kwargs)


def partition(**kwargs):
    '''
    Configure an L3V private partition.
    '''
    op_type = 'partition'
    return _apply_config(op_type, **kwargs)


def partition_group(**kwargs):
    '''
    Modify a named set of partitions.
    '''
    op_type = 'partition_group'
    return _apply_config(op_type, **kwargs)


def pki(**kwargs):
    '''
    Configure SCEP Certificate enrollment objects. 
    '''
    op_type = 'pki'
    return _apply_config(op_type, **kwargs)


def radius_server(**kwargs):
    '''
    Configure RADIUS parameters. Used for authenticating administrative
    access to the ACOS device.
    '''
    op_type = 'radius_server'
    return _apply_config(op_type, **kwargs)


def rate_limit(**kwargs):
    '''
    Configure rate limit.
    '''
    op_type = 'rate_limit'
    return _apply_config(op_type, **kwargs)


def rba(**kwargs):
    '''
    Configure Role-Based Access Control (RBA). This feature supports the creation of
    multiple users, groups, and roles with varying degrees of permissions.
    '''
    op_type = 'rba'
    return _apply_config(op_type, **kwargs)


def remove_upgrade_lock(**kwargs):
    '''
    Specify removing of upgrade lock file: mgmt_is_upgrade.
    '''
    op_type = 'remove_upgrade_lock'
    return _apply_config(op_type, **kwargs)


def report(**kwargs):
    '''
    Define report configurations.
    '''
    op_type = 'report'
    return _apply_config(op_type, **kwargs)


def route_map(**kwargs):
    '''
    Configure a rule in a route map. Use route maps to
    provide input to routing commands.
    '''
    op_type = 'route_map'
    return _apply_config(op_type, **kwargs)


def router(**kwargs):
    '''
    Configure routing process.
    '''
    op_type = 'router'
    return _apply_config(op_type, **kwargs)


def rule_set(**kwargs):
    '''
    Configure security policy.
    '''
    op_type = 'rule_set'
    return _apply_config(op_type, **kwargs)


def running_config(**kwargs):
    '''
    Configure the behaviour of show or hide running config to show aFleX scripts.
    '''
    op_type = 'running_config'
    return _apply_config(op_type, **kwargs)


def scaleout(**kwargs):
    '''
    Configure scaleout settings.
    '''
    op_type = 'scaleout'
    return _apply_config(op_type, **kwargs)


def session_filter(**kwargs):
    '''
    Configure a convenience filter used to display/clear sessions.
    '''
    op_type = 'session_filter'
    return _apply_config(op_type, **kwargs)


def sflow(**kwargs):
    '''
    Configure sflow settings used to collect information about ethernet data
    interfaces and send the data to an external sFlow collector.
    '''
    op_type = 'sflow'
    return _apply_config(op_type, **kwargs)


def slb(**kwargs):
    '''
    Configure server loadbalancing (SLB) settings. 
    '''
    op_type = 'slb'
    return _apply_config(op_type, **kwargs)


def smtp(**kwargs):
    '''
    Configure a Simple Mail Transfer Protocol (SMTP) server to use for
    sending emails from the ACOS device.
    '''
    op_type = 'smtp'
    return _apply_config(op_type, **kwargs)


def snmp_server(**kwargs):
    '''
    Configure Simple Network Management Protocol (SNMP) engine parameters.
    '''
    op_type = 'snmp_server'
    return _apply_config(op_type, **kwargs)


def so_counters(**kwargs):
    '''
    Configure scaleout statistic settings.
    '''
    op_type = 'so_counters'
    return _apply_config(op_type, **kwargs)


def syn_cookie(**kwargs):
    '''
    Configure hardware-based SYN cookies, which protect against TCP SYN flood attacks. 
    '''
    op_type = 'syn_cookie'
    return _apply_config(op_type, **kwargs)


def system(**kwargs):
    '''
    Configure system parameters.
    '''
    op_type = 'system'
    return _apply_config(op_type, **kwargs)


def system_4x10g_mode(**kwargs):
    '''
    Specify 40G port to split into 4x10g ports.
    '''
    op_type = 'system_4x10g_mode'
    return _apply_config(op_type, **kwargs)


def system_buff_debug(**kwargs):
    '''
    Define the system buff debug configuration.
    '''
    op_type = 'system_buff_debug'
    return _apply_config(op_type, **kwargs)


def system_jumbo_global(**kwargs):
    '''
    Configure jumbo frame support. 
    '''
    op_type = 'system_jumbo_global'
    return _apply_config(op_type, **kwargs)


def system_view(**kwargs):
    '''
    Configure system view prameters.
    '''
    op_type = 'system_view'
    return _apply_config(op_type, **kwargs)


def tacacs_server(**kwargs):
    '''
    Configure two TACACS+ servers for authorization and accounting. 
    '''
    op_type = 'tacacs_server'
    return _apply_config(op_type, **kwargs)


def techreport(**kwargs):
    '''
    Configure automated collection of system information.
    '''
    op_type = 'techreport'
    return _apply_config(op_type, **kwargs)


def terminal(**kwargs):
    '''
    Configure terminal startup display parameters.
    '''
    op_type = 'terminal'
    return _apply_config(op_type, **kwargs)


def tftp(**kwargs):
    '''
    Configure TFTP client.
    '''
    op_type = 'tftp'
    return _apply_config(op_type, **kwargs)


def timezone(**kwargs):
    '''
    Configure the Time Zone.
    '''
    op_type = 'timezone'
    return _apply_config(op_type, **kwargs)


def vcs(**kwargs):
    '''
    Configure virtual chassis system.
    '''
    op_type = 'vcs'
    return _apply_config(op_type, **kwargs)


def vcs_vblades(**kwargs):
    '''
    Configure vcs vblade statistic and counter information.
    '''
    op_type = 'vcs_vblades'
    return _apply_config(op_type, **kwargs)


def vpn(**kwargs):
    '''
    Configure vpn settings.
    '''
    op_type = 'vpn'
    return _apply_config(op_type, **kwargs)


def vrrp_a(**kwargs):
    '''
    Configure vrrp-a parameters.
    '''
    op_type = 'vrrp_a'
    return _apply_config(op_type, **kwargs)


def waf(**kwargs):
    '''
    Configure web application firewall (WAF).
    '''
    op_type = 'waf'
    return _apply_config(op_type, **kwargs)


def web_category(**kwargs):
    '''
    Configure Web-Category settings.
    '''
    op_type = 'web_category'
    return _apply_config(op_type, **kwargs)


def web_service(**kwargs):
    '''
    Configure web services.
    '''
    op_type = 'web_service'
    return _apply_config(op_type, **kwargs)


def zone(**kwargs):
    '''
    Configure security zone.
    '''
    op_type = 'zone'
    return _apply_config(op_type, **kwargs)
