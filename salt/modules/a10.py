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


def _apply_config(config_api, **kwargs):
    '''
    Pass configuration onto A10 library for processing and execution
    of CRUD calls.
    '''
    client = _get_client()

    post_result = {}
    try:
       sub_result = {}

       for k, v in kwargs.items():
           # Fetch the name of the object (pos 0) and the
           # values of the object (pos 1)
           object_params = v[0].popitem(last=False)
           object_config = object_params[1]

           # Reassign the identifier as a value of the object for later usage
           object_config.append({'a10_name': object_params[0]})
           resp = a10_salt.parse_config(k, config_api, client, *object_config)
           if resp:
               sub_result[k] = resp 
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
    config_api = 'aam'
    return _apply_config(config_api, **kwargs) 


def access_list(**kwargs):
    '''
    Configure a standard Access Control List (ACL) to permit or deny
    source IP addresses.
    '''
    config_api = 'access_list'
    return _apply_config(config_api, **kwargs)


def accounting(**kwargs):
    '''
    Configuration for EXEC <shell> accounting.
    '''
    config_api = 'accounting'
    return _apply_config(config_api, **kwargs)


def active_partition(**kwargs):
    '''
    Switch current partition.
    '''
    config_api = 'active_partition'
    return _apply_config(config_api, **kwargs)


def admin(**kwargs):
    '''
    Configure admin user account details for management access
    to the ACOS device.
    '''
    config_api = 'admin'
    return _apply_config(config_api, **kwargs)


def admin_lockout(**kwargs):
    '''
    Set lockout parameters for admin sessions.
    '''
    config_api = 'admin_lockout'
    return _apply_config(config_api, **kwargs)


def application_type(**kwargs):
    '''
    Configure application to be used in partition (ADC/CGNV6).
    '''
    config_api = 'application_type'
    return _apply_config(config_api, **kwargs)


def audit(**kwargs):
    '''
    Configure command auditing.
    '''
    config_api = 'audit'
    return _apply_config(config_api, **kwargs)


def authentication(**kwargs):
    '''
    Configure authentication of admin access.
    '''
    config_api = 'authentication'
    return _apply_config(config_api, **kwargs)


def authorization(**kwargs):
    '''
    Configure authorization for controlling access to functions.
    '''
    config_api = 'authorization'
    return _apply_config(config_api, **kwargs)


def backup_periodic(**kwargs):
    '''
    Configure periodic backups for the system files and the log files.
    '''
    config_api = 'backup_periodic'
    return _apply_config(config_api, **kwargs) 


def banner(**kwargs):
    '''
    Set the banners to be displayed when an admin logs onto the CLI
    or accesses the Privileged EXEC mode.
    '''
    config_api = 'banner'
    return _apply_config(config_api, **kwargs)


def bgp(**kwargs):
    '''
    Configure the ACOS device for Border Gateway Protocol (BGP) 4-octet BGP
    Autonomous System Number (ASN) capabilities and BGP nexthop tracking.
    '''
    config_api = 'bgp'
    return _apply_config(config_api, **kwargs)


def bios_prog(**kwargs):
    '''
    Programming for BIOS.
    '''
    config_api = 'bios_prog'
    return _apply_config(config_api, **kwargs)


def cgnv6(**kwargs):
    '''
    Carrier Grade NAT and IPv6 Migration commands. 
    '''
    config_api = 'cgnv6'
    return _apply_config(config_api, **kwargs)


def class_list(**kwargs):
    '''
    Configure classification list.
    '''
    config_api = 'class_list'
    return _apply_config(config_api, **kwargs)


def cloud_services(**kwargs):
    '''
    Cloud Services configuration.
    '''
    config_api = 'cloud_services'
    return _apply_config(config_api, **kwargs)


def counter(**kwargs):
    '''
    Counter configuration for http vport, port diameter, vtep.
    '''
    config_api = 'counter'
    return _apply_config(config_api, **kwargs)


def delete(**kwargs):
    '''
    Delete Configuration file.
    '''
    config_api = 'delete'
    return _apply_config(config_api, **kwargs)


def disable_management(**kwargs):
    '''
    Disable management access to the ACOS device.
    '''
    config_api = 'disable_management'
    return _apply_config(config_api, **kwargs)


def dnssec(**kwargs):
    '''
    Configure and manage Domain Name System Security Extensions (DNSSEC).
    '''
    config_api = 'dnssec'
    return _apply_config(config_api, **kwargs)


def enable_core(**kwargs):
    '''
    Enable system coredump switch.
    '''
    config_api = 'enable_core'
    return _apply_config(config_api, **kwargs)


def enable_management(**kwargs):
    '''
    Enable management access to the ACOS device.
    '''
    config_api = 'enable_management'
    return _apply_config(config_api, **kwargs)


def enviroment(**kwargs):
    '''
    Confingure environment status colletion parameters.
    '''
    config_api = 'enviroment'
    return _apply_config(config_api, **kwargs)


def event(**kwargs):
    '''
    Generate an event action for the creation or deletion of an existing
    L3V partition.
    '''
    config_api = 'event'
    return _apply_config(config_api, **kwargs)


def export_periodic(**kwargs):
    '''
    Put files to a remote site periodically.
    '''
    config_api = 'export_periodic'
    return _apply_config(config_api, **kwargs)


def fail_safe(**kwargs):
    '''
    Configure fail-safe automatic recovery.
    '''
    config_api = 'fail_safe'
    return _apply_config(config_api, **kwargs)


def fan_speed(**kwargs):
    '''
    Configure FAN Speed setting.
    '''
    config_api = 'fan_speed'
    return _apply_config(config_api, **kwargs)


def fw(**kwargs):
    '''
    Configure firewall parameters.
    '''
    config_api = 'fw'
    return _apply_config(config_api, **kwargs)


def glid(**kwargs):
    '''
    Configure a global set of IP limiting rules for system-wide IP limiting.
    '''
    config_api = 'glid'
    return _apply_config(config_api, **kwargs)


def glm(**kwargs):
    '''
    Configure Global License Manager (GLM) connection values. 
    '''
    config_api = 'glm'
    return _apply_config(config_api, **kwargs)


def gslb(**kwargs):
    '''
    Configure global server load balance settings. 
    '''
    config_api = 'gslb'
    return _apply_config(config_api, **kwargs)


def hd_monitor(**kwargs):
    '''
    Enable hard disk monitoring on the given ACOS device.
    '''
    config_api = 'hd_monitor'
    return _apply_config(config_api, **kwargs)


def health(**kwargs):
    '''
    Configure health monitor parameters.
    '''
    config_api = 'health'
    return _apply_config(config_api, **kwargs)


def hostname(**kwargs):
    '''
    Configure the system’s network name.
    '''
    config_api = 'hostname'
    return _apply_config(config_api, **kwargs)


def hsm(**kwargs):
    '''
    Configures settings for DNSSEC Hardware Security Module (HSM) support.
    '''
    config_api = 'hsm'
    return _apply_config(config_api, **kwargs)


def import_periodic(**kwargs):
    '''
    Configure period files from a remote site periodically.
    '''
    config_api = 'import_periodic'
    return _apply_config(config_api, **kwargs)


def interface(**kwargs):
    '''
    Configure the interface.
    '''
    config_api = 'interface'
    return _apply_config(config_api, **kwargs)


def ip(**kwargs):
    '''
    Configure ip settings. 
    '''
    config_api = 'ip'
    return _apply_config(config_api, **kwargs)


def ip_list(**kwargs):
    '''
    Configure IP address list with group ID's to be used by other GSLB commands.
    '''
    config_api = 'ip_list'
    return _apply_config(config_api, **kwargs)


def ipv4_in_ipv6(**kwargs):
    '''
    Global IPv4-in-IPv6 configuration subcommands.
    '''
    config_api = 'ipv4_in_ipv6'
    return _apply_config(config_api, **kwargs)


def ipv6(**kwargs):
    '''
    Configure ipv6 settings. 
    '''
    config_api = 'ipv6'
    return _apply_config(config_api, **kwargs)


def ipv6_in_ipv4(**kwargs):
    '''
    Global IPv4-in-IPv6 configuration subcommands.
    '''
    config_api = 'ipv6_in_ipv4'
    return _apply_config(config_api, **kwargs)


def key(**kwargs):
    '''
    Configure a key chain for use by RIP or IS-IS MD5 authentication.
    '''
    config_api = 'key'
    return _apply_config(config_api, **kwargs)


def ldap_server(**kwargs):
    '''
    Configure the LDAP server’s hostname or IP address.
    '''
    config_api = 'ldap_server'
    return _apply_config(config_api, **kwargs)


def license_manager(**kwargs):
    '''
    Configure license manager.
    '''
    config_api = 'license_manager'
    return _apply_config(config_api, **kwargs)


def locale(**kwargs):
    '''
    Specify locale for the CLI startup.
    '''
    config_api = 'locale'
    return _apply_config(config_api, **kwargs)


def logging(**kwargs):
    '''
    Configure logging settings.
    '''
    config_api = 'logging'
    return _apply_config(config_api, **kwargs)


def maximum_paths(**kwargs):
    '''
    Change the maximum number of paths a route can have in the
    Forwarding Information Base (FIB).
    '''
    config_api = 'maximum_paths'
    return _apply_config(config_api, **kwargs)


def merge_mode_add(**kwargs):
    '''
    Controls for block-merge mode behavior.
    '''
    config_api = 'merge_mode_add'
    return _apply_config(config_api, **kwargs)


def mirror_port(**kwargs):
    '''
    Configure a port to act as a mirror port and receive copies
    of another port’s traffic.
    '''
    config_api = 'mirror_port'
    return _apply_config(config_api, **kwargs)


def monitor(**kwargs):
    '''
    Specify event thresholds for utilization of resources.
    '''
    config_api = 'monitor'
    return _apply_config(config_api, **kwargs)


def multi_config(**kwargs):
    '''
    Configure simultaneous admin sessions.
    '''
    config_api = 'multi_config'
    return _apply_config(config_api, **kwargs)


def netflow(**kwargs):
    '''
    Configure netflow/ip flow settings.
    '''
    config_api = 'netflow'
    return _apply_config(config_api, **kwargs)


def network(**kwargs):
    '''
    Configure network commands and related settings.
    '''
    config_api = 'network'
    return _apply_config(config_api, **kwargs)


def ntp(**kwargs):
    '''
    Configure Network Time Protocol (NTP) parameters.
    '''
    config_api = 'ntp'
    return _apply_config(config_api, **kwargs)


def object(**kwargs):
    '''
    Configure network object.
    '''
    config_api = 'object'
    return _apply_config(config_api, **kwargs)


def object_group(**kwargs):
    '''
    Configure Network Object Group.
    '''
    config_api = 'object_group'
    return _apply_config(config_api, **kwargs)


def overlay_mgmt_info(**kwargs):
    '''
    Configure the connection strings used by the SCVMM plugin or other
    virtual machine manager plugins on the ACOS device.
    '''
    config_api = 'overlay_mgmt_info'
    return _apply_config(config_api, **kwargs)


def overlay_tunnel(**kwargs):
    '''
    Configure virtual tunnel as well as system and packet behavior related
    to the tunnel configuration
    '''
    config_api = 'overlay_tunnel'
    return _apply_config(config_api, **kwargs)


def partition(**kwargs):
    '''
    Configure an L3V private partition.
    '''
    config_api = 'partition'
    return _apply_config(config_api, **kwargs)


def partition_group(**kwargs):
    '''
    Modify a named set of partitions.
    '''
    config_api = 'partition_group'
    return _apply_config(config_api, **kwargs)


def pki(**kwargs):
    '''
    Configure SCEP Certificate enrollment objects. 
    '''
    config_api = 'pki'
    return _apply_config(config_api, **kwargs)


def radius_server(**kwargs):
    '''
    Configure RADIUS parameters. Used for authenticating administrative
    access to the ACOS device.
    '''
    config_api = 'radius_server'
    return _apply_config(config_api, **kwargs)


def rate_limit(**kwargs):
    '''
    Configure rate limit.
    '''
    config_api = 'rate_limit'
    return _apply_config(config_api, **kwargs)


def rba(**kwargs):
    '''
    Configure Role-Based Access Control (RBA). This feature supports the creation of
    multiple users, groups, and roles with varying degrees of permissions.
    '''
    config_api = 'rba'
    return _apply_config(config_api, **kwargs)


def remove_upgrade_lock(**kwargs):
    '''
    Specify removing of upgrade lock file: mgmt_is_upgrade.
    '''
    config_api = 'remove_upgrade_lock'
    return _apply_config(config_api, **kwargs)


def report(**kwargs):
    '''
    Define report configurations.
    '''
    config_api = 'report'
    return _apply_config(config_api, **kwargs)


def route_map(**kwargs):
    '''
    Configure a rule in a route map. Use route maps to
    provide input to routing commands.
    '''
    config_api = 'route_map'
    return _apply_config(config_api, **kwargs)


def router(**kwargs):
    '''
    Configure routing process.
    '''
    config_api = 'router'
    return _apply_config(config_api, **kwargs)


def rule_set(**kwargs):
    '''
    Configure security policy.
    '''
    config_api = 'rule_set'
    return _apply_config(config_api, **kwargs)


def running_config(**kwargs):
    '''
    Configure the behaviour of show or hide running config to show aFleX scripts.
    '''
    config_api = 'running_config'
    return _apply_config(config_api, **kwargs)


def scaleout(**kwargs):
    '''
    Configure scaleout settings.
    '''
    config_api = 'scaleout'
    return _apply_config(config_api, **kwargs)


def session_filter(**kwargs):
    '''
    Configure a convenience filter used to display/clear sessions.
    '''
    config_api = 'session_filter'
    return _apply_config(config_api, **kwargs)


def sflow(**kwargs):
    '''
    Configure sflow settings used to collect information about ethernet data
    interfaces and send the data to an external sFlow collector.
    '''
    config_api = 'sflow'
    return _apply_config(config_api, **kwargs)


def slb(**kwargs):
    '''
    Configure server loadbalancing (SLB) settings. 
    '''
    config_api = 'slb'
    return _apply_config(config_api, **kwargs)


def smtp(**kwargs):
    '''
    Configure a Simple Mail Transfer Protocol (SMTP) server to use for
    sending emails from the ACOS device.
    '''
    config_api = 'smtp'
    return _apply_config(config_api, **kwargs)


def snmp_server(**kwargs):
    '''
    Configure Simple Network Management Protocol (SNMP) engine parameters.
    '''
    config_api = 'snmp_server'
    return _apply_config(config_api, **kwargs)


def so_counters(**kwargs):
    '''
    Configure scaleout statistic settings.
    '''
    config_api = 'so_counters'
    return _apply_config(config_api, **kwargs)


def syn_cookie(**kwargs):
    '''
    Configure hardware-based SYN cookies, which protect against TCP SYN flood attacks. 
    '''
    config_api = 'syn_cookie'
    return _apply_config(config_api, **kwargs)


def system(**kwargs):
    '''
    Configure system parameters.
    '''
    config_api = 'system'
    return _apply_config(config_api, **kwargs)


def system_4x10g_mode(**kwargs):
    '''
    Specify 40G port to split into 4x10g ports.
    '''
    config_api = 'system_4x10g_mode'
    return _apply_config(config_api, **kwargs)


def system_buff_debug(**kwargs):
    '''
    Define the system buff debug configuration.
    '''
    config_api = 'system_buff_debug'
    return _apply_config(config_api, **kwargs)


def system_jumbo_global(**kwargs):
    '''
    Configure jumbo frame support. 
    '''
    config_api = 'system_jumbo_global'
    return _apply_config(config_api, **kwargs)


def system_view(**kwargs):
    '''
    Configure system view prameters.
    '''
    config_api = 'system_view'
    return _apply_config(config_api, **kwargs)


def tacacs_server(**kwargs):
    '''
    Configure two TACACS+ servers for authorization and accounting. 
    '''
    config_api = 'tacacs_server'
    return _apply_config(config_api, **kwargs)


def techreport(**kwargs):
    '''
    Configure automated collection of system information.
    '''
    config_api = 'techreport'
    return _apply_config(config_api, **kwargs)


def terminal(**kwargs):
    '''
    Configure terminal startup display parameters.
    '''
    config_api = 'terminal'
    return _apply_config(config_api, **kwargs)


def tftp(**kwargs):
    '''
    Configure TFTP client.
    '''
    config_api = 'tftp'
    return _apply_config(config_api, **kwargs)


def timezone(**kwargs):
    '''
    Configure the Time Zone.
    '''
    config_api = 'timezone'
    return _apply_config(config_api, **kwargs)


def vcs(**kwargs):
    '''
    Configure virtual chassis system.
    '''
    config_api = 'vcs'
    return _apply_config(config_api, **kwargs)


def vcs_vblades(**kwargs):
    '''
    Configure vcs vblade statistic and counter information.
    '''
    config_api = 'vcs_vblades'
    return _apply_config(config_api, **kwargs)


def vpn(**kwargs):
    '''
    Configure vpn settings.
    '''
    config_api = 'vpn'
    return _apply_config(config_api, **kwargs)


def vrrp_a(**kwargs):
    '''
    Configure vrrp-a parameters.
    '''
    config_api = 'vrrp_a'
    return _apply_config(config_api, **kwargs)


def waf(**kwargs):
    '''
    Configure web application firewall (WAF).
    '''
    config_api = 'waf'
    return _apply_config(config_api, **kwargs)


def web_category(**kwargs):
    '''
    Configure Web-Category settings.
    '''
    config_api = 'web_category'
    return _apply_config(config_api, **kwargs)


def web_service(**kwargs):
    '''
    Configure web services.
    '''
    config_api = 'web_service'
    return _apply_config(config_api, **kwargs)


def zone(**kwargs):
    '''
    Configure security zone.
    '''
    config_api = 'zone'
    return _apply_config(config_api, **kwargs)
