# -*- coding: utf-8 -*-
'''
:codeauthor: Hunter Thompson <hthompson@a10networks.com>
'''

# Import Python Modules
from __future__ import absolute_import

# Import A10 modules
try:
    from a10_saltstack import errors as a10_ex
    HAS_A10 = True
except ImportError:
    HAS_A10 = False

import salt.modules.a10 as a10

# Import Salt Test Modules
from tests.support.mixins import LoaderModuleMockMixin
from tests.support.unit import TestCase, skipIf
from tests.support.mock import MagicMock, Mock, patch


@skipIf(not HAS_A10, "The a10-saltstack library is required")
class Test_A10_Module(TestCase, LoaderModuleMockMixin):

    def setup_loader_modules(self):
        return {
            a10: {
                '__proxy__': {
                    'a10.get_session': self.fake_session,
                },
            }
        }

    def fake_session(self):
        return MagicMock()

    def fake_obj(self):
        a10_obj = {'virtual-server':
                    {'port-list': [
                        {'port-number': 443, 'protocol': 'https'},
                        {'port-number': 80, 'protocol': 'http'},
                        {'port-number': 22, 'protocol': 'tcp'}],
                        'name': 'vs1',
                        'ip-address': '192.168.42.1',
                        'netmask': '255.255.255.0'}
                   }
        return a10_obj

    def test_create(self):
        mock_client = Mock()
        with patch('a10_saltstack.helpers.helper.get_url', return_value='/axapi/v3/slb/virtual-server/'), \
                patch('a10_saltstack.helpers.helper.get_obj_type', return_value='virtual-server'), \
                patch('a10_saltstack.helpers.helper.get_props', return_value=[]), \
                patch('salt.modules.a10._get_client', return_value=mock_client), \
                patch('salt.modules.a10._build_json', return_value=self.fake_obj()), \
                patch('a10_saltstack.errors'):

            post_ret = a10.create('slb_virtual_server', **self.fake_obj())
            mock_client.post.assert_called_with('/axapi/v3/slb/virtual-server/', self.fake_obj())

    def test_create_exists(self):
        mock_client = Mock()
        with patch('a10_saltstack.helpers.helper.get_url', return_value='/axapi/v3/slb/virtual-server/'), \
                patch('a10_saltstack.helpers.helper.get_obj_type', return_value='virtual-server'), \
                patch('a10_saltstack.helpers.helper.get_props', return_value=[]), \
                patch('salt.modules.a10._get_client', return_value=mock_client), \
                patch('salt.modules.a10._build_json', return_value=self.fake_obj()), \
                patch('a10_saltstack.errors'):

            mock_client.post = Mock(side_effect=a10_ex.Exists())
            post_ret = a10.create('slb_virtual_server', **self.fake_obj())
            self.assertEqual({'result': False}, post_ret)

    def test_create_acos_exception(self):
        mock_client = Mock()
        with patch('a10_saltstack.helpers.helper.get_url', return_value='/axapi/v3/slb/virtual-server/'), \
                patch('a10_saltstack.helpers.helper.get_obj_type', return_value='virtual-server'), \
                patch('a10_saltstack.helpers.helper.get_props', return_value=[]), \
                patch('salt.modules.a10._get_client', return_value=mock_client), \
                patch('salt.modules.a10._build_json', return_value=self.fake_obj()), \
                patch('a10_saltstack.errors'):

            mock_client.post = Mock(side_effect=a10_ex.ACOSException(''))
            post_ret = a10.create('slb_virtual_server', **self.fake_obj())
            self.assertEqual({'comment': ''}, post_ret)

    def test_create_exception(self):
        mock_client = Mock()
        with patch('a10_saltstack.helpers.helper.get_url', return_value='/axapi/v3/slb/virtual-server/'), \
                patch('a10_saltstack.helpers.helper.get_obj_type', return_value='virtual-server'), \
                patch('a10_saltstack.helpers.helper.get_props', return_value=[]), \
                patch('salt.modules.a10._get_client', return_value=mock_client), \
                patch('salt.modules.a10._build_json', return_value=self.fake_obj()), \
                patch('a10_saltstack.errors'):

            mock_client.post = Mock(side_effect=Exception())
            with self.assertRaises(Exception):
                a10.create('slb_virtual_server', **self.fake_obj())

    def test_update(self):
        mock_client = Mock()
        with patch('a10_saltstack.helpers.helper.get_url', return_value='/axapi/v3/slb/virtual-server/vs1'), \
                patch('a10_saltstack.helpers.helper.get_obj_type', return_value='virtual-server'), \
                patch('a10_saltstack.helpers.helper.get_props', return_value=[]), \
                patch('salt.modules.a10._get_client', return_value=mock_client), \
                patch('salt.modules.a10._build_json', return_value=self.fake_obj()), \
                patch('a10_saltstack.errors'):

            post_ret = a10.update('slb_virtual_server', **self.fake_obj())
            mock_client.put.assert_called_with('/axapi/v3/slb/virtual-server/vs1', self.fake_obj())

    def test_update_notfound(self):
        mock_client = Mock()
        with patch('a10_saltstack.helpers.helper.get_url', return_value='/axapi/v3/slb/virtual-server/vs1'), \
                patch('a10_saltstack.helpers.helper.get_obj_type', return_value='virtual-server'), \
                patch('a10_saltstack.helpers.helper.get_props', return_value=[]), \
                patch('salt.modules.a10._get_client', return_value=mock_client), \
                patch('salt.modules.a10._build_json', return_value=self.fake_obj()), \
                patch('a10_saltstack.errors'):

            mock_client.put = Mock(side_effect=a10_ex.NotFound())
            post_ret = a10.update('slb_virtual_server', **self.fake_obj())
            self.assertEqual({'result': False}, post_ret)

    def test_update_acos_exception(self):
        mock_client = Mock()
        with patch('a10_saltstack.helpers.helper.get_url', return_value='/axapi/v3/slb/virtual-server/vs1'), \
                patch('a10_saltstack.helpers.helper.get_obj_type', return_value='virtual-server'), \
                patch('a10_saltstack.helpers.helper.get_props', return_value=[]), \
                patch('salt.modules.a10._get_client', return_value=mock_client), \
                patch('salt.modules.a10._build_json', return_value=self.fake_obj()), \
                patch('a10_saltstack.errors'):

            mock_client.put = Mock(side_effect=a10_ex.ACOSException(''))
            post_ret = a10.update('slb_virtual_server', **self.fake_obj())
            self.assertEqual({'comment': ''}, post_ret)

    def test_update_exception(self):
        mock_client = Mock()
        with patch('a10_saltstack.helpers.helper.get_url', return_value='/axapi/v3/slb/virtual-server/'), \
                patch('a10_saltstack.helpers.helper.get_obj_type', return_value='virtual-server'), \
                patch('a10_saltstack.helpers.helper.get_props', return_value=[]), \
                patch('salt.modules.a10._get_client', return_value=mock_client), \
                patch('salt.modules.a10._build_json', return_value=self.fake_obj()), \
                patch('a10_saltstack.errors'):

            mock_client.put = Mock(side_effect=Exception())
            with self.assertRaises(Exception):
                a10.update('slb_virtual_server', **self.fake_obj())

    def test_delete(self):
        mock_client = Mock()
        with patch('a10_saltstack.helpers.helper.get_url', return_value='/axapi/v3/slb/virtual-server/vs1'), \
                patch('a10_saltstack.helpers.helper.get_obj_type', return_value='virtual-server'), \
                patch('a10_saltstack.helpers.helper.get_props', return_value=[]), \
                patch('salt.modules.a10._get_client', return_value=mock_client), \
                patch('salt.modules.a10._build_json', return_value=self.fake_obj()), \
                patch('a10_saltstack.errors'):

            post_ret = a10.delete('slb_virtual_server')
            mock_client.delete.assert_called_with('/axapi/v3/slb/virtual-server/vs1')

    def test_delete_acos_exception(self):
        mock_client = Mock()
        with patch('a10_saltstack.helpers.helper.get_url', return_value='/axapi/v3/slb/virtual-server/vs1'), \
                patch('a10_saltstack.helpers.helper.get_obj_type', return_value='virtual-server'), \
                patch('a10_saltstack.helpers.helper.get_props', return_value=[]), \
                patch('salt.modules.a10._get_client', return_value=mock_client), \
                patch('a10_saltstack.errors'):

            mock_client.delete = Mock(side_effect=a10_ex.ACOSException(''))
            post_ret = a10.delete('slb_virtual_server')
            self.assertEqual({'comment': ''}, post_ret)

    def test_delete_exception(self):
        mock_client = Mock()
        with patch('a10_saltstack.helpers.helper.get_url', return_value='/axapi/v3/slb/virtual-server/'), \
                patch('a10_saltstack.helpers.helper.get_obj_type', return_value='virtual-server'), \
                patch('a10_saltstack.helpers.helper.get_props', return_value=[]), \
                patch('salt.modules.a10._get_client', return_value=mock_client), \
                patch('salt.modules.a10._build_json', return_value=self.fake_obj()), \
                patch('a10_saltstack.errors'):

            mock_client.delete = Mock(side_effect=Exception())
            with self.assertRaises(Exception):
                a10.delete('slb_virtual_server')

    def test_build_param_list(self):
        with patch('salt.modules.a10._to_axapi', return_value='test_prop'):
            ret = a10._build_dict_from_param({'test_prop': [{'test_prop': 1337}]})
            self.assertEqual({'test_prop': [{'test_prop': 1337}]}, ret)

    def test_build_param_dict(self):
        with patch('salt.modules.a10._to_axapi', return_value='test_prop'):
            ret = a10._build_dict_from_param({'test_prop': {'test_prop': 1337}})
            self.assertEqual({'test_prop': {'test_prop': 1337}}, ret)

    def test_build_json(self):
        with patch('salt.modules.a10._build_envelope') as build_env:
            a10._build_json('test_title', ['test_prop'])
            build_env.assert_called_with('test_title', {})

    def test_build_json_list(self):
        with patch('salt.modules.a10._to_axapi', return_value='test_prop'), \
            patch('salt.modules.a10._build_dict_from_param') as build_param:
            a10._build_json('test_title', ['test_prop'], test_prop=[{'test': 1337}])
            build_param.assert_called_with({'test': 1337})

    def test_build_json_dict(self):
        with patch('salt.modules.a10._to_axapi', return_value='test_prop'), \
            patch('salt.modules.a10._build_dict_from_param') as build_param:
            a10._build_json('test_title', ['test_prop'], test_prop={'test': 1337})
            build_param.assert_called_with({'test': 1337})
