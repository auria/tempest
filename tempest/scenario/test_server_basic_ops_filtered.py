# Copyright 2014 NEC Corporation
# Copyright 2019 Canonical Ltd
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from oslo_serialization import jsonutils as json

from tempest import config
from tempest.common import tempest_fixtures
from tempest.common import utils
from tempest.lib import decorators
from tempest.scenario import manager

CONF = config.CONF


class TestServerBasicOpsFiltered(manager.ComputeServiceScenarioTest):

    """The test suite for server basic operations on specific compute nodes.

    This smoke test case inherits the server basic operations available in
    a different scenario. See
    tempest.scenario.test_server_basic_ops.TestServerBasicOps.test_server_basic_ops
    The set of operations are:
     * Launch an instance - AZ or host filter is specified in tempest.conf
       -> [scenario]
         boot_hosts_filter={'zones':['nova']}
                          or {'hosts':['host-a', 'host-b']}
                          or EMPTY STRING
         EMPTY STRING means 'ALL compute nodes'.
     * Rest of operations are the same as
    TestServerBasicOps.test_server_basic_ops
    """

    def setUp(self):
        super(TestServerBasicOpsFiltered, self).setUp()
        self.run_ssh = CONF.validation.run_validation
        self.ssh_user = CONF.validation.image_ssh_user

    def _select_hosts(self):
        """Returns a filtered list of hosts from the compute services available

        In tempest.conf, [scenario] section, the variable boot_hosts_filter
        contains the filter to be applied against the full list of enabled
        (and up) compute services of the type 'nova-compute'. Allowed filters
        are:
        {"zones":["nova"]}
        {"hosts":["host-a", "host-b"]})'

        :returns: List of available hosts that match the provided filter
        :rtype: List(str)
        """
        filter = CONF.scenario.boot_hosts_filter
        if filter:
            filter = json.loads(filter)

        compute_nodes = self.get_compute_service_list(binary='nova-compute')
        filtered_list = [
            '{}:{}'.format(node['zone'], node['host'])
            for node in compute_nodes
            if (node['status'] == 'enabled' and node['state'] == 'up' and
                (not filter or
                 node['host'] in filter.get('hosts', []) or
                 node['zone'] in filter.get('zones', [])))
        ]
        return filtered_list

    @decorators.idempotent_id('a3135422-0f21-4776-8fbb-28a701c9c206')
    @decorators.attr(type='smoke')
    @utils.services('compute', 'network')
    def test_server_basic_ops_filtered(self):
        self.useFixture(tempest_fixtures.LockFixture('availability_zone'))
        # Create server with image and flavor from input scenario
        keypair = self.create_keypair()
        security_group = self._create_security_group()
        for az_host in self._select_hosts():
            kwargs = {
                'key_name': keypair['name'],
                'security_groups': [{'name': security_group['name']}],
                'availability_zone': az_host,  # 'zone:host'
            }
            instance = self.create_server(wait_until='ACTIVE', **kwargs)
            srv = self.servers_client.show_server(instance['id'])
            actual = ('{}:{}'.format(
                getattr(srv, 'OS-EXT-AZ:availability_zone'),
                getattr(srv, 'OS-EXT-SRV-ATTR:host'))
            )
            self.assertEqual(az_host, actual)
