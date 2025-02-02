#! /usr/bin/env python

# Copyright 2016 Hewlett Packard Enterprise Development Company, L.P.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

# This script is intended to be run as part of a periodic proposal bot
# job in OpenStack infrastructure.
#
# In order to function correctly, the environment in which the
# script runs must have
#   * network access to the review.opendev.org Gerrit API
#     working directory
#   * network access to https://opendev.org/openstack

import json
import re
import sys

try:
    # For Python 3.0 and later
    from urllib.error import HTTPError
    import urllib.request as urllib
except ImportError:
    # Fall back to Python 2's urllib2
    import urllib2 as urllib
    from urllib2 import HTTPError

# List of projects having tempest plugin stale or unmaintained for a long time
# (6 months or more)
# TODO(masayukig): Some of these can be removed from BLACKLIST in the future
# when the patches are merged.
BLACKLIST = [
    'openstack/barbican-tempest-plugin',
    # https://review.opendev.org/#/c/634631/
    'x/gce-api',  # It looks gce-api doesn't support python3 yet.
    'x/intel-nfv-ci-tests',  # https://review.opendev.org/#/c/634640/
    'openstack/networking-generic-switch',
    # https://review.opendev.org/#/c/634846/
    'openstack/networking-l2gw-tempest-plugin',
    # https://review.opendev.org/#/c/635093/
    'openstack/networking-midonet',  # https://review.opendev.org/#/c/635096/
    'x/networking-plumgrid',  # https://review.opendev.org/#/c/635096/
    'x/networking-spp',  # https://review.opendev.org/#/c/635098/
    'openstack/neutron-dynamic-routing',
    # https://review.opendev.org/#/c/637718/
    'openstack/neutron-vpnaas',  # https://review.opendev.org/#/c/637719/
    'x/valet',  # https://review.opendev.org/#/c/638339/
]

url = 'https://review.opendev.org/projects/'

# This is what a project looks like
'''
  "openstack-attic/akanda": {
    "id": "openstack-attic%2Fakanda",
    "state": "READ_ONLY"
  },
'''


# Rather than returning a 404 for a nonexistent file, cgit delivers a
# 0-byte response to a GET request.  It also does not provide a
# Content-Length in a HEAD response, so the way we tell if a file exists
# is to check the length of the entire GET response body.
def has_tempest_plugin(proj):
    try:
        r = urllib.urlopen(
            "https://opendev.org/%s/raw/branch/"
            "master/setup.cfg" % proj)
    except HTTPError as err:
        if err.code == 404:
            return False
        # We should not ignore non 404 errors.
        raise err
    p = re.compile(r'^tempest\.test_plugins', re.M)
    if p.findall(r.read().decode('utf-8')):
        return True
    else:
        False


if len(sys.argv) > 1 and sys.argv[1] == 'blacklist':
    for black_plugin in BLACKLIST:
        print(black_plugin)
    # We just need BLACKLIST when we use this `blacklist` option.
    # So, this exits here.
    sys.exit()

r = urllib.urlopen(url)
# Gerrit prepends 4 garbage octets to the JSON, in order to counter
# cross-site scripting attacks.  Therefore we must discard it so the
# json library won't choke.
content = r.read().decode('utf-8')[4:]
projects = sorted(json.loads(content))

# Retrieve projects having no deployment tool repo (such as deb,
# puppet, ansible, etc.), infra repos, ui or spec namespace as those
# namespaces do not contains tempest plugins.
projects_list = [i for i in projects if not (
    i.startswith('openstack-dev/') or
    i.startswith('openstack-infra/') or
    i.startswith('openstack/ansible-') or
    i.startswith('openstack/charm-') or
    i.startswith('openstack/cookbook-openstack-') or
    i.startswith('openstack/devstack-') or
    i.startswith('openstack/fuel-') or
    i.startswith('openstack/deb-') or
    i.startswith('openstack/puppet-') or
    i.startswith('openstack/openstack-ansible-') or
    i.startswith('x/deb-') or
    i.startswith('x/fuel-') or
    i.startswith('x/python-') or
    i.startswith('zuul/') or
    i.endswith('-ui') or
    i.endswith('-specs'))]

found_plugins = list(filter(has_tempest_plugin, projects_list))

# We have tempest plugins not only in 'openstack/' namespace but also the
# other name spaces such as 'airship/', 'x/', etc.
# So, we print all of them here.
for project in found_plugins:
    print(project)
