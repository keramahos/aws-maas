# -*- coding: utf-8 -*-
# Copyright: (c) 2022, XLAB Steampunk <steampunk@xlab.si>
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
name: inventory
author:
  - Domen Dobnikar (@domen_dobnikar)
short_description: Inventory source for Canonical MAAS.
description:
  - Builds an inventory containing VMs on Canonical MAAS.
  - Does not support caching.
version_added: 1.0.0
seealso: []
options:
  plugin:
    description:
      - The name of the MAAS Inventory Plugin.
      - This should always be C(maas.maas.inventory).
    required: true
    type: str
    choices: [ maas.maas.inventory ]
  status:
    description:
      - If missing, all VMs are included into inventory.
      - If set, then only VMs with selected status are included into inventory.
    type: str
    choices: [ ready, broken, new, allocated, deployed, commissioning, testing, failed commissioning, failed deployment ]
"""
EXAMPLES = r"""
# A trivial example that creates a list of all VMs.
# VMs are grouped based on their domains.
# In the example, two domains are being used: "maas" and "test".

plugin: maas.maas.inventory

# `ansible-inventory -i examples/maas_inventory.yaml --graph` output:
# @all:
#  |--@maas:
#  |  |--first.maas
#  |--@test:
#  |  |--second.test
#  |--@ungrouped:

# `ansible-inventory -i maas_inventory.yaml --list` output:
# {
#    "_meta": {
#        "hostvars": {}
#    },
#    "all": {
#        "children": [
#            "maas",
#            "test",
#            "ungrouped"
#        ]
#    },
#    "maas": {
#        "hosts": [
#            "first.maas"
#        ]
#    },
#    "test": {
#        "hosts": [
#            "second.test"
#        ]
#    }
# }

# Example with all available parameters and how to set them.
# A group "test" is created based on the domain name "test".
# Only VMs with status "ready", are added to the group.

status: ready

# `ansible-inventory -i examples/maas_inventory.yaml --graph` output:
# @all:
#  |--@test:
#  |  |--second.test
#  |--@ungrouped:

# `ansible-inventory -i maas_inventory.yaml --list` output:
# {
#    "_meta": {
#        "hostvars": {}
#    },
#    "all": {
#        "children": [
#            "test",
#            "ungrouped"
#        ]
#    },
#    "test": {
#        "hosts": [
#            "second.test"
#        ]
#    }
# }
"""

import logging
import os

from ansible.plugins.inventory import (
    BaseInventoryPlugin,
    Cacheable,
    Constructable,
)
import yaml

from ..module_utils import errors
from ..module_utils.client import Client

logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger(__name__)


class LdapBaseException(Exception):
    pass


class InventoryModule(BaseInventoryPlugin, Constructable, Cacheable):
    NAME = "inventory"  # used internally by Ansible, it should match the file name but not required

    @classmethod
    def read_config_data(cls, path, env):
        """
        Reads and validates the inventory source file and environ,
        storing the provided configuration as options.
        """
        with open(path, "r") as inventory_src:
            cfg = yaml.safe_load(inventory_src)
        return cfg

    def verify_file(self, path):
        """
        return true/false if this is possibly a valid file for this plugin to consume
        """
        # only check file is yaml, and contains magic plugin key with correct value.
        with open(path, "r") as inventory_src:
            config_contents = yaml.safe_load(inventory_src)
        plugin = config_contents.get("plugin")
        if not plugin:
            return False
        if plugin not in [self.NAME, "maas.maas.inventory"]:
            return False
        return True

    def parse(self, inventory, loader, path, cache=False):
        super(InventoryModule, self).parse(inventory, loader, path)
        cfg = self.read_config_data(path, os.environ)

        # Try getting variables from env
        try:
            host = os.getenv("MAAS_HOST")
            token_key = os.getenv("MAAS_TOKEN_KEY")
            token_secret = os.getenv("MAAS_TOKEN_SECRET")
            customer_key = os.getenv("MAAS_CUSTOMER_KEY")
        except KeyError:
            raise errors.MaasError(
                "Missing parameters: MAAS_HOST, MAAS_TOKEN_KEY, MAAS_TOKEN_SECRET, MAAS_CUSTOMER_KEY."
            )
        client = Client(host, token_key, token_secret, customer_key)

        machine_list = client.get("/api/2.0/machines/").json

        # Process machines (VMs)
        for machine in (machine_list or []):
            status_cfg = cfg.get("status")
            machine_status = (machine.get("status_name") or "").lower()
            if status_cfg and status_cfg.lower() != machine_status:
                continue

            # determine group (domain) and ensure group exists
            group_name = "ungrouped"
            if machine.get("domain") and machine["domain"].get("name"):
                group_name = machine["domain"]["name"]
            inventory.add_group(group_name)

            # host identifier
            host_name = machine.get("fqdn") or machine.get("hostname") or machine.get("system_id")
            if not host_name:
                # skip items without usable name
                continue
            inventory.add_host(host_name, group=group_name)

            # gather interfaces (try resource_uri then inline)
            interfaces = []
            ansible_host = machine.get("fqdn") or None
            try:
                res_uri = machine.get("resource_uri")
                if res_uri:
                    iface_list = client.get(res_uri.rstrip("/") + "/interfaces/").json
                else:
                    iface_list = machine.get("interfaces", [])
            except Exception:
                iface_list = machine.get("interfaces", [])

            for iface in (iface_list or []):
                mac = iface.get("mac_address") or iface.get("mac") or iface.get("macaddr")
                name = iface.get("name") or iface.get("device") or iface.get("iface")
                ips = []
                for ip in iface.get("ip_addresses", []) or iface.get("ips", []) or []:
                    if isinstance(ip, dict):
                        ip_addr = ip.get("address") or ip.get("ip")
                    else:
                        ip_addr = ip
                    if ip_addr:
                        ips.append(ip_addr)
                        if not ansible_host:
                            ansible_host = ip_addr
                interfaces.append({"name": name, "mac": mac, "ips": ips})

            inventory.set_variable(host_name, "ansible_host", ansible_host or host_name)
            inventory.set_variable(host_name, "ansible_group", group_name)
            inventory.set_variable(host_name, "interfaces", interfaces)

        # Include physical nodes / devices with interfaces
        try:
            node_list = client.get("/api/2.0/nodes/").json
        except Exception:
            node_list = []

        for node in (node_list or []):
            node_name = node.get("hostname") or node.get("fqdn") or node.get("system_id")
            if not node_name:
                continue

            inventory.add_group("devices")
            inventory.add_host(node_name, group="devices")
            inventory.set_variable(node_name, "ansible_group", "devices")

            interfaces = []
            ansible_host = node.get("fqdn") or None
            try:
                res_uri = node.get("resource_uri")
                if res_uri:
                    iface_list = client.get(res_uri.rstrip("/") + "/interfaces/").json
                else:
                    iface_list = node.get("interfaces", [])
            except Exception:
                iface_list = node.get("interfaces", [])

            for iface in (iface_list or []):
                mac = iface.get("mac_address") or iface.get("mac") or iface.get("macaddr")
                name = iface.get("name") or iface.get("device") or iface.get("iface")
                ips = []
                for ip in iface.get("ip_addresses", []) or iface.get("ips", []) or []:
                    if isinstance(ip, dict):
                        ip_addr = ip.get("address") or ip.get("ip")
                    else:
                        ip_addr = ip
                    if ip_addr:
                        ips.append(ip_addr)
                        if not ansible_host:
                            ansible_host = ip_addr
                interfaces.append({"name": name, "mac": mac, "ips": ips})

            inventory.set_variable(node_name, "ansible_host", ansible_host or node_name)
            inventory.set_variable(node_name, "interfaces", interfaces)
