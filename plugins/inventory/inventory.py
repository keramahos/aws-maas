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
from concurrent.futures import ThreadPoolExecutor, as_completed

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


def fetch_node_interfaces(client, system_id):
    """
    Fetch interface data for a node/machine using MAAS API.
    Returns a tuple of (interfaces_list, ansible_host).
    """
    interfaces = []
    ansible_host = None

    try:
        # Get detailed interface information using proper API endpoint
        iface_response = client.get(f"/api/2.0/nodes/{system_id}/interfaces/").json

        # Handle both list and dict responses
        if isinstance(iface_response, list):
            iface_data = iface_response
        elif isinstance(iface_response, dict) and "objects" in iface_response:
            iface_data = iface_response.get("objects", [])
        else:
            iface_data = []

        for iface in iface_data:
            interface_data = {
                "name": iface.get("name"),
                "mac": iface.get("mac_address"),
                "ips": [],
                "type": iface.get("type"),
                "enabled": iface.get("enabled")
            }

            # Get IP addresses from links (static, DHCP, AUTO)
            links = iface.get("links", [])
            for link in links:
                ip_address = link.get("ip_address")
                if ip_address:
                    interface_data["ips"].append(ip_address)
                    # Store subnet info if available
                    subnet = link.get("subnet", {})
                    if subnet and isinstance(subnet, dict):
                        cidr = subnet.get("cidr")
                        if cidr and "subnet" not in interface_data:
                            interface_data["subnet"] = cidr

            # Also check for discovered IPs
            discovered = iface.get("discovered")
            if discovered and isinstance(discovered, list):
                for disc in discovered:
                    if isinstance(disc, dict):
                        subnet = disc.get("subnet")
                        if subnet and isinstance(subnet, dict):
                            ip = subnet.get("cidr")
                            if ip and ip not in interface_data["ips"]:
                                interface_data["ips"].append(ip)

            # Set first usable IP as ansible_host if not set
            if interface_data["ips"] and not ansible_host:
                for ip in interface_data["ips"]:
                    # Skip loopback and link-local addresses
                    if not ip.startswith(("127.", "169.254.", "fe80:")):
                        ansible_host = ip
                        break

            # Only include interfaces with either MAC or IPs
            if interface_data["mac"] or interface_data["ips"]:
                interfaces.append(interface_data)

    except Exception as e:
        logger.error(f"Failed to fetch interfaces for node {system_id}: {str(e)}")

    return interfaces, ansible_host


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

        # read environment variables (os.getenv is safe)
        host = os.getenv("MAAS_HOST")
        token_key = os.getenv("MAAS_TOKEN_KEY")
        token_secret = os.getenv("MAAS_TOKEN_SECRET")
        customer_key = os.getenv("MAAS_CUSTOMER_KEY")

        if not all([host, token_key, token_secret, customer_key]):
            raise errors.MaasError(
                "Missing parameters: MAAS_HOST, MAAS_TOKEN_KEY, MAAS_TOKEN_SECRET, MAAS_CUSTOMER_KEY."
            )

        client = Client(host, token_key, token_secret, customer_key)

        # --- MACHINES (VMs) ---
        try:
            machine_list = client.get("/api/2.0/machines/").json or []
        except Exception:
            machine_list = []

        inventory.add_group("machines")

        # Pre-fetch all interface data in parallel for better performance
        machine_interfaces_cache = {}
        machine_system_ids = []

        for machine in (machine_list or []):
            system_id = machine.get("system_id")
            if system_id:
                machine_system_ids.append(system_id)

        # Fetch interfaces in parallel using ThreadPoolExecutor
        if machine_system_ids:
            with ThreadPoolExecutor(max_workers=10) as executor:
                future_to_system_id = {
                    executor.submit(fetch_node_interfaces, client, system_id): system_id
                    for system_id in machine_system_ids
                }
                for future in as_completed(future_to_system_id):
                    system_id = future_to_system_id[future]
                    try:
                        interfaces, ansible_host = future.result()
                        machine_interfaces_cache[system_id] = (interfaces, ansible_host)
                    except Exception as e:
                        logger.error(f"Failed to fetch interfaces for {system_id}: {str(e)}")
                        machine_interfaces_cache[system_id] = ([], None)

        # Now process machines with cached interface data
        for machine in (machine_list or []):
            # status filtering
            status_cfg = cfg.get("status")
            machine_status = (machine.get("status_name") or "").lower()
            if status_cfg and status_cfg.lower() != machine_status:
                continue

            # host identifier
            host_name = machine.get("fqdn") or machine.get("hostname") or machine.get("system_id")
            if not host_name:
                continue

            # Add to machines group only
            inventory.add_host(host_name, group="machines")

            # Get interfaces from cache
            system_id = machine.get("system_id")
            ansible_host = machine.get("fqdn") or None
            interfaces = []

            if system_id and system_id in machine_interfaces_cache:
                interfaces, fetched_host = machine_interfaces_cache[system_id]
                # Use fetched IP if FQDN not available
                if not ansible_host and fetched_host:
                    ansible_host = fetched_host

            # Fallback to inline interface data if cache is empty
            if not interfaces and system_id:
                try:
                    inline_ifaces = machine.get("interface_set", []) or machine.get("interfaces", [])
                    for iface in inline_ifaces:
                        if isinstance(iface, dict):
                            mac = iface.get("mac_address")
                            name = iface.get("name")
                            if mac or name:
                                interfaces.append({
                                    "name": name,
                                    "mac": mac,
                                    "ips": []
                                })
                except Exception:
                    pass

            inventory.set_variable(host_name, "ansible_host", ansible_host or host_name)
            inventory.set_variable(host_name, "interfaces", interfaces)

        # --- NODES / DEVICES ---
        try:
            node_list = client.get("/api/2.0/nodes/").json or []
        except Exception:
            node_list = []

        # top-level devices group
        inventory.add_group("devices")

        # Pre-fetch all node interface data in parallel for better performance
        node_interfaces_cache = {}
        node_system_ids = []

        for node in (node_list or []):
            system_id = node.get("system_id")
            if system_id:
                node_system_ids.append(system_id)

        # Fetch interfaces in parallel using ThreadPoolExecutor
        if node_system_ids:
            with ThreadPoolExecutor(max_workers=10) as executor:
                future_to_system_id = {
                    executor.submit(fetch_node_interfaces, client, system_id): system_id
                    for system_id in node_system_ids
                }
                for future in as_completed(future_to_system_id):
                    system_id = future_to_system_id[future]
                    try:
                        interfaces, ansible_host = future.result()
                        node_interfaces_cache[system_id] = (interfaces, ansible_host)
                    except Exception as e:
                        logger.error(f"Failed to fetch interfaces for {system_id}: {str(e)}")
                        node_interfaces_cache[system_id] = ([], None)

        for node in (node_list or []):
            fqdn = node.get("fqdn")
            hostname = node.get("hostname")
            system_id = node.get("system_id")

            if fqdn:
                node_name = fqdn
            elif hostname:
                node_name = hostname
            else:
                node_name = system_id

            if not node_name:
                continue

            # Add to devices group only
            inventory.add_host(node_name, group="devices")

            # Get interfaces from cache
            ansible_host = node.get("fqdn") or None
            interfaces = []

            if system_id and system_id in node_interfaces_cache:
                interfaces, fetched_host = node_interfaces_cache[system_id]
                # Use fetched IP if FQDN not available
                if not ansible_host and fetched_host:
                    ansible_host = fetched_host

            # Fallback to inline interface data if cache is empty
            if not interfaces and system_id:
                try:
                    inline_ifaces = node.get("interface_set", []) or node.get("interfaces", [])
                    for iface in inline_ifaces:
                        if isinstance(iface, dict):
                            mac = iface.get("mac_address")
                            name = iface.get("name")
                            if mac or name:
                                interfaces.append({
                                    "name": name,
                                    "mac": mac,
                                    "ips": []
                                })
                except Exception:
                    pass

            inventory.set_variable(node_name, "ansible_host", ansible_host or node_name)
            inventory.set_variable(node_name, "interfaces", interfaces)
