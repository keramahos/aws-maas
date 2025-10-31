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

        for machine in (machine_list or []):
            # status filtering
            status_cfg = cfg.get("status")
            machine_status = (machine.get("status_name") or "").lower()
            if status_cfg and status_cfg.lower() != machine_status:
                continue

            # domain/group name (domain can be dict or string)
            domain_name = None
            if machine.get("domain"):
                if isinstance(machine["domain"], dict):
                    domain_name = machine["domain"].get("name")
                elif isinstance(machine["domain"], str):
                    domain_name = machine["domain"]
            group_name = domain_name or "ungrouped"
            inventory.add_group(group_name)

            # host identifier
            host_name = machine.get("fqdn") or machine.get("hostname") or machine.get("system_id")
            if not host_name:
                continue

            inventory.add_host(host_name, group=group_name)
            inventory.add_host(host_name, group="machines")

            # fetch interfaces: prefer machine resource interfaces endpoint, fallback to inline
            iface_list = []
            try:
                res_uri = machine.get("resource_uri")
                if res_uri:
                    resp = client.get(res_uri.rstrip("/") + "/interfaces/").json
                    if isinstance(resp, dict) and "objects" in resp:
                        iface_list = resp.get("objects") or []
                    else:
                        iface_list = resp or []
                else:
                    iface_list = machine.get("interfaces") or []
            except Exception:
                iface_list = machine.get("interfaces") or []

            # normalize interfaces (follow URIs if present)
            normalized_ifaces = []
            for iface in (iface_list or []):
                if isinstance(iface, str):
                    try:
                        iface_obj = client.get(iface).json
                    except Exception:
                        continue
                else:
                    iface_obj = iface
                if not isinstance(iface_obj, dict):
                    continue
                normalized_ifaces.append(iface_obj)

            # Fetch interfaces and network data directly using MAAS API
            interfaces = []
            ansible_host = machine.get("fqdn") or None
            system_id = machine.get("system_id")

            if system_id:
                try:
                    # Get all network interfaces for this machine
                    iface_list = client.get(f"/api/2.0/machines/{system_id}/interfaces/").json

                    for iface in iface_list:
                        interface_data = {
                            "name": iface.get("name"),
                            "mac": iface.get("mac_address"),
                            "ips": []
                        }

                        # Get IP addresses from both links and discovered IPs
                        if iface.get("links"):
                            for link in iface.get("links", []):
                                # Static and DHCP addresses
                                if link.get("ip_address"):
                                    interface_data["ips"].append(link["ip_address"])
                                # Subnet details if available
                                if link.get("subnet", {}).get("cidr"):
                                    interface_data["subnet"] = link["subnet"]["cidr"]

                        # Include discovered IPs if any
                        if iface.get("discovered", {}).get("ip_addresses"):
                            for ip in iface["discovered"]["ip_addresses"]:
                                if ip not in interface_data["ips"]:
                                    interface_data["ips"].append(ip)

                        # Set first usable IP as ansible_host if FQDN not available
                        if interface_data["ips"] and not ansible_host:
                            for ip in interface_data["ips"]:
                                if not ip.startswith("127."):
                                    ansible_host = ip
                                    break

                        # Only include interfaces with either MAC or IPs
                        if interface_data["mac"] or interface_data["ips"]:
                            interfaces.append(interface_data)

                except Exception as e:
                    logger.error(f"Failed to fetch interfaces for machine {system_id}: {str(e)}")

            inventory.set_variable(host_name, "ansible_host", ansible_host or host_name)
            inventory.set_variable(host_name, "interfaces", interfaces)

        # --- NODES / DEVICES ---
        try:
            node_list = client.get("/api/2.0/nodes/").json or []
        except Exception:
            node_list = []

        # top-level devices group
        inventory.add_group("devices")

        for node in (node_list or []):
            # domain for node (can be dict or string)
            domain_name = None
            if node.get("domain"):
                if isinstance(node["domain"], dict):
                    domain_name = node["domain"].get("name")
                elif isinstance(node["domain"], str):
                    domain_name = node["domain"]

            fqdn = node.get("fqdn")
            hostname = node.get("hostname")
            system_id = node.get("system_id")

            if fqdn:
                node_name = fqdn
            elif hostname:
                node_name = "{}.{}".format(hostname, domain_name) if domain_name else hostname
            else:
                node_name = system_id

            if not node_name:
                continue

            # groups: domain (if any) and top-level devices
            inventory.add_host(node_name, group="devices")
            if domain_name:
                inventory.add_group(domain_name)
                inventory.add_host(node_name, group=domain_name)

            inventory.set_variable(node_name, "ansible_group", domain_name or "devices")

            # fetch node interfaces (same logic as machines)
            iface_list = []
            try:
                res_uri = node.get("resource_uri")
                if res_uri:
                    resp = client.get(res_uri.rstrip("/") + "/interfaces/").json
                    if isinstance(resp, dict) and "objects" in resp:
                        iface_list = resp.get("objects") or []
                    else:
                        iface_list = resp or []
                else:
                    iface_list = node.get("interfaces") or []
            except Exception:
                iface_list = node.get("interfaces") or []

            normalized_ifaces = []
            for iface in (iface_list or []):
                if isinstance(iface, str):
                    try:
                        iface_obj = client.get(iface).json
                    except Exception:
                        continue
                else:
                    iface_obj = iface
                if not isinstance(iface_obj, dict):
                    continue
                normalized_ifaces.append(iface_obj)

            interfaces = []
            ansible_host = node.get("fqdn") or None

            for iface in (normalized_ifaces or []):
                mac = iface.get("mac_address") or iface.get("mac") or iface.get("macaddr")
                name = iface.get("name") or iface.get("device") or iface.get("iface")
                ips = []

                ip_entries = (
                    iface.get("ip_addresses")
                    or iface.get("ips")
                    or iface.get("ip_address")
                    or iface.get("ipv4_addresses")
                    or iface.get("ipv6_addresses")
                    or []
                )

                for ip in (ip_entries or []):
                    ip_addr = None
                    if isinstance(ip, str):
                        try:
                            ip_obj = client.get(ip).json
                        except Exception:
                            ip_obj = None
                        if isinstance(ip_obj, dict):
                            ip_addr = ip_obj.get("address") or ip_obj.get("ip") or ip_obj.get("cidr")
                    elif isinstance(ip, dict):
                        ip_addr = ip.get("address") or ip.get("ip") or ip.get("cidr")
                    else:
                        ip_addr = str(ip)

                    if ip_addr:
                        ips.append(ip_addr)
                        if not ansible_host and not ip_addr.startswith("127."):
                            ansible_host = ip_addr

                interfaces.append({"name": name, "mac": mac, "ips": ips})

            inventory.set_variable(node_name, "ansible_host", ansible_host or node_name)
            inventory.set_variable(node_name, "interfaces", interfaces)
