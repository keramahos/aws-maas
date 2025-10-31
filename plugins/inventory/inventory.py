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

        # top-level machines group
        inventory.add_group("machines")

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
            # add to domain group and top-level machines group
            inventory.add_host(host_name, group=group_name)
            inventory.add_host(host_name, group="machines")

            # gather interfaces (try resource_uri then inline)
            interfaces = []
            ansible_host = machine.get("fqdn") or None
            try:
                res_uri = machine.get("resource_uri")
                if res_uri:
                    iface_resp = client.get(res_uri.rstrip("/") + "/interfaces/").json
                    # MAAS may return a dict with 'objects' or a plain list
                    if isinstance(iface_resp, dict) and "objects" in iface_resp:
                        iface_list = iface_resp.get("objects", [])
                    else:
                        iface_list = iface_resp
                else:
                    iface_list = machine.get("interfaces", [])
            except Exception:
                iface_list = machine.get("interfaces", [])

            # normalize: fetch interface resources if entries are URIs
            normalized_ifaces = []
            for iface in (iface_list or []):
                if isinstance(iface, str):
                    try:
                        iface = client.get(iface).json
                    except Exception:
                        continue
                normalized_ifaces.append(iface)

            for iface in (normalized_ifaces or []):
                mac = iface.get("mac_address") or iface.get("mac") or iface.get("macaddr")
                name = iface.get("name") or iface.get("device") or iface.get("iface")
                ips = []

                # MAAS may expose ip entries as dicts or URIs; handle both
                ip_entries = iface.get("ip_addresses") or iface.get("ips") or iface.get("ip_address") or []
                for ip in (ip_entries or []):
                    ip_addr = None
                    if isinstance(ip, str):
                        # ip is a resource URI -> fetch it
                        try:
                            ip_obj = client.get(ip).json
                        except Exception:
                            ip_obj = None
                        if isinstance(ip_obj, dict):
                            ip_addr = ip_obj.get("address") or ip_obj.get("ip") or ip_obj.get("cidr")
                    elif isinstance(ip, dict):
                        ip_addr = ip.get("address") or ip.get("ip") or ip.get("cidr")
                    else:
                        # fallback to string conversion
                        ip_addr = str(ip)

                    if ip_addr:
                        ips.append(ip_addr)
                        # prefer a non-loopback ip for ansible_host if fqdn missing
                        if not ansible_host and not ip_addr.startswith("127."):
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

        # ensure top-level devices group exists
        inventory.add_group("devices")

        for node in (node_list or []):
            # build node name: prefer fqdn, otherwise hostname + domain (if available), otherwise system_id
            fqdn = node.get("fqdn")
            hostname = node.get("hostname")
            system_id = node.get("system_id")
            domain_name = None
            if node.get("domain"):
                if isinstance(node["domain"], dict):
                    domain_name = node["domain"].get("name")
                elif isinstance(node["domain"], str):
                    domain_name = node["domain"]

            if fqdn:
                node_name = fqdn
            elif hostname:
                node_name = "{}.{}".format(hostname, domain_name) if domain_name else hostname
            else:
                node_name = system_id

            if not node_name:
                continue

            # add to domain group (if available) and top-level devices group
            inventory.add_host(node_name, group="devices")
            if domain_name:
                inventory.add_group(domain_name)
                inventory.add_host(node_name, group=domain_name)

            inventory.set_variable(node_name, "ansible_group", domain_name or "devices")

            interfaces = []
            ansible_host = node.get("fqdn") or None
            try:
                res_uri = node.get("resource_uri")
                if res_uri:
                    iface_resp = client.get(res_uri.rstrip("/") + "/interfaces/").json
                    if isinstance(iface_resp, dict) and "objects" in iface_resp:
                        iface_list = iface_resp.get("objects", [])
                    else:
                        iface_list = iface_resp
                else:
                    iface_list = node.get("interfaces", [])
            except Exception:
                iface_list = node.get("interfaces", [])

            normalized_ifaces = []
            for iface in (iface_list or []):
                if isinstance(iface, str):
                    try:
                        iface = client.get(iface).json
                    except Exception:
                        continue
                normalized_ifaces.append(iface)

            for iface in (normalized_ifaces or []):
                mac = iface.get("mac_address") or iface.get("mac") or iface.get("macaddr")
                name = iface.get("name") or iface.get("device") or iface.get("iface")
                ips = []

                ip_entries = iface.get("ip_addresses") or iface.get("ips") or iface.get("ip_address") or []
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
