# Copyright 2016 Ebay Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import netaddr
import random
import re

from rally_ovs.plugins.ovs.scenarios import ovn

from rally.task import scenario
from rally.task import atomic
from rally.task import validation

class OvnNorthbound(ovn.OvnScenario):
    """Benchmark scenarios for OVN northbound."""

    @atomic.action_timer("ovn.create_or_update_address_set")
    def create_or_update_address_set(self, name, ipaddr, create = True):
        if (create):
            self._create_address_set(name, ipaddr)
        else:
            self._address_set_add_addrs(name, ipaddr)

    @atomic.action_timer("ovn.create_port_acls")
    def create_port_acls(self, lswitch, lports, addr_set):
        """
        create two acl for each logical port
        prio 1000: allow inter project traffic
        prio 900: deny all
        """
        match = "%(direction)s == %(lport)s && ip4.src == %(address_set)s"
        acl_create_args = { "match" : match, "address_set" : addr_set }
        self._create_acl(lswitch, lports, acl_create_args, 1)
        acl_create_args = { "priority" : 900, "action" : "drop", "match" : "%(direction)s == %(lport)s" }
        self._create_acl(lswitch, lports, acl_create_args, 1)

    def create_lport_acl_addrset(self, lswitch, lport_create_args, port_bind_args,
                                 ip_start_index = 0, addr_set_index = 0,
                                 create_addr_set = True, create_acls = True):
        iteration = self.context["iteration"]

        lports = self._create_lports(lswitch, lport_create_args,
                                     lport_ip_shift = ip_start_index)

        if create_acls:
            network_cidr = lswitch.get("cidr", None)
            if network_cidr:
                ip_list = netaddr.IPNetwork(network_cidr.ip + ip_start_index).iter_hosts()
                ipaddr = str(ip_list.next())
            else:
                ipaddr = ""
            self.create_or_update_address_set("addrset%d" % addr_set_index,
                                              ipaddr, create_addr_set)

            self.create_port_acls(lswitch, lports,
                                  "$addrset%d" % addr_set_index)

        sandboxes = self.context["sandboxes"]
        self._bind_ports(lports, sandboxes, port_bind_args)

    @scenario.configure()
    def create_routed_lport(self, lport_create_args = None,
                            port_bind_args = None,
                            create_acls = True):
        lswitches = self.context["datapaths"]["lswitches"]

        iteration = self.context["iteration"]
        lswitch = lswitches[iteration % len(lswitches)]
        addr_set_index = iteration / 2
        ip_start_index = iteration / len(lswitches) + 1

        self.create_lport_acl_addrset(lswitch, lport_create_args,
                                      port_bind_args, ip_start_index,
                                      addr_set_index, (iteration % 2) == 0,
                                      create_acls)

    @atomic.action_timer("ovn.delete_port_acls")
    def delete_port_acls(self, lswitch, lport, addr_set_index):
        match = "'outport == %s && ip4.src == $addrset%d'" % (lport["name"], addr_set_index)
        self._delete_acls(lswitch, "to-lport", "1000", match)
        match = "'outport == %s'" % lport["name"]
        self._delete_acls(lswitch, "to-lport", "900", match)

    @atomic.action_timer("ovn.delete_addr_from_addrset")
    def delete_addr_from_addrset(self, addr_set_index, addr):
       self._address_set_remove_addrs("addrset%d" % addr_set_index, addr)

    @scenario.configure()
    def add_remove_routed_lport(self, test_args,
                                lport_create_args = None,
                                port_bind_args = None,
                                create_acls = True):
        naddress_set = test_args.get("naddress", 10)
        prefix_len = test_args.get("prefixlen", 24)

        iteration = self.context["iteration"]
        lswitches = self.context["ovn-nb"]

        addr_set_index = iteration % naddress_set

        if random.randint(0, 1):
            #add a port
            lswitch = lswitches[iteration % len(lswitches)]
            ip_start_index = (iteration + 2 * naddress_set) / len(lswitches) + 1
            LOG.info("adding port to %s" % lswitch["name"])
            self.create_lport_acl_addrset(lswitch, lport_create_args,
                                          port_bind_args, ip_start_index,
                                          addr_set_index, False,
                                          create_acls)
        else:
            addr_set = self._get_address_set("addrset%d" % addr_set_index)
            # get first ip of the address set
            ip_addr = re.sub('\[|\]|\"|\\n', '', addr_set).split(",")[0]
            cidr = netaddr.IPNetwork(ip_addr)
            cidr.prefixlen = prefix_len

            lport = { "name": "lport_%s" % ip_addr }
            lswitch = { "name" : "lswitch_%s" % cidr.cidr }
            LOG.info("removing port %s from %s lswitch" % (lport["name"], lswitch["name"]))

            if create_acls:
                self.delete_addr_from_addrset(addr_set_index, ip_addr)
                self.delete_port_acls(lswitch, lport, addr_set_index)
            self._delete_lport([lport])

    @scenario.configure(context={})
    def create_and_list_lswitches(self, lswitch_create_args=None):
        self._create_lswitches(lswitch_create_args)
        self._list_lswitches()


    @scenario.configure(context={})
    def create_and_delete_lswitches(self, lswitch_create_args=None):
        lswitches = self._create_lswitches(lswitch_create_args or {})
        self._delete_lswitch(lswitches)


    @scenario.configure(context={})
    def cleanup_lswitches(self, lswitch_cleanup_args=None):
        lswitch_cleanup_args = lswitch_cleanup_args or {}
        prefix = lswitch_cleanup_args.get("prefix", "")

        lswitches = self.context.get("ovn-nb", [])
        matched_lswitches = []
        for lswitch in lswitches:
            if lswitch["name"].find(prefix) == 0:
                matched_lswitches.append(lswitch)

        self._delete_lswitch(matched_lswitches)


    @validation.number("lports_per_lswitch", minval=1, integer_only=True)
    @scenario.configure(context={})
    def create_and_list_lports(self,
                              lswitch_create_args=None,
                              lport_create_args=None,
                              lports_per_lswitch=None):

        lswitches = self._create_lswitches(lswitch_create_args)

        for lswitch in lswitches:
            self._create_lports(lswitch, lport_create_args, lports_per_lswitch)

        self._list_lports(lswitches, self.install_method)


    @scenario.configure(context={})
    def create_and_delete_lports(self,
                              lswitch_create_args=None,
                              lport_create_args=None,
                              lports_per_lswitch=None):

        lswitches = self._create_lswitches(lswitch_create_args)
        for lswitch in lswitches:
            lports = self._create_lports(lswitch, lport_create_args,
                                        lports_per_lswitch)
            self._delete_lport(lports)

        self._delete_lswitch(lswitches)



    def get_or_create_lswitch_and_lport(self,
                              lswitch_create_args=None,
                              lport_create_args=None,
                              lports_per_lswitch=None):

        lswitches = None
        if lswitch_create_args != None:
            lswitches = self._create_lswitches(lswitch_create_args)
            for lswitch in lswitches:
                lports = self._create_lports(lswitch, lport_create_args,
                                                    lports_per_lswitch)
                lswitch["lports"] = lports
        else:
            lswitches = self.context["ovn-nb"]

        return lswitches



    @validation.number("lports_per_lswitch", minval=1, integer_only=True)
    @validation.number("acls_per_port", minval=1, integer_only=True)
    @scenario.configure(context={})
    def create_and_list_acls(self,
                              lswitch_create_args=None,
                              lport_create_args=None,
                              lports_per_lswitch=None,
                              acl_create_args=None,
                              acls_per_port=None):
        lswitches = self.get_or_create_lswitch_and_lport(lswitch_create_args,
                                    lport_create_args, lports_per_lswitch)

        for lswitch in lswitches:
            self._create_acl(lswitch, lswitch["lports"],
                             acl_create_args, acls_per_port)

        self._list_acl(lswitches)



    @scenario.configure(context={})
    def cleanup_acls(self):

        lswitches = self.context["ovn-nb"]

        self._delete_all_acls_in_lswitches(lswitches)


    @validation.number("lports_per_lswitch", minval=1, integer_only=True)
    @validation.number("acls_per_port", minval=1, integer_only=True)
    @scenario.configure(context={})
    def create_and_delete_acls(self,
                              lswitch_create_args=None,
                              lport_create_args=None,
                              lports_per_lswitch=None,
                              acl_create_args=None,
                              acls_per_port=None):

        lswitches = self.get_or_create_lswitch_and_lport(lswitch_create_args,
                                    lport_create_args, lports_per_lswitch)


        for lswitch in lswitches:
            self._create_acl(lswitch, lswitch["lports"],
                             acl_create_args, acls_per_port)


        self._delete_all_acls_in_lswitches(lswitches)

    @scenario.configure(context={})
    def create_and_remove_address_set(self, name, address_list):
        self._create_address_set(name, address_list)
        self._remove_address_set(name)


