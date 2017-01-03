# Copyright (C) 2016 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from operator import attrgetter

import simple_switch2_13
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from ryu.lib.packet import ether_types
from ryu.lib.packet import in_proto


class SimpleMonitor13(simple_switch2_13.SimpleSwitch2_13):

    def __init__(self, *args, **kwargs):
        super(SimpleMonitor13, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)
        self.eth_types = {ether_types.ETH_TYPE_ARP: 'ARP', ether_types.ETH_TYPE_IP: 'IP'}
        self.protos = {in_proto.IPPROTO_TCP: 'TCP', in_proto.IPPROTO_UDP: 'UDP', in_proto.IPPROTO_ICMP: 'ICMP'}

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(10)

    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        
        #self.logger.info(body);

        self.logger.info('eth_type ip_proto '
                         'ip_src           ip_dst           '
                         'port_src port_dst '
                         'tcp_flag '
                         'packets  bytes')
        self.logger.info('-------- -------- '
                         '---------------- ---------------- '
                         '-------- -------- '
                         '-------- '
                         '-------- --------')

        for stat in sorted([flow for flow in body if flow.priority == 2],
                           key=lambda flow: (flow.match['eth_type'])):
            if stat.match['eth_type'] == ether_types.ETH_TYPE_IP:
                if stat.match['ip_proto'] == in_proto.IPPROTO_TCP:
                    self.logger.info('%8s %8s %16s %16s %8d %8d %8d %8d %8d',
                                     self.eth_types[stat.match['eth_type']], self.protos[stat.match['ip_proto']],
                                     stat.match['ipv4_src'], stat.match['ipv4_dst'],
                                     stat.match['tcp_src'], stat.match['tcp_dst'],
                                     stat.match['tcp_flags'],
                                     stat.packet_count, stat.byte_count)
                elif stat.match['ip_proto'] == in_proto.IPPROTO_UDP:
                    self.logger.info('%8s %8s %16s %16s %8d %8d %8d %8d %8d',
                                     self.eth_types[stat.match['eth_type']], self.protos[stat.match['ip_proto']],
                                     stat.match['ipv4_src'], stat.match['ipv4_dst'],
                                     stat.match['udp_src'], stat.match['udp_dst'],
                                     -1,
                                     stat.packet_count, stat.byte_count)
                elif stat.match['ip_proto'] == in_proto.IPPROTO_ICMP:
                    self.logger.info('%8s %8s %16s %16s %8d %8d %8d %8d %8d',
                                     self.eth_types[stat.match['eth_type']], self.protos[stat.match['ip_proto']],
                                     stat.match['ipv4_src'], stat.match['ipv4_dst'],
                                     -1, -1,
                                     -1,
                                     stat.packet_count, stat.byte_count)
            elif stat.match['eth_type'] == ether_types.ETH_TYPE_ARP:
                self.logger.info('%8s %8s %16s %16s %8d %8d %8d %8d %8d',
                                 self.eth_types[stat.match['eth_type']], None,
                                 stat.match['arp_spa'], stat.match['arp_tpa'],
                                 -1, -1,
                                 -1,
                                 stat.packet_count, stat.byte_count)

