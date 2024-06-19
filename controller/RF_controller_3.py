from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub

import switch
from datetime import datetime

import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier

from sklearn.metrics import confusion_matrix
from sklearn.metrics import accuracy_score
from ryu.lib.packet import packet, ethernet, ether_types, ipv4, icmp, tcp, udp, in_proto

class SimpleMonitor13(switch.SimpleSwitch13):

    def __init__(self, *args, **kwargs):

        super(SimpleMonitor13, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)

        start = datetime.now()

        self.flow_training()

        end = datetime.now()
        print("Training time: ", (end - start))

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

            self.flow_predict()

    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):

        timestamp = datetime.now()
        timestamp = timestamp.timestamp()

        file0 = open("PredictFlowStatsfile.csv", "w")
        file0.write(
            'timestamp,datapath_id,flow_id,ip_src,tp_src,ip_dst,tp_dst,ip_proto,icmp_code,icmp_type,flow_duration_sec,flow_duration_nsec,idle_timeout,hard_timeout,flags,packet_count,byte_count,packet_count_per_second,packet_count_per_nsecond,byte_count_per_second,byte_count_per_nsecond\n')
        body = ev.msg.body
        icmp_code = -1
        icmp_type = -1
        tp_src = 0
        tp_dst = 0

        for stat in sorted([flow for flow in body if (flow.priority == 1)], key=lambda flow:
        (flow.match['eth_type'], flow.match['ipv4_src'], flow.match['ipv4_dst'], flow.match['ip_proto'])):

            ip_src = stat.match['ipv4_src']
            ip_dst = stat.match['ipv4_dst']
            ip_proto = stat.match['ip_proto']

            if stat.match['ip_proto'] == 1:
                icmp_code = stat.match['icmpv4_code']
                icmp_type = stat.match['icmpv4_type']

            elif stat.match['ip_proto'] == 6:
                tp_src = stat.match['tcp_src']
                tp_dst = stat.match['tcp_dst']

            elif stat.match['ip_proto'] == 17:
                tp_src = stat.match['udp_src']
                tp_dst = stat.match['udp_dst']

            flow_id = str(ip_src) + str(tp_src) + str(ip_dst) + str(tp_dst) + str(ip_proto)

            try:
                packet_count_per_second = stat.packet_count / stat.duration_sec
                packet_count_per_nsecond = stat.packet_count / stat.duration_nsec
            except:
                packet_count_per_second = 0
                packet_count_per_nsecond = 0

            try:
                byte_count_per_second = stat.byte_count / stat.duration_sec
                byte_count_per_nsecond = stat.byte_count / stat.duration_nsec
            except:
                byte_count_per_second = 0
                byte_count_per_nsecond = 0

            file0.write("{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n"
                        .format(timestamp, ev.msg.datapath.id, flow_id, ip_src, tp_src, ip_dst, tp_dst,
                                stat.match['ip_proto'], icmp_code, icmp_type,
                                stat.duration_sec, stat.duration_nsec,
                                stat.idle_timeout, stat.hard_timeout,
                                stat.flags, stat.packet_count, stat.byte_count,
                                packet_count_per_second, packet_count_per_nsecond,
                                byte_count_per_second, byte_count_per_nsecond))

        file0.close()

    def flow_training(self):

        self.logger.info("Flow Training ...")

        flow_dataset = pd.read_csv('FlowStatsfile.csv')

        flow_dataset.iloc[:, 2] = flow_dataset.iloc[:, 2].str.replace('.', '')
        flow_dataset.iloc[:, 3] = flow_dataset.iloc[:, 3].str.replace('.', '')
        flow_dataset.iloc[:, 5] = flow_dataset.iloc[:, 5].str.replace('.', '')

        X_flow = flow_dataset.iloc[:, :-1].values
        X_flow = X_flow.astype('float64')

        y_flow = flow_dataset.iloc[:, -1].values

        X_flow_train, X_flow_test, y_flow_train, y_flow_test = train_test_split(X_flow, y_flow, test_size=0.25,
                                                                                random_state=0)

        classifier = RandomForestClassifier(n_estimators=10, criterion="entropy", random_state=0)
        self.flow_model = classifier.fit(X_flow_train, y_flow_train)

        y_flow_pred = self.flow_model.predict(X_flow_test)

        self.logger.info("------------------------------------------------------------------------------")

        self.logger.info("confusion matrix")
        cm = confusion_matrix(y_flow_test, y_flow_pred)
        self.logger.info(cm)

        acc = accuracy_score(y_flow_test, y_flow_pred)

        self.logger.info("succes accuracy = {0:.2f} %".format(acc * 100))
        fail = 1.0 - acc
        self.logger.info("fail accuracy = {0:.2f} %".format(fail * 100))
        self.logger.info("------------------------------------------------------------------------------")

    def flow_predict(self):
        try:
            predict_flow_dataset = pd.read_csv('PredictFlowStatsfile.csv')

            predict_flow_dataset.iloc[:, 2] = predict_flow_dataset.iloc[:, 2].str.replace('.', '')
            predict_flow_dataset.iloc[:, 3] = predict_flow_dataset.iloc[:, 3].str.replace('.', '')
            predict_flow_dataset.iloc[:, 5] = predict_flow_dataset.iloc[:, 5].str.replace('.', '')

            X_predict_flow = predict_flow_dataset.iloc[:, :].values
            X_predict_flow = X_predict_flow.astype('float64')

            y_flow_pred = self.flow_model.predict(X_predict_flow)

            legitimate_trafic = 0
            ddos_trafic = 0
            portscan_trafic = 0
            is_ddos = False
            host_or_switch_flag = False
            for i in y_flow_pred:
                if i == 0:
                    legitimate_trafic = legitimate_trafic + 1
                elif i == 2:
                    portscan_trafic = portscan_trafic + 1
                    victim = int(predict_flow_dataset.iloc[i, 5]) % 20
                    attacker = int(predict_flow_dataset.iloc[i, 3]) % 20
                else:
                    ddos_trafic = ddos_trafic + 1
                    victim = int(predict_flow_dataset.iloc[i, 5]) % 20
                    attacker = int(predict_flow_dataset.iloc[i, 1])
                    host_or_switch_flag = True

            self.logger.info("legitimate traffic: {}".format(legitimate_trafic))
            self.logger.info("ddos traffic: {}".format(ddos_trafic))
            self.logger.info("port scan traffic: {}".format(portscan_trafic))

            self.logger.info("------------------------------------------------------------------------------")
            is_Land = False
            land_attacker = int(predict_flow_dataset.iloc[i, 3]) % 20

            if (legitimate_trafic/len(y_flow_pred)*100) > 80:
                self.logger.info("legitimate trafic ...")
            else:
                self.logger.info("ddos trafic ...")
                self.logger.info("victim is host: h{}".format(victim))
                if host_or_switch_flag == True: 
                    self.logger.info("attacker is switch: id {}".format(attacker))
                else: 
                    self.logger.info("attacker is host: h{}".format(attacker))
                    
                self.logger.info("Applying countermeasures ...")
                is_Land = self.apply_counter_land(victim,land_attacker)
                if is_Land == True:
                    self.logger.info("Land attack ...")
                if ddos_trafic != 0:
                    if ((ddos_trafic - portscan_trafic)/ddos_trafic) *100 > 80:
                        is_ddos = True
                self.apply_countermeasures(attacker,is_ddos)

            self.logger.info("------------------------------------------------------------------------------")

            file0 = open("PredictFlowStatsfile.csv", "w")

            file0.write(
                'timestamp,datapath_id,flow_id,ip_src,tp_src,ip_dst,tp_dst,ip_proto,icmp_code,icmp_type,flow_duration_sec,flow_duration_nsec,idle_timeout,hard_timeout,flags,packet_count,byte_count,packet_count_per_second,packet_count_per_nsecond,byte_count_per_second,byte_count_per_nsecond\n')
            file0.close()

        except:
            pass
    

    def apply_counter_land(self, victim, attacker):
        
        for dp in self.datapaths.values():
            ofproto = dp.ofproto
            parser = dp.ofproto_parser
            self.logger.info(" victim  {}, attacker  {}  ".format(victim,attacker))
         
            # Check if the victim and attacker are the same
            if victim == attacker:
                

                try:
                    # Add rule to drop packets with the same source and destination IP address
                    match_drop_same_ip = parser.OFPMatch(
                        eth_type=ether_types.ETH_TYPE_IP,
                        ipv4_src="10.0.0.{}".format(attacker),
                        ipv4_dst="10.0.0.{}".format(victim)
                    )

                    # Define actions as empty to drop the packet
                    actions_drop = []
                    inst_drop = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions_drop)]

                    # Create flow mod message to drop packets with same source and destination IP
                    mod_drop_same_ip = parser.OFPFlowMod(
                        datapath=dp, priority=200, match=match_drop_same_ip, instructions=inst_drop
                    )

                    dp.send_msg(mod_drop_same_ip)

                    self.logger.info("Dropping packets with matching source and destination IP on switch {}".format(dp.id))
                    
                    return True
                except Exception as e:
                    self.logger.info("Error applying countermeasures on switch {}: {}".format(dp.id, str(e)))
                    return False
            else:
                return False

        return False



    def apply_countermeasures(self, attacker, is_ddos_attack):
    
        for dp in self.datapaths.values():
            ofproto = dp.ofproto
            parser = dp.ofproto_parser

            try:
                if is_ddos_attack:
                    self.logger.info("attacker {} dp {}".format(attacker , dp.id))
                    if dp.id == attacker:
                        # Define instructions for rate limiting
                        actions_limit = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, max_len=ofproto.OFPCML_NO_BUFFER)]
                        inst_limit = [
                            parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions_limit),
                            parser.OFPInstructionMeter(meter_id=1)
                        ]
                        
                        
                        match_ip = parser.OFPMatch(
                            eth_type=ether_types.ETH_TYPE_IP,
                            
                        )
                        


                        # Create flow mod message to rate limit IP traffic
                        mod_limit = parser.OFPFlowMod(
                            datapath=dp, priority=50, match=match_ip, instructions=inst_limit
                        )

                        dp.send_msg(mod_limit)

                        self.logger.info("Rate limiting IP traffic from attacker id {} on switch {}".format(attacker, dp.id))

                else:
                    # Define instructions for blocking
                    actions_block = []
                    inst_block = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions_block)]

                    # Match IP traffic from the attacker
                    match_ip = parser.OFPMatch(
                        eth_type=ether_types.ETH_TYPE_IP,
                        ipv4_src='10.0.0.{}'.format(attacker)
                    )

                    # Create flow mod message to block all IP traffic
                    mod_block = parser.OFPFlowMod(
                        datapath=dp, priority=100, match=match_ip, instructions=inst_block
                    )

                    dp.send_msg(mod_block)

                    self.logger.info("Blocking all IP traffic from attacker h{} on switch {}".format(attacker, dp.id))

            except Exception as e:
                self.logger.info("Error applying countermeasures on switch {}: {}".format(dp.id, str(e)))

