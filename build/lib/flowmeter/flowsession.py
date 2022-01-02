from scapy.sessions import DefaultSession, TCPSession
from scapy.layers.inet import TCP, IP, UDP
from scapy.layers.l2 import ARP
from scapy.plist import PacketList
from types import FunctionType
# from flowmeter.flowmeter import Flowmeter
import time

FLOW_TIMEOUT = 120  # seconds

class FlowSession(TCPSession):

    def __init__(self, 
            flow_timeout: float = FLOW_TIMEOUT, 
            callback: FunctionType = None,
            sess_function: FunctionType = None,
            *args, **kwargs):
        super(FlowSession, self).__init__(*args, **kwargs)
        # self.flows = Flowmeter()
        self.flow_timeout = flow_timeout
        self.callback = callback
        
        self.sess_function = sess_function

    @property
    def callback(self):
        return self._callback

    @callback.setter
    def callback(self, fn):
        if fn is None:
            self._callback = None
            return

        def clear_list_wrapper(fn):
            def inner_fn(packetlist):
                self.lst = [pkt for pkt in self.lst if pkt not in packetlist]
                return fn(packetlist)
            return inner_fn
        self._callback = clear_list_wrapper(fn)

    # def _output_flow(self, sess_pkts: PacketList):
    #     self.lst = [pkt for pkt in self.lst if pkt not in sess_pkts]

    #     self.flows._pcap = sess_pkts
    #     try:
    #         self.flows.build_feature_dataframe().to_csv('test.csv', mode='a')
    #     except ValueError:
    #         print('Packet Summary:')
    #         print(sess_pkts.summary())
    #         raise
    #     self._first = False

    def on_packet_received(self, pkt):
        """Hook to the Sessions API: entry point of the dissection.
        This will defragment IP if necessary, then process to
        TCP reassembly.
        """

        # Now see if we need to return a complete session
        if self.callback is not None:
            pkt_list = self.toPacketList()
            sessions = pkt_list.sessions(self.sess_function)
            for k, sess in sessions.items():
                packet_times = [packet.time for packet in sess]
                if k == "Other" or "Ethernet" in k or "ARP" in k:
                    # print('Got one!')
                    continue
                if len(packet_times) < 2:
                    continue
                if pkt.time - min(packet_times) >= self.flow_timeout:
                    self.callback(sess)
                    continue

        # First, defragment IP if necessary
        pkt = self._ip_process_packet(pkt)
        # Now handle TCP reassembly
        pkt = self._process_packet(pkt)

        if not pkt:
            return
        
        DefaultSession.on_packet_received(self, pkt)

        if self.callback is not None:
            if TCP in pkt:
                if pkt[TCP].flags.F or pkt[TCP].flags.R:
                    pkt_list = self.toPacketList()
                    sessions = pkt_list.sessions(self.sess_function)
                    sess_pkts, = [plist for plist in sessions.values() if pkt in plist]
                    self.callback(sess_pkts)
                return
        
