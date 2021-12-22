# from scapy.all import *
from scapy.layers.inet import TCP, IP, UDP
from scapy.sendrecv import sniff
from scapy.utils import PcapReader
from joblib import Parallel, delayed
import signal
from lockfile import LockFile
import pandas as pd
import numpy as np
import binascii
import gc
import itertools

class Flowmeter:

    """
    This is the flowmeter class. It's purpose is to
    take in a pcap file and output a csv file
    containing 84 features to be used in machine
    learning applications.
    """
    
    def __init__(self, offline=None, outfunc=None, outfile=None, buffsize=1024):
        
        """
        Args:
            offline (str): OS location to a pcap file.
            outfunc: Function to send csv string to; if none supplied, print is used.
            outfile: (str): file to catpture csv output
        """
        if outfunc is None:
            outfunc = print
        self.outfunc = outfunc
        self.offline = offline
        self.outfile = outfile
        self.buffsize=buffsize
        self._sess_frames = dict()
        self.columns = [
            "flow",                 # Index
            "src",                  # Source IP
            "src_port",             # Source port
            "dst",                  # Destination IP
            "dst_port",             # Destination port
            "protocol",             # Protocol
            "timestamp",            # Timestamp
            "duration",	            # Duration of the flow in Microsecond

            "total_fpackets",	    # Total packets in the forward direction
            "total_bpackets",	    # Total packets in the backward direction
            "total_fpktl",	        # Total size of packet in forward direction
            "total_bpktl",	        # Total size of packet in backward direction

            "min_fpktl",	        # Minimum size of packet in forward direction
            "max_fpktl",            # Maximum size of packet in forward direction
            "mean_fpktl",	        # Mean size of packet in forward direction
            "std_fpktl",	        # Standard deviation size of packet in forward direction

            "min_bpktl",	        # Minimum size of packet in backward direction
            "max_bpktl",	        # Maximum size of packet in backward direction
            "mean_bpktl",	        # Mean size of packet in backward direction
            "std_bpktl",	        # Standard deviation size of packet in backward direction

            "flowBytesPerSecond",	# Number of flow bytes per second
            "flowPktsPerSecond",	# Number of flow packets per second

            "mean_flowiat",	        # Mean inter-arrival time of packet
            "std_flowiat",	        # Standard deviation inter-arrival time of packet
            "max_flowiat",	        # Maximum inter-arrival time of packet
            "min_flowiat",	        # Minimum inter-arrival time of packet

            "total_fiat",	        # Total time between two packets sent in the forward direction
            "mean_fiat",	        # Mean time between two packets sent in the forward direction
            "std_fiat", 	        # Standard deviation time between two packets sent in the forward direction
            "max_fiat", 	        # Maximum time between two packets sent in the forward direction
            "min_fiat", 	        # Minimum time between two packets sent in the forward direction

            "total_biat",	        # Total time between two packets sent in the backward direction
            "mean_biat",	        # Mean time between two packets sent in the backward direction
            "std_biat", 	        # Standard deviation time between two packets sent in the backward direction
            "max_biat", 	        # Maximum time between two packets sent in the backward direction
            "min_biat", 	        # Minimum time between two packets sent in the backward direction

            "fpsh_cnt", 	        # Number of times the PSH flag was set in packets travelling in the forward direction (0 for UDP)
            "bpsh_cnt", 	        # Number of times the PSH flag was set in packets travelling in the backward direction (0 for UDP)

            "furg_cnt", 	        # Number of times the URG flag was set in packets travelling in the forward direction (0 for UDP)
            "burg_cnt", 	        # Number of times the URG flag was set in packets travelling in the backward direction (0 for UDP)

            "total_fhlen",	        # Total bytes used for headers in the forward direction
            "total_bhlen",	        # Total bytes used for headers in the forward direction

            "fPktsPerSecond",	    # Number of forward packets per second
            "bPktsPerSecond",	    # Number of backward packets per second

            "min_flowpktl", 	    # Minimum length of a flow
            "max_flowpktl",	        # Maximum length of a flow
            "mean_flowpktl",	    # Mean length of a flow
            "std_flowpktl", 	    # Standard deviation length of a flow
            "var_flowpktl",         # Variance of length of a flow

            "flow_fin", 	        # Number of packets with FIN
            "flow_syn", 	        # Number of packets with SYN
            "flow_rst", 	        # Number of packets with RST
            "flow_psh", 	        # Number of packets with PUSH
            "flow_ack", 	        # Number of packets with ACK
            "flow_urg", 	        # Number of packets with URG
            "flow_cwr", 	        # Number of packets with CWR
            "flow_ece", 	        # Number of packets with ECE

            "downUpRatio",	        # Download and upload ratio

            "avgPacketSize",	    # Average size of packet
            "fAvgSegmentSize",	    # Average size observed in the forward direction
            "bAvgSegmentSize",	    # Average size observed in the backward direction

            "fAvgBytesPerBulk",	    # Average number of bytes bulk rate in the forward direction
            "fAvgPacketsPerBulk",	# Average number of packets bulk rate in the forward direction
            "fAvgBulkRate", 	    # Average number of bulk rate in the forward direction

            "bAvgBytesPerBulk",	    # Average number of bytes bulk rate in the backward direction
            "bAvgPacketsPerBulk",	# Average number of packets bulk rate in the backward direction
            "bAvgBulkRate", 	    # Average number of bulk rate in the backward direction
            
            "fSubFlowAvgPkts",
            "fSubFlowAvgBytes",
            "bSubFlowAvgPkts",
            "bSubFlowAvgBytes",

            'fInitWinSize',
            'bInitWinSize',
            'fDataPkts',
            'fHeaderSizeMin',

            'mean_active_s',
            'std_active_s',
            'max_active_s',
            'min_active_s',

            'mean_idle_s',
            'std_idle_s',
            'max_idle_s',
            'min_idle_s',

            "label",                # Classification Label
        ]
        self._frames = []

        if outfile is not None:
            with open(outfile, 'wt') as f:
                f.write(','.join(self.columns) + '\n')

    
    def process_session(self, session_df):
        for column in session_df.columns:
            session_df[column] = session_df[column].replace(r'\s+', np.nan, regex=True)
            session_df[column] = session_df[column].fillna(0)
        out_string = session_df.to_csv(header=False, index=False, line_terminator='\n')
        self.outfunc(out_string)
        if self.outfile is not None:
            lock = LockFile(self.outfile)
            lock.acquire()
            with open(self.outfile, 'at', newline='') as f:
                f.write(out_string)
            lock.release()

    def run(self):
        session_kwargs = dict(
            callback=self.process_session,
            sess_function=self._get_sessions
        )

        if self.offline:
            reader = PcapReader(self.offline)
            Parallel(-1)(delayed(self.process_packet)(packet) for packet in reader)

        else:
            print('Sniffing; ctrl+c to stop.') 
            results = sniff(prn=self.process_packet)
            print('Stopping...')
            for packet in results:
                self.process_packet
        
        
    def empty(self):
        keys = list(self._sess_frames.keys())
        for flow in keys:
            self.process_session(self._build_feature_from_flow(self._sess_frames.pop(flow)))
        

    def _get_sessions(self, packet):

        """
        This function takes in packets and builds
        bi-directional flows between source and
        destinations.

        This is to be used in conjuction with a
        scapy PacketList object.

        Example:

        packet_capture = rdpcap(test.pcap)
        session_flows = packet_capture.sessions(_get_sessions)

        Args:
            packet (packet): A packet placeholder handled by scapy.

        Returns a dictionary with session information as the key
        and the corresponding bi-directional PacketList object

        Example Output:

            {
            "['192.168.86.21', '192.168.86.22', 60604, 8009, 'TCP']": <PacketList: TCP:6 UDP:0 ICMP:0 Other:0>, 
            "['192.168.86.21', '34.212.215.14', 443, 60832, 'TCP']": <PacketList: TCP:9 UDP:0 ICMP:0 Other:0>
            }

        """
        sess = "Other"
        if "Ether" in packet:
            if "IP" in packet:
                if "TCP" in packet:
                    sess = str(sorted(["TCP", packet["IP"].src, packet["TCP"].sport,
                                    packet["IP"].dst, packet["TCP"].dport], key=str))
                elif "UDP" in packet:
                    sess = str(sorted(["UDP", packet["IP"].src, packet["UDP"].sport,
                                    packet["IP"].dst, packet["UDP"].dport], key=str))
                elif "ICMP" in packet:
                    sess = str(sorted(["ICMP", packet["IP"].src, packet["IP"].dst,
                                    packet["ICMP"].code, packet["ICMP"].type, packet["ICMP"].id], key=str))
                else:
                    sess = str(sorted(["IP", packet["IP"].src, packet["IP"].dst,
                                    packet["IP"].proto], key=str))
            elif "ARP" in packet:
                sess = str(sorted(["ARP", packet["ARP"].psrc, packet["ARP"].pdst], key=str))
            else:
                sess = packet.sprintf("Ethernet type = %04xr,Ether.type%")
        return sess

    def build_dataframe(self, packet_list):

        """
        This function takes in a scapy PacketList object and 
        builds a pandas dataframe.

        Args:
            packet_list (PacketList): A scapy PacketList object.
        
        """
        ip_fields = [field.name for field in IP().fields_desc]
        tcp_fields = [field.name for field in TCP().fields_desc]
        # udp_fields = [field.name for field in UDP().fields_desc if field.name not in tcp_fields]

        dataframe_fields = ip_fields + ['time', 'protocol'] + tcp_fields + ['size','payload','payload_raw','payload_hex'] 

        # Create blank DataFrame
        df = pd.DataFrame(columns=dataframe_fields)
        for packet in packet_list[IP]:
            # Field array for each row of DataFrame
            field_values = []
            # Add all IP fields to dataframe
            for field in ip_fields:
                if field == 'options':
                    # Retrieving number of options defined in IP Header
                    field_values.append(len(packet[IP].fields[field]))
                else:
                    field_values.append(packet[IP].fields[field])

            field_values.append(packet.time)
            layer_type = type(packet[IP].payload)

            field_values.append(layer_type().name)
            for field in tcp_fields:
                try:
                    if field == 'options':
                        field_values.append(len(packet[layer_type].fields[field]))
                    else:
                        field_values.append(packet[layer_type].fields[field])
                    
                except:
                    field_values.append(None)
            
            # Append payload
            field_values.append(len(packet))
            field_values.append(len(packet[layer_type].payload))
            field_values.append(packet[layer_type].payload.original)
            field_values.append(binascii.hexlify(packet[layer_type].payload.original))
            # Add row to DF
            df_append = pd.DataFrame([field_values], columns=dataframe_fields)
            df = pd.concat([df, df_append], axis=0)
            
        # Reset Index
        df = df.reset_index()
        # Drop old index column
        df = df.drop(columns="index")
        return df

    def build_dataframe_row(self, packet):

        """
        This function takes in a scapy PacketList object and 
        builds a pandas dataframe.

        Args:
            packet_list (PacketList): A scapy PacketList object.
        
        """
        ip_fields = [field.name for field in IP().fields_desc]
        tcp_fields = [field.name for field in TCP().fields_desc]
        # udp_fields = [field.name for field in UDP().fields_desc if field.name not in tcp_fields]

        dataframe_fields = ip_fields + ['time', 'protocol'] + tcp_fields + ['size','payload','payload_raw','payload_hex'] 

        # Create blank DataFrame
        # df = pd.DataFrame(columns=dataframe_fields)
        # Field array for each row of DataFrame
        field_values = []
        # Add all IP fields to dataframe
        for field in ip_fields:
            if field == 'options':
                # Retrieving number of options defined in IP Header
                field_values.append(len(packet[IP].fields[field]))
            else:
                field_values.append(packet[IP].fields[field])

        field_values.append(packet.time)
        layer_type = type(packet[IP].payload)

        field_values.append(layer_type().name)
        for field in tcp_fields:
            try:
                if field == 'options':
                    field_values.append(len(packet[layer_type].fields[field]))
                else:
                    field_values.append(packet[layer_type].fields[field])
                
            except:
                field_values.append(None)
        
        # Append payload
        field_values.append(len(packet))
        field_values.append(len(packet[layer_type].payload))
        field_values.append(packet[layer_type].payload.original)
        field_values.append(binascii.hexlify(packet[layer_type].payload.original))
        return dataframe_fields, field_values

    def build_sessions(self):
			  
        """
        This function returns dictionary of bi-directional
        flows.

        """
        return self._pcap.sessions(self._get_sessions)

    def get_src_ip(self, df):

        """
        This function should take in a pandas dataframe object
        that contains all the information for a single bi-directional
        flow. It will return the source IP address of the flow.

        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        
        """
        return df["src"].unique().tolist()[0]

    def get_dst_ip(self, df):

        """
        This function should take in a pandas dataframe object
        that contains all the information for a single bi-directional
        flow. It will return the destination IP address of the flow.

        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        
        """
        
        if df["src"].unique().shape[0] == 2:
            self.multicast_flag = 0
            return df["src"].unique().tolist()[1]
        else:
            self.multicast_flag = 1
            return df["dst"].unique().tolist()[0]
		
    def get_flow_duration(self, df):
        
        """
        This function returns the total time for the session flow.
        """

        if df.shape[0] == 1:
            return 1
        df["date_time"] = pd.to_datetime(df["time"].astype(float), unit="s")
        duration = (df.date_time.max() - df.date_time.min()) / np.timedelta64(1, 's')
        return duration

		
    def get_total_len_forward_packets(self, df):
        
        """
        This function calculates the total length of all packets that
        originated from the source IP address
        
        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
			
        """
        
        src = self.get_src_ip(df)
        src_df = df.loc[df["src"]==src]
        return src_df["size"].sum()
		
    
    def get_total_len_backward_packets(self, df):
	
        """
        This function calculates the total length of all packets that
        originated from the destination IP address
        
        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
			
        """

        if self.multicast_flag == 1:
            return 0
        
        src = self.get_dst_ip(df)
        src_df = df.loc[df["src"]==src]
        
        return src_df["size"].sum()
	
    def get_total_forward_packets(self, df):
    
        """
        This function calculates the total number of packets that
        originated from the source IP address

        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """
    
        src = self.get_src_ip(df)
        return  df.loc[df['src']==src].shape[0]

    
    def get_total_backward_packets(self, df):
    
        """
        This function calculates the total number of packets that
        originated from the destination IP address
        
        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """
    
        src = self.get_dst_ip(df)
        return  df.loc[df['src']==src].shape[0]

    def get_min_forward_packet_size(self, df):
    
        """
        This function calculates the minimum payload size that
        originated from the source IP address
        
        Args:
        df (Dataframe): A bi-directional flow pandas dataframe.
        """
    
        src = self.get_src_ip(df)
        src_df = df.loc[df["src"]==src]
        return  min(src_df["size"])

    def get_min_backward_packet_size(self, df):
    
        """
        This function calculates the minimum payload size that
        originated from the destination IP address
        
        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """
    
        src = self.get_dst_ip(df)
        src_df = df.loc[df["src"]==src]
        if self.multicast_flag == 1:
            return 0
        else:
            return  min(src_df["size"])

    def get_max_forward_packet_size(self, df):
    
        """
        This function calculates the maximum payload size that
        originated from the source IP address
        
        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """
    
        src = self.get_src_ip(df)
        src_df = df.loc[df["src"]==src]
        return  max(src_df["size"])

    def get_max_backward_packet_size(self, df):
    
        """
        This function calculates the maximum payload size that
        originated from the destination IP address
        
        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """
    
        src = self.get_dst_ip(df)
        src_df = df.loc[df["src"]==src]
        if self.multicast_flag == 1:
            return 0
        else:
            return  max(src_df["size"])

    def get_mean_forward_packet_size(self, df):
    
        """
        This function calculates the mean payload size that
        originated from the source IP address
        
        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """
    
        src = self.get_src_ip(df)
        src_df = df.loc[df["src"]==src]
        return  src_df["size"].mean()

    def get_mean_backward_packet_size(self, df):
    
        """
        This function calculates the mean payload size that
        originated from the destination IP address
        
        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """
    
        src = self.get_dst_ip(df)
        src_df = df.loc[df["src"]==src]
        return  src_df["size"].mean()
    
    def get_std_forward_packet_size(self, df):
    
        """
        This function calculates the standard deviation of payload sizes that
        originated from the source IP address
        
        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """
    
        src = self.get_src_ip(df)
        src_df = df.loc[df["src"]==src]
        return  src_df["size"].std()

    def get_std_backward_packet_size(self, df):
    
        """
        This function calculates the standard deviaton of payload sizes that
        originated from the destination IP address
            
        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """
        
        src = self.get_dst_ip(df)
        src_df = df.loc[df["src"]==src]
        return  src_df["size"].std()

    def get_iat_forward_total_time(self, df):
    
        """
        This function calculates the total inter arrival 
        time (iat) of packets from the source IP address.
            
        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """

        src = self.get_src_ip(df)
        src_df = df.loc[df["src"]==src]
        return  src_df['time'].sort_values().diff().sum() 

    def get_iat_backward_total_time(self, df):
    
        """
        This function calculates the total inter arrival 
        time (iat) of packets from the destination IP address.
            
        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """

        src = self.get_dst_ip(df)
        src_df = df.loc[df["src"]==src]
        return  src_df['time'].sort_values().diff().sum() 

    def get_src_times(self, df):
    
        """
        This function returns the "time" Series object 
        from the passed in dataframe for the session
        source.
            
        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """
        
        src = self.get_src_ip(df)
        src_df = df.loc[df["src"]==src]
        return  src_df["time"]

    def get_dst_times(self, df):
        
        """
        This function returns the "time" Series object 
        from the passed in dataframe for the session
        destination.
            
        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """
        
        src = self.get_dst_ip(df)
        src_df = df.loc[df["src"]==src]
        return  src_df["time"]

    def get_iat_forward_min_times(self, df):
    
        """
        This function returns the minimum inter arrival
        time (IAT) between packets from the source.
            
        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """
        
        src_times = self.get_src_times(df)
        if src_times.shape[0] > 1:
            return  min(src_times.diff().dropna()) 
        else:
            return src_times.tolist()[0]

    def get_iat_backwards_min_times(self, df):
        
        """
        This function returns the minimum inter arrival
        time (IAT) between packets from the destination.
            
        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """
        
        src_times = self.get_dst_times(df)
        if self.multicast_flag == 1 or src_times.shape[0] == 1:
            return 0 # Test
        else:
            return  min(src_times.diff().dropna().tolist()) 

    def get_iat_forward_max_times(self, df):
    
        """
        This function returns the maximum inter arrival
        time (IAT) between packets from the source.
            
        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """
        
        src_times = self.get_src_times(df)
        if src_times.shape[0] > 1:
            return  max(src_times.diff().dropna().tolist()) 
        else:
            return src_times.tolist()[0]

    def get_iat_backwards_max_times(self, df):
        
        """
        This function returns the maximum inter arrival
        time (IAT) between packets from the destination.
            
        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """
        
        src_times = self.get_dst_times(df)
        return  max(src_times.diff().dropna()) 

    def get_iat_forward_mean_times(self, df):
        
        """
        This function returns the mean inter arrival
        time (IAT) between packets from the source.
            
        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """
        
        src_times = self.get_src_times(df)
        return  src_times.diff().dropna().mean() 

    def get_iat_backwards_mean_times(self, df):
        
        """
        This function returns the mean inter arrival
        time (IAT) between packets from the destination.
            
        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """
        
        src_times = self.get_dst_times(df)
        return  src_times.diff().dropna().mean() 

    def get_iat_forward_std_times(self, df):
    
        """
        This function returns the standard deviation for inter arrival
        time (IAT) between packets from the source.
            
        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """
        
        src_times = self.get_src_times(df)
        return  src_times.diff().dropna().std() 

    def get_iat_backwards_std_times(self, df):
        
        """
        This function returns the standard deviation inter arrival
        time (IAT) between packets from the destination.
            
        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """
        
        src_times = self.get_dst_times(df)
        return  src_times.diff().dropna().std() 

    def remove_duplicate_flags_col(self, df):
    
        """
        This function removes the first occurence
        of the 'flags' column due to multiple
        columns named 'flags'
            
        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """
        
        column_numbers = [x for x in range(df.shape[1])]
        column_numbers.remove(5)
        return df.iloc[:, column_numbers]

    def decode_flags(self, df):
    
        """
        This function decodes the bitwise flag
        into a string.
            
        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
            
        """
        
        return df["flags"].astype(str)

    def count_flags(self, df, ip, flag):
        
        """
        This function counts the total number of
        flags from the specified origin.
            
        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
            ip (String): A string representation of the IP address
            flag (String): The first letter of the flag to search.
        """
        
        df = df.loc[df["src"]==ip]
        has_flags = self.decode_flags(df).str.contains(flag)
        return has_flags.sum()

    def get_total_forward_push_flags(self, df):
    
        """
        This function calculates the total number of
        push flags in the forward direction.
            
        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """
        
        
        df = self.remove_duplicate_flags_col(df)
        src = self.get_src_ip(df)
        return self.count_flags(df, src, "P")

    def get_total_backward_push_flags(self, df):
        
        """
        This function calculates the total number of
        push flags in the forward direction.
            
        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """
        
        
        df = self.remove_duplicate_flags_col(df)
        src = self.get_dst_ip(df)
        return self.count_flags(df, src, "P")

    def get_total_forward_urgent_flags(self, df):
    
        """
        This function calculates the total number of
        urgent flags in the forward direction.
            
        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """
        
        
        df = self.remove_duplicate_flags_col(df)
        src = self.get_src_ip(df)
        return self.count_flags(df, src, "U")

    def get_total_backward_urgent_flags(self, df):
        
        """
        This function calculates the total number of
        urgent flags in the forward direction.
            
        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """
        
        
        df = self.remove_duplicate_flags_col(df)
        src = self.get_dst_ip(df)
        return self.count_flags(df, src, "U")

    def get_total_header_len_forward_packets(self, df):
    
        """
        This function calculates the total size
        of headers in the forward direction.
            
        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """
            
        src = self.get_src_ip(df)
        src_df = df[df["src"]==src]
        return src_df["size"].sum() - self.get_total_len_forward_packets(df)

    def get_total_header_len_backward_packets(self, df):
        
        """
        This function calculates the total size
        of headers in the backward direction.
            
        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """
        
        src = self.get_dst_ip(df)
        src_df = df[df["src"]==src]
        if self.multicast_flag == 1:
            return 0
        else:
            return src_df["size"].sum() - self.get_total_len_backward_packets(df)

    def get_forward_packets_per_second(self, df):
    
        """
        This function calculates number of packets
        per second in the forward direction.
        
        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """
        if df.shape[0] > 1:
            duration = self.get_flow_duration(df)
            if duration > 0:
                return self.get_total_forward_packets(df) / duration
            else:
                return 0
        else:
             return 1

    def get_backward_packets_per_second(self, df):
        
        """
        This function calculates number of packets
        per second in the forward direction.
            
        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """

        if df.shape[0] > 1:
            duration = self.get_flow_duration(df)
            if duration > 0:
                return self.get_total_backward_packets(df) / duration
            else:
                return 0
        else:
             return 1

    def get_flow_packets_per_second(self, df):
    
        """
        This function calculates number of packets
        per second in the flow.
            
        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """
        if df.shape[0] > 1:
            duration = self.get_flow_duration(df)
            if duration > 0:
                return (self.get_total_backward_packets(df) + self.get_total_forward_packets(df)) / duration
            else:
                return 0
        else:
            return 1

    def get_flow_bytes_per_second(self, df):
    
        """
        This function calculates number of bytes
        per second in the flow.
            
        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """
        duration = self.get_flow_duration(df)
        if duration > 0:
            return (self.get_total_len_forward_packets(df) + self.get_total_len_backward_packets(df)) / duration
        else:
            return 0

    def get_min_flow_packet_size(self, df):
    
        """
        This function calculates the minimum payload size that
        originated from flow.
        
        Args:
        df (Dataframe): A bi-directional flow pandas dataframe.
        """
    
        return  min(df["size"])
        
    def get_max_flow_packet_size(self, df):
        
        """
        This function calculates the maximum payload size that
        originated from the flow.
        
        Args:
        df (Dataframe): A bi-directional flow pandas dataframe.
        """
    
        return  max(df["size"])

    def get_mean_flow_packet_size(self, df):
    
        """
        This function calculates the mean payload size that
        originated from flow.
        
        Args:
        df (Dataframe): A bi-directional flow pandas dataframe.
        """
    
        return  df["size"].mean()
    
    def get_std_flow_packet_size(self, df):

        """
        This function calculates the payloads tandard deviation size that
        originated from the flow.
        
        Args:
        df (Dataframe): A bi-directional flow pandas dataframe.
        """

        return  df["size"].std()

    def get_var_flow_packet_size(self, df):
        return df['size'].var()

    def get_min_flow_iat(self, df):
    
        """
        This function calculates the min inter arival time
        from the flow.
        
        Args:
        df (Dataframe): A bi-directional flow pandas dataframe.
        """
        if df.shape[0] > 1:
            return  min(df['time'].sort_values().astype(float).diff().dropna())
        else:
            return 0
    
    def get_max_flow_iat(self, df):
    
        """
        This function calculates the max inter arival time
        from the flow.
        
        Args:
        df (Dataframe): A bi-directional flow pandas dataframe.
        """
    
        if df.shape[0] > 1:
            return  max(df['time'].sort_values().astype(float).diff().dropna())
        else:
            return 0


    def get_mean_flow_iat(self, df):
    
        """
        This function calculates the mean inter arival time
        from the flow.
        
        Args:
        df (Dataframe): A bi-directional flow pandas dataframe.
        """
    
        #src_times = get_src_times(df)
        return df['time'].sort_values().astype(float).diff().dropna().mean()
    
    def get_std_flow_iat(self, df):
    
        """
        This function calculates the inter arival time
        standard deviation from the flow.
        
        Args:
        df (Dataframe): A bi-directional flow pandas dataframe.
        """
    
        return  df['time'].sort_values().astype(float).diff().dropna().std()

    def get_total_flow_push_flags(self, df):
    
        """
        This function calculates the total number
        of push flags in the flow.

        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """
        
        df = self.remove_duplicate_flags_col(df)
        src = self.get_src_ip(df)
        dst = self.get_dst_ip(df)
        return self.count_flags(df, src, "P") + self.count_flags(df, dst, "P")


    def get_total_flow_fin_flags(self, df):
        
        """
        This function calculates the total number
        of finish flags in the flow.

        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """
        
        df = self.remove_duplicate_flags_col(df)
        src = self.get_src_ip(df)
        dst = self.get_dst_ip(df)
        return self.count_flags(df, src, "F") + self.count_flags(df, dst, "F")

    def get_total_flow_syn_flags(self, df):
    
        """
        This function calculates the total number
        of syn flags in the flow.

        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """
        
        df = self.remove_duplicate_flags_col(df)
        src = self.get_src_ip(df)
        dst = self.get_dst_ip(df)
        return self.count_flags(df, src, "S") + self.count_flags(df, dst, "S")


    def get_total_flow_reset_flags(self, df):
        
        """
        This function calculates the total number
        of reset flags in the flow.

        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """
        
        df = self.remove_duplicate_flags_col(df)
        src = self.get_src_ip(df)
        dst = self.get_dst_ip(df)
        return self.count_flags(df, src, "R") + self.count_flags(df, dst, "R")

    def get_total_flow_ack_flags(self, df):
        
        """
        This function calculates the total number
        of ack flags in the flow.

        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """
        
        df = self.remove_duplicate_flags_col(df)
        src = self.get_src_ip(df)
        dst = self.get_dst_ip(df)
        return self.count_flags(df, src, "A") + self.count_flags(df, dst, "A")


    def get_total_flow_urg_flags(self, df):
        
        """
        This function calculates the total number
        of urgent flags in the flow.

        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """
        
        df = self.remove_duplicate_flags_col(df)
        src = self.get_src_ip(df)
        dst = self.get_dst_ip(df)
        return self.count_flags(df, src, "U") + self.count_flags(df, dst, "U")

    def get_total_flow_cwr_flags(self, df):
    
        """
        This function calculates the total number
        of cwr flags in the flow.

        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """
        
        df = self.remove_duplicate_flags_col(df)
        src = self.get_src_ip(df)
        dst = self.get_dst_ip(df)
        return self.count_flags(df, src, "C") + self.count_flags(df, dst, "C")


    def get_total_flow_ece_flags(self, df):
        
        """
        This function calculates the total number
        of ece flags in the flow.

        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """
        
        df = self.remove_duplicate_flags_col(df)
        src = self.get_src_ip(df)
        dst = self.get_dst_ip(df)
        return self.count_flags(df, src, "E") + self.count_flags(df, dst, "E")

    def get_average_burst_rate(self, df, window=100):
    
        """
        This is a helper function calculates the average burst rate
        based on the number of packets sent in the 
        burst window.
        
        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
            window (Int): The number in milliseconds to calculate the burst rate
        """
        if self.multicast_flag == 1:
            return 0 

        a = pd.DataFrame()
        a["time"] = pd.to_datetime(df["time"].astype(float).sort_values(), unit="s")
        a["count"] = 1
        a.set_index(["time"], inplace=True)
        a["rolling"] = a.rolling('100ms').sum()
        return a["rolling"].mean()

    def get_average_forward_bytes_per_burt(self, df, window=100):
    
        """
        This finds the average bytes per burst
        that originated from the source.
        
        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
            window (Int): The number in milliseconds to calculate the burst rate
        """
        
        if self.multicast_flag == 1:
            return 0
        src = self.get_src_ip(df)
        src_df = df[df["src"]==src]
        src_burst_rate = self.get_average_burst_rate(src_df)
        src_bytes = self.get_total_len_forward_packets(src_df)
        return src_bytes / src_burst_rate


    def get_average_backward_bytes_per_burt(self, df, window=100):
        
        """
        This finds the average bytes per burst
        that originated from the destination.
        
        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
            window (Int): The number in milliseconds to calculate the burst rate
        """

        src = self.get_dst_ip(df)
        src_df = df[df["src"]==src]
        src_burst_rate = self.get_average_burst_rate(src_df)
        src_bytes = self.get_total_len_backward_packets(src_df)
        if self.multicast_flag == 1:
            return 0
        else:
            return src_bytes / src_burst_rate

    def get_upload_download_ratio(self, df):
    
        """
        This finds the upload to download ratio.
        
        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """
        if self.multicast_flag == 1:
            return 1
        else:
            return self.get_total_len_forward_packets(df) / self.get_total_len_backward_packets(df)

    def get_avg_packet_size(self, df):
    
        """
        This finds the average packet size
        
        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """
        
        return df["size"].mean()

    def get_avg_forward_segment_size(self, df):
    
        """
        This finds the average segment size in
        the forward direction.
        
        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """
        
        src = self.get_src_ip(df)
        src_df = df[df["src"]==src]
        
        return src_df["payload"].mean()

    def get_avg_backward_segment_size(self, df):
        
        """
        This finds the average segment size in
        the forward direction.
        
        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """
        
        src = self.get_dst_ip(df)
        src_df = df[df["src"]==src]
        
        return src_df["payload"].mean()

    def get_avg_forward_burst_packets(self, df):
    
        """
        This finds the average packets sent in burst
        originating from the source.
        
        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """
        
        src = self.get_src_ip(df)
        src_df = df[df["src"]==src]
        
        return self.get_average_burst_rate(src_df)

    def get_avg_backward_burst_packets(self, df):
        
        """
        This finds the average packets sent in burst
        originating from the source.
        
        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """
        
        src = self.get_dst_ip(df)
        src_df = df[df["src"]==src]
        
        return self.get_average_burst_rate(src_df)

    def get_avg_forward_in_total_burst(self, df):
    
        """
        This finds the average packets sent in burst
        originating from the source.
        
        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """
        
        if self.multicast_flag == 1:
            return 0

        src = self.get_src_ip(df)
        src_df = df[df["src"]==src]
        
        return self.get_average_burst_rate(src_df) / self.get_average_burst_rate(df)

    def get_avg_backward_in_total_burst(self, df):
        
        """
        This finds the average packets sent in burst
        originating from the source.
        
        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """
        
        if self.multicast_flag == 1:
            return 0

        src = self.get_dst_ip(df)
        src_df = df[df["src"]==src]
        
        return self.get_average_burst_rate(src_df) / self.get_average_burst_rate(df)

    def get_src_port(self, df):
    
        """
        This finds the source port in the flow.
        
        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """
    
        row = df.iloc[0,]
        return row[["src", "sport", "dst", "dport"]].tolist()[1]

    def get_dst_port(self, df):
    
        """
        This finds the destination port in the flow.
        
        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """
    
        row = df.iloc[0,]
        return row[["src", "sport", "dst", "dport"]].tolist()[3]

    def get_protocol(self, df):
    
        """
        This returns the flow's protocol.
        
        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """
    
        row = df.iloc[0,]
        return row["protocol"]

    def get_timestamp(self, df):
        return str(pd.to_datetime(df['time'].astype(float), unit='s').min())

    def get_timedelta_ns(self, df):
        sorted_time = df['time'].astype(float).sort_values()
        time_delta = (sorted_time - sorted_time.shift(1).fillna(sorted_time)).values[1:].astype(float)
        return time_delta

    def get_n_subflows(self, df):
        time_delta = self.get_timedelta_ns(df)
        n_subflows = (time_delta > 1e9).sum() + 1
        return n_subflows

    def get_fwd_subflow_packets(self, df):
        subflows = self.get_n_subflows(df)
        fwd_packets = self.get_total_forward_packets(df)
        return fwd_packets / subflows

    def get_bwd_subflow_packets(self, df):
        subflows = self.get_n_subflows(df)
        bwd_packets = self.get_total_backward_packets(df)
        return bwd_packets / subflows

    def get_fwd_subflow_bytes(self, df):
        subflows = self.get_n_subflows(df)
        fwd_bytes = self.get_total_len_forward_packets(df)
        return fwd_bytes / subflows

    def get_bwd_subflow_bytes(self, df):
        subflows = self.get_n_subflows(df)
        bwd_bytes = self.get_total_len_backward_packets(df)
        return bwd_bytes / subflows

    def get_period_lengths(self, df, idle_threshold_s):

        # Get a list of time deltas between consecutive packets
        time_delta_s = self.get_timedelta_ns(df) / 1e9

        # Determine whether each delta is less than the idle threshold
        is_active = time_delta_s <= idle_threshold_s

        # Find the indices where it goes from active to inactive
        swaps = is_active[:-1] ^ is_active[1:]
        
        # That gets us the last index of each period. We want
        # the first index of the next one.
        swap_index = np.where(swaps)[0] + 1

        # Now we need to add 0 and len(time_delta_ns) so that 
        # we have start and end points
        swap_index = np.hstack([0, swap_index, len(time_delta_s)])

        # Make slices that represent the start and finish of each period
        active_slices = [slice(start, stop) for start, stop in zip(swap_index[::2], swap_index[1::2])]
        idle_slices = [slice(start, stop) for start, stop in zip(swap_index[1::2], swap_index[2::2])]

        # Get the sums of each period denoted by their slices
        active_periods = np.array([time_delta_s[slice_].sum() for slice_ in active_slices])
        idle_periods = np.array([time_delta_s[slice_].sum() for slice_ in idle_slices])

        return active_periods, idle_periods

    def get_mean_active_sec(self, df):
        active_periods, _ = self.get_period_lengths(df, idle_threshold_s=5)
        return active_periods.mean()

    def get_std_active_sec(self, df):
        active_periods, _ = self.get_period_lengths(df, idle_threshold_s=5)
        return active_periods.std()

    def get_max_active_sec(self, df):
        active_periods, _ = self.get_period_lengths(df, idle_threshold_s=5)
        return active_periods.max()

    def get_min_active_sec(self, df):
        active_periods, _ = self.get_period_lengths(df, idle_threshold_s=5)
        return active_periods.min()

    def get_mean_idle_sec(self, df):
        _, idle_periods = self.get_period_lenghts(df, idle_threshold_s=5)
        return idle_periods.mean()

    def get_std_idle_sec(self, df):
        _, idle_periods = self.get_period_lenghts(df, idle_threshold_s=5)
        return idle_periods.std()

    def get_max_idle_sec(self, df):
        _, idle_periods = self.get_period_lenghts(df, idle_threshold_s=5)
        return idle_periods.max()

    def get_min_idle_sec(self, df):
        _, idle_periods = self.get_period_lenghts(df, idle_threshold_s=5)
        return idle_periods.min()

    def get_fwd_init_tcp_win(self, df):
        src = self.get_src_ip(df)
        src_df = df.loc[df["src"]==src].sort_values('time')
        if len(src_df) == 0:
            return 0

        row = src_df.iloc[0]
        return row['window']

    def get_bwd_init_tcp_win(self, df):
        src = self.get_dst_ip(df)
        src_df = df.loc[df["src"]==src].sort_values('time')
        if len(src_df) == 0:
            return 0

        row = src_df.iloc[0]
        return row['window']

    def get_fwd_data_packets(self, df):
        src = self.get_src_ip(df)
        src_df = df.loc[df["src"]==src].sort_values('time')
        if len(src_df) == 0:
            return 0

        data_pkt_count = (src_df['size'] > 0).sum()
        return data_pkt_count

    def get_fwd_header_min(self, df):
        src = self.get_src_ip(df)
        src_df = df.loc[df["src"]==src].sort_values('time')
        if len(src_df) == 0:
            return 0
        
        min_header_len = src_df['len'].min()
        return min_header_len

    def build_index(self, df):

        """
        This buids the index to be used in the dataframe
        
        Args:
            df (Dataframe): A bi-directional flow pandas dataframe.
        """

        src = self.get_src_ip(df)
        dst = self.get_dst_ip(df)
        src_df = df[df["src"]==src]
        dst_df = df[df["src"]==dst]
        src_port = src_df["sport"].unique()
        dst_port = dst_df["sport"].unique()
        
        if self.multicast_flag == 0:
            return ("{}:{}<->{}:{}").format(src,str(src_port[0]),dst,str(dst_port[0]))
        else:
            return ("{}:{}<->{}:{}").format(src,str(src_port[0]),dst,str(src_port[0]))

 
    def _build_feature_from_flow(self, flow_df):

        gc.collect()
        # print(("\nEntering {}").format(flow)) # Test

        result = pd.DataFrame(columns=self.columns)
        result["flow"] = [self.build_index(flow_df)]
        result["src"] = [self.get_src_ip(flow_df)]
        result["src_port"] = [self.get_src_port(flow_df)]
        result["dst"] = [self.get_dst_ip(flow_df)]
        result["dst_port"] = [self.get_dst_port(flow_df)]
        result["protocol"] = [self.get_protocol(flow_df)]
        result['timestamp'] = [self.get_timestamp(flow_df)]
        result["duration"] = [self.get_flow_duration(flow_df)]
        
        result["total_fpackets"] = [self.get_total_forward_packets(flow_df)]
        result["total_bpackets"] = [self.get_total_backward_packets(flow_df)]
        result["total_fpktl"] = [self.get_total_len_forward_packets(flow_df)]
        result["total_bpktl"] = [self.get_total_len_backward_packets(flow_df)]
        
        result["min_fpktl"] = [self.get_min_forward_packet_size(flow_df)]
        result["max_fpktl"] = [self.get_max_forward_packet_size(flow_df)]
        result["mean_fpktl"] = [self.get_mean_forward_packet_size(flow_df)]
        result["std_fpktl"] = [self.get_std_forward_packet_size(flow_df)]
        
        result["min_bpktl"] = [self.get_min_backward_packet_size(flow_df)]
        result["max_bpktl"] = [self.get_max_backward_packet_size(flow_df)]
        result["mean_bpktl"] = [self.get_mean_backward_packet_size(flow_df)]
        result["std_bpktl"] = [self.get_std_backward_packet_size(flow_df)]
        
        result["flowBytesPerSecond"] = [self.get_flow_bytes_per_second(flow_df)]
        result["flowPktsPerSecond"] = [self.get_flow_packets_per_second(flow_df)]
        
        result["mean_flowiat"] = [self.get_mean_flow_iat(flow_df)]
        result["std_flowiat"] = [self.get_std_flow_iat(flow_df)]
        result["max_flowiat"] = [self.get_max_flow_iat(flow_df)]
        result["min_flowiat"] = [self.get_min_flow_iat(flow_df)]
        
        result["total_fiat"] = [self.get_iat_forward_total_time(flow_df)]
        result["mean_fiat"] = [self.get_iat_forward_mean_times(flow_df)]
        result["std_fiat"] = [self.get_iat_forward_std_times(flow_df)]
        result["max_fiat"] = [self.get_iat_forward_max_times(flow_df)]
        result["min_fiat"] = [self.get_iat_forward_min_times(flow_df)]
        
        result["total_biat"] = [self.get_iat_backward_total_time(flow_df)]
        result["mean_biat"] = [self.get_iat_backwards_mean_times(flow_df)]
        result["std_biat"] = [self.get_iat_backwards_std_times(flow_df)]
        result["max_biat"] = [self.get_iat_forward_max_times(flow_df)]
        result["min_biat"] = [self.get_iat_backwards_min_times(flow_df)]
        
        result["fpsh_cnt"] = [self.get_total_forward_push_flags(flow_df)]
        result["bpsh_cnt"] = [self.get_total_backward_push_flags(flow_df)]
        
        result["furg_cnt"] = [self.get_total_forward_urgent_flags(flow_df)]
        result["burg_cnt"] = [self.get_total_backward_urgent_flags(flow_df)]
        
        result["total_fhlen"] = [self.get_total_header_len_forward_packets(flow_df)]
        result["total_bhlen"] = [self.get_total_header_len_backward_packets(flow_df)]
        
        result["fPktsPerSecond"] = [self.get_forward_packets_per_second(flow_df)]
        result["bPktsPerSecond"] = [self.get_backward_packets_per_second(flow_df)]
        
        result["min_flowpktl"] = [self.get_min_flow_packet_size(flow_df)]
        result["max_flowpktl"] = [self.get_max_flow_packet_size(flow_df)]
        result["mean_flowpktl"] = [self.get_mean_flow_packet_size(flow_df)]
        result["std_flowpktl"] = [self.get_std_flow_packet_size(flow_df)]
        result["var_flowpktl"] = [self.get_var_flow_packet_size(flow_df)]
        
        result["flow_fin"] = [self.get_total_flow_fin_flags(flow_df)]
        result["flow_syn"] = [self.get_total_flow_syn_flags(flow_df)]
        result["flow_rst"] = [self.get_total_flow_reset_flags(flow_df)]
        result["flow_psh"] = [self.get_total_flow_push_flags(flow_df)]
        result["flow_ack"] = [self.get_total_flow_ack_flags(flow_df)]
        result["flow_urg"] = [self.get_total_flow_urg_flags(flow_df)]
        result["flow_cwr"] = [self.get_total_flow_cwr_flags(flow_df)]
        result["flow_ece"] = [self.get_total_flow_ece_flags(flow_df)]
        
        result["downUpRatio"] = [self.get_upload_download_ratio(flow_df)]
        
        result["avgPacketSize"] = [self.get_avg_packet_size(flow_df)]
        result["fAvgSegmentSize"] = [self.get_avg_forward_segment_size(flow_df)]
        result["bAvgSegmentSize"] = [self.get_avg_backward_segment_size(flow_df)]
        
        result["fAvgBytesPerBulk"] = [self.get_average_forward_bytes_per_burt(flow_df)]
        result["fAvgPacketsPerBulk"] = [self.get_avg_forward_burst_packets(flow_df)]
        result["fAvgBulkRate"] = [self.get_avg_forward_in_total_burst(flow_df)]
        
        result["bAvgBytesPerBulk"] = [self.get_average_backward_bytes_per_burt(flow_df)]
        result["bAvgPacketsPerBulk"] = [self.get_avg_backward_burst_packets(flow_df)]
        result["bAvgBulkRate"] = [self.get_avg_backward_in_total_burst(flow_df)]
        
        result["fSubFlowAvgPkts"] = [self.get_fwd_subflow_packets(flow_df)]
        result["fSubFlowAvgBytes"] = [self.get_fwd_subflow_bytes(flow_df)]
        result["bSubFlowAvgPkts"] = [self.get_bwd_subflow_packets(flow_df)]
        result["bSubFlowAvgBytes"] = [self.get_bwd_subflow_bytes(flow_df)]
        
        result['fInitWinSize'] = [self.get_fwd_init_tcp_win(flow_df)]
        result['bInitWinSize'] = [self.get_bwd_init_tcp_win(flow_df)]
        result['fDataPkts'] = [self.get_fwd_data_packets(flow_df)]
        result['fHeaderSizeMin'] = [self.get_fwd_header_min(flow_df)]
        active_periods, idle_periods = self.get_period_lengths(flow_df, idle_threshold_s=5)
        if len(active_periods) > 0:
            result['mean_active_s'] = [active_periods.mean()]
            result['std_active_s'] = [active_periods.std()]
            result['max_active_s'] = [active_periods.max()]
            result['min_active_s'] = [active_periods.std()]
        else:
            result['mean_active_s'] = [0]
            result['std_active_s'] = [0]
            result['max_active_s'] = [0]
            result['min_active_s'] = [0]
        if len(idle_periods) > 0:
            result['mean_idle_s'] = [idle_periods.mean()]
            result['std_idle_s'] = [idle_periods.std()]
            result['max_idle_s'] = [idle_periods.max()]
            result['min_idle_s'] = [idle_periods.std()]
        else:
            result['mean_idle_s'] = [0]
            result['std_idle_s'] = [0]
            result['max_idle_s'] = [0]
            result['min_idle_s'] = [0]
            
        result["label"] = ["None"]
        #print(("\nAppending {}\n").format(result))
        return result
        #print(self._frames)


    def _build_sessions(self):
        gc.collect()
        return self.build_sessions()


    def process_packet(self, packet):        
        sess = self._get_sessions(packet)
        if sess == "Other" or "Ethernet" in sess or "ARP" in sess: 
            return
        fields, row = self.build_dataframe_row(packet)
        if sess not in self._sess_frames.keys():
            self._sess_frames[sess] = pd.DataFrame([row], columns=fields)
        else:
            self._sess_frames[sess] = self._sess_frames[sess].append(dict(zip(fields, row)), ignore_index=True)
        curr_df = self._sess_frames[sess]
        if TCP in packet:
            if packet[TCP].flags.F or packet[TCP].flags.R:
                self.process_session(self._build_feature_from_flow(self._sess_frames.pop(sess)))
        elif curr_df['time'].astype(float).max() - curr_df['time'].astype(float).min() > 120000:
            self.process_session(self._build_feature_from_flow(self._sess_frames.pop(sess)))
