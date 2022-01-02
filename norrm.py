import pandas as pd
import numpy as np
from rich.theme import Theme
from rich.console import Console

# dict of rich colors
# color used in project
ct = Theme({
    'good': "bold green ",
    'bad': "red",
    'blue': "blue",
    'yellow': "yellow",
    'purple': "purple",
    'magenta': "magenta",
    'cyan': "cyan"
})
rc = Console(record=True, theme=ct)


class Preprocessing:

    def __init__(self, df):
        self.df = df
        self.df.replace([np.inf, -np.inf], np.nan, inplace=True)
        self.df.dropna(inplace=True)

    def rm_col(self):
        del self.df['src_port']
        del self.df['mean_bpktl']
        del self.df['bpsh_cnt']
        del self.df['total_bpktl']
        del self.df['mean_active_s']
        del self.df['max_active_s']
        del self.df['downUpRatio']
        del self.df['flow']
        del self.df['src']
        del self.df['dst']
        del self.df['protocol']
        del self.df['timestamp']
        del self.df['std_biat']
        del self.df['furg_cnt']
        del self.df['burg_cnt']
        del self.df['total_bhlen']
        del self.df['flow_cwr']
        del self.df['flow_ece']
        del self.df['std_active_s']
        del self.df['min_active_s']
        del self.df['fAvgBytesPerBulk']
        del self.df['fAvgPacketsPerBulk']
        del self.df['bAvgPacketsPerBulk']
        del self.df['fAvgBulkRate']
        del self.df['bAvgBytesPerBulk']

        del self.df['bAvgBulkRate']
        del self.df['mean_biat']
        del self.df['min_biat']
        del self.df['label']
        return

    def r_csv(self, filename):
        df = pd.read_csv(filename, encoding='utf-8')
        return df

    def col_rename(self):

        self.dict = {'min_idle_s': 'Idle Min',
                     'max_idle_s': 'Idle Max',
                     'std_idle_s': 'Idle Std',
                     'mean_idle_s': 'Idle Mean',
                     'dst_port': 'Destination Port',
                     'duration': 'Duration',
                     'total_fpackets': 'Total Fwd Packets',
                     'total_bpackets': 'Total Backward Packets',
                     'total_fpktl': 'Total Length of Fwd Packets',
                     'min_fpktl': 'Fwd Packet Length Min',
                     'max_fpktl': 'Fwd Packet Length Max',
                     'mean_fpktl': 'Fwd Packet Length Mean',
                     'std_fpktl': 'Fwd Packet Length Std',
                     'min_bpktl': 'Bwd Packet Length Min',
                     'max_bpktl': 'Bwd Packet Length Max',
                     'std_bpktl': 'Bwd Packet Length Std',
                     'mean_bpktl': 'Bwd Packet Length Mean',
                     'flowBytesPerSecond': 'Flow Bytes/s',
                     'flowPktsPerSecond': 'Flow Packets/s',
                     'mean_flowiat': 'Flow IAT Mean',
                     'std_flowiat': 'Flow IAT Std',
                     'max_flowiat': 'Flow IAT Max',
                     'min_flowiat': 'Flow IAT Min',
                     'total_fiat': 'Fwd IAT Total',
                     'mean_fiat': 'Fwd IAT Mean',
                     'std_fiat': 'Fwd IAT Std',
                     'max_fiat': 'Fwd IAT Max',
                     'min_fiat': 'Fwd IAT Min',
                     'total_biat': 'Bwd IAT Total',
                     'max_biat': 'Bwd IAT Max',
                     'fpsh_cnt': 'Fwd PSH Flags',
                     'fPktsPerSecond': 'Fwd Packets/s',
                     'bPktsPerSecond': 'Bwd Packets/s',
                     'min_flowpktl': 'Min Packet Length',
                     'max_flowpktl': 'Max Packet Length',
                     'mean_flowpktl': 'Mean Packet Length',
                     'std_flowpktl': 'Packet Length Std',
                     'var_flowpktl': 'Packet Length Variance',
                     'flow_fin': 'FIN Flag Count',
                     'flow_syn': 'SYN Flag Count',
                     'flow_rst': 'RST Flag Count',
                     'flow_psh': 'PSH Flag Count',
                     'flow_ack': 'ACK Flag Count',
                     'avgPacketSize': 'Average Packet Size',
                     'fAvgSegmentSize': 'Avg Fwd Segment Size',
                     'bAvgSegmentSize': 'Avg Bwd Segment Size',
                     'fSubFlowAvgPkts': 'Subflow Fwd Packets',
                     'fSubFlowAvgBytes': 'Subflow Fwd Bytes',
                     'bSubFlowAvgPkts': 'Subflow Bwd Packets',
                     'bSubFlowAvgBytes': 'Subflow Bwd Bytes',
                     'fInitWinSize': 'Init_Win_bytes_forward',
                     'bInitWinSize': 'Init_Win_bytes_backward',
                     'fDataPkts': 'act_data_pkt_fwd',
                     'fHeaderSizeMin': 'Min Header size_forward',
                     'label': 'Label',
                     'total_fhlen': 'Fwd Header Length',
                     'flow_urg': 'URG Flag Count'
                     }

        # call rename () method
        df.rename(columns=self.dict,
                  inplace=True)

        return df

    def r_hdf(self):
        filename = 'prediction_data/data.h5'
        df = pd.read_hdf(filename)
        return df

    def save_to_hdf(self):
        # converting df(csv) to df(HDF5)
        filename = 'prediction_data/Normalized-data.h5'
        self.df.to_hdf(filename, 'data', mode='w', format='table')
        rc.log("\n[cyan]Converted Df to HDF5[/]\n")
        # del df

    def df_info(self):
        # df.head(5)
        rc.log("\n[purple]Head of Dataframe: {}[/] \n".format(self.df.head(5)))
        # rc.log(self.df.head(5))

        # df.shape
        rc.log("\n[magenta]Shape of Dataframe: {}[/]\n".format(self.df.shape))
        # rc.log(self.df.shape)

        # No. of rows and columns in dataframe
        rc.log(
            "\n[cyan]Number of Rows in Dataframe: {}[/]\n".format(self.df.shape[0]))
        rc.log("\n[good]Number of Columns in Dataframe: {}[/]\n".format(
            self.df.shape[1]))

        # # df.info
        # rc.log("\nDataframe Information: \n")
        # self.df.info()

    def columns_in_df(self):
        rc.log("\n[yellow]Columns in Dataframe:[/] \n")
        col = []
        for i in self.df.columns:
            col.append(i)
        return col

    def dropna(self):
        # df.replace([np.inf, -np.inf], np.nan).dropna(axis=1)
        self.df.replace([np.inf, -np.inf], np.nan, inplace=True)
        # Dropping all the rows with nan valuess
        self.df.dropna(inplace=True)

    # -------------------changing datatypes

    def check_size_dtypes(self, df):

        max = df.max()
        rc.log('[yellow]Maximum: {}[/]'.format(max))
        # rc.log(max, 'max')

        min = df.min()
        rc.log('[blue]Minimum: {}[/]'.format(min))

        # rc.log(min, 'min')
        # rc.log(df.value_counts())
        var1 = df.memory_usage(index=False, deep=True)
        rc.log('[magenta]This is the memory usage: {}[/]'.format(var1))
        # rc.log(var1, 'This is the memory usage')
        # rc.log(df.sample(8))

    def convert_datatypes(self, df, a='uint8'):

        # rc.log('Trying to convert datatypes for less memory usage')
        max = df.max()
        rc.log('[yellow]Maximum: {}[/]'.format(max))

        min = df.min()
        rc.log('[blue]Minimum: {}[/]'.format(min))

        # rc.log(df.value_counts())

        var1 = df.memory_usage(index=False, deep=True)
        rc.log('[cyan]This is the memory usage: {}[/]'.format(var1))
        df = df.astype(a, errors='ignore')
        var2 = df.memory_usage(index=False, deep=True)
        # rc.log(var2, ' new memory usage| the difference -> ', var1 / var2)
        return df

    def normalize(self, df):

        rc.log("[blue][* ] - Normalized data[/]")
        normalized_df = ((df - df.min()) /
                         (df.max() - df.min())) * 225
        return normalized_df

    def apply_fn(self):

        df['dst_port'] = d.normalize(df['dst_port'])
        df['dst_port'] = d.convert_datatypes(df['dst_port'])
        d.check_size_dtypes(df['dst_port'])

        df['duration'] = d.normalize(df['duration'])
        df['duration'] = d.convert_datatypes(df['duration'])
        d.check_size_dtypes(df['duration'])

        df['total_fpackets'] = d.normalize(df['total_fpackets'])
        df['total_fpackets'] = d.convert_datatypes(df['total_fpackets'])
        d.check_size_dtypes(df['total_fpackets'])

        df['total_bpackets'] = d.normalize(df['total_bpackets'])
        df['total_bpackets'] = d.convert_datatypes(df['total_bpackets'])
        d.check_size_dtypes(df['total_bpackets'])

        df['total_fpktl'] = d.normalize(df['total_fpktl'])
        df['total_fpktl'] = d.convert_datatypes(df['total_fpktl'])
        d.check_size_dtypes(df['total_fpktl'])

        df['min_fpktl'] = d.normalize(df['min_fpktl'])
        df['min_fpktl'] = d.convert_datatypes(df['min_fpktl'])
        d.check_size_dtypes(df['min_fpktl'])

        df['max_fpktl'] = d.normalize(df['max_fpktl'])
        df['max_fpktl'] = d.convert_datatypes(df['max_fpktl'])
        d.check_size_dtypes(df['max_fpktl'])

        df['mean_fpktl'] = d.normalize(df['mean_fpktl'])
        df['mean_fpktl'] = d.convert_datatypes(df['mean_fpktl'])
        d.check_size_dtypes(df['mean_fpktl'])

        df['std_fpktl'] = d.normalize(df['std_fpktl'])
        df['std_fpktl'] = d.convert_datatypes(df['std_fpktl'])
        d.check_size_dtypes(df['std_fpktl'])

        df['min_bpktl'] = d.normalize(df['min_bpktl'])
        df['min_bpktl'] = d.convert_datatypes(df['min_bpktl'])
        d.check_size_dtypes(df['min_bpktl'])

        df['max_bpktl'] = d.normalize(df['max_bpktl'])
        df['max_bpktl'] = d.convert_datatypes(df['max_bpktl'])
        d.check_size_dtypes(df['max_bpktl'])

        df['std_bpktl'] = d.normalize(df['std_bpktl'])
        df['std_bpktl'] = d.convert_datatypes(df['std_bpktl'])
        d.check_size_dtypes(df['std_bpktl'])

        df['flowBytesPerSecond'] = d.normalize(df['flowBytesPerSecond'])
        df['flowBytesPerSecond'] = d.convert_datatypes(
            df['flowBytesPerSecond'])
        d.check_size_dtypes(df['flowBytesPerSecond'])

        df['flowPktsPerSecond'] = d.normalize(df['flowPktsPerSecond'])
        df['flowPktsPerSecond'] = d.convert_datatypes(
            df['flowPktsPerSecond'])
        d.check_size_dtypes(df['flowPktsPerSecond'])

        df['mean_flowiat'] = d.normalize(df['mean_flowiat'])
        df['mean_flowiat'] = d.convert_datatypes(df['mean_flowiat'])
        d.check_size_dtypes(df['mean_flowiat'])

        df['std_flowiat'] = d.normalize(df['std_flowiat'])
        df['std_flowiat'] = d.convert_datatypes(df['std_flowiat'])
        d.check_size_dtypes(df['std_flowiat'])

        df['max_flowiat'] = d.normalize(df['max_flowiat'])
        df['max_flowiat'] = d.convert_datatypes(df['max_flowiat'])
        d.check_size_dtypes(df['max_flowiat'])

        df['min_flowiat'] = d.normalize(df['min_flowiat'])
        df['min_flowiat'] = d.convert_datatypes(df['min_flowiat'])
        d.check_size_dtypes(df['min_flowiat'])

        df['total_fiat'] = d.normalize(df['total_fiat'])
        df['total_fiat'] = d.convert_datatypes(df['total_fiat'])
        d.check_size_dtypes(df['total_fiat'])

        df['mean_fiat'] = d.normalize(df['mean_fiat'])
        df['mean_fiat'] = d.convert_datatypes(df['mean_fiat'])
        d.check_size_dtypes(df['mean_fiat'])

        df['std_fiat'] = d.normalize(df['std_fiat'])
        df['std_fiat'] = d.convert_datatypes(df['std_fiat'])
        d.check_size_dtypes(df['std_fiat'])

        df['max_fiat'] = d.normalize(df['max_fiat'])
        df['max_fiat'] = d.convert_datatypes(df['max_fiat'])
        d.check_size_dtypes(df['max_fiat'])

        df['min_fiat'] = d.normalize(df['min_fiat'])
        df['min_fiat'] = d.convert_datatypes(df['min_fiat'])
        d.check_size_dtypes(df['min_fiat'])

        df['total_biat'] = d.normalize(df['total_biat'])
        df['total_biat'] = d.convert_datatypes(df['total_biat'])
        d.check_size_dtypes(df['total_biat'])

        df['max_biat'] = d.normalize(df['max_biat'])
        df['max_biat'] = d.convert_datatypes(df['max_biat'])
        d.check_size_dtypes(df['max_biat'])

        df['fpsh_cnt'] = d.normalize(df['fpsh_cnt'])
        df['fpsh_cnt'] = d.convert_datatypes(df['fpsh_cnt'])
        d.check_size_dtypes(df['fpsh_cnt'])

        df['fPktsPerSecond'] = d.normalize(df['fPktsPerSecond'])
        df['fPktsPerSecond'] = d.convert_datatypes(df['fPktsPerSecond'])
        d.check_size_dtypes(df['fPktsPerSecond'])

        df['bPktsPerSecond'] = d.normalize(df['bPktsPerSecond'])
        df['bPktsPerSecond'] = d.convert_datatypes(df['bPktsPerSecond'])
        d.check_size_dtypes(df['bPktsPerSecond'])

        df['min_flowpktl'] = d.normalize(df['min_flowpktl'])
        df['min_flowpktl'] = d.convert_datatypes(df['min_flowpktl'])
        d.check_size_dtypes(df['min_flowpktl'])

        df['max_flowpktl'] = d.normalize(df['max_flowpktl'])
        df['max_flowpktl'] = d.convert_datatypes(df['max_flowpktl'])
        d.check_size_dtypes(df['max_flowpktl'])

        df['mean_flowpktl'] = d.normalize(df['mean_flowpktl'])
        df['mean_flowpktl'] = d.convert_datatypes(df['mean_flowpktl'])
        d.check_size_dtypes(df['mean_flowpktl'])

        df['std_flowpktl'] = d.normalize(df['std_flowpktl'])
        df['std_flowpktl'] = d.convert_datatypes(df['std_flowpktl'])
        d.check_size_dtypes(df['std_flowpktl'])

        df['var_flowpktl'] = d.normalize(df['var_flowpktl'])
        df['var_flowpktl'] = d.convert_datatypes(df['var_flowpktl'])
        d.check_size_dtypes(df['var_flowpktl'])

        df['flow_fin'] = d.normalize(df['flow_fin'])
        df['flow_fin'] = d.convert_datatypes(df['flow_fin'])
        d.check_size_dtypes(df['flow_fin'])

        df['flow_syn'] = d.normalize(df['flow_syn'])
        df['flow_syn'] = d.convert_datatypes(df['flow_syn'])
        d.check_size_dtypes(df['flow_syn'])

        df['flow_rst'] = d.normalize(df['flow_rst'])
        df['flow_rst'] = d.convert_datatypes(df['flow_rst'])
        d.check_size_dtypes(df['flow_rst'])

        df['flow_psh'] = d.normalize(df['flow_psh'])
        df['flow_psh'] = d.convert_datatypes(df['flow_psh'])
        d.check_size_dtypes(df['flow_psh'])

        df['flow_ack'] = d.normalize(df['flow_ack'])
        df['flow_ack'] = d.convert_datatypes(df['flow_ack'])
        d.check_size_dtypes(df['flow_ack'])

        df['avgPacketSize'] = d.normalize(df['avgPacketSize'])
        df['avgPacketSize'] = d.convert_datatypes(df['avgPacketSize'])
        d.check_size_dtypes(df['avgPacketSize'])

        df['fAvgSegmentSize'] = d.normalize(df['fAvgSegmentSize'])
        df['fAvgSegmentSize'] = d.convert_datatypes(df['fAvgSegmentSize'])
        d.check_size_dtypes(df['fAvgSegmentSize'])

        df['bAvgSegmentSize'] = d.normalize(df['bAvgSegmentSize'])
        df['bAvgSegmentSize'] = d.convert_datatypes(df['bAvgSegmentSize'])
        d.check_size_dtypes(df['bAvgSegmentSize'])

        df['fSubFlowAvgPkts'] = d.normalize(df['fSubFlowAvgPkts'])
        df['fSubFlowAvgPkts'] = d.convert_datatypes(df['fSubFlowAvgPkts'])
        d.check_size_dtypes(df['fSubFlowAvgPkts'])

        df['fSubFlowAvgBytes'] = d.normalize(df['fSubFlowAvgBytes'])
        df['fSubFlowAvgBytes'] = d.convert_datatypes(df['fSubFlowAvgBytes'])
        d.check_size_dtypes(df['fSubFlowAvgBytes'])

        df['bSubFlowAvgPkts'] = d.normalize(df['bSubFlowAvgPkts'])
        df['bSubFlowAvgPkts'] = d.convert_datatypes(df['bSubFlowAvgPkts'])
        d.check_size_dtypes(df['bSubFlowAvgPkts'])

        df['bSubFlowAvgBytes'] = d.normalize(df['bSubFlowAvgBytes'])
        df['bSubFlowAvgBytes'] = d.convert_datatypes(df['bSubFlowAvgBytes'])
        d.check_size_dtypes(df['bSubFlowAvgBytes'])

        df['fInitWinSize'] = d.normalize(df['fInitWinSize'])
        df['fInitWinSize'] = d.convert_datatypes(df['fInitWinSize'])
        d.check_size_dtypes(df['fInitWinSize'])

        df['bInitWinSize'] = d.normalize(df['bInitWinSize'])
        df['bInitWinSize'] = d.convert_datatypes(df['bInitWinSize'])
        d.check_size_dtypes(df['bInitWinSize'])

        df['fDataPkts'] = d.normalize(df['fDataPkts'])
        df['fDataPkts'] = d.convert_datatypes(df['fDataPkts'])
        d.check_size_dtypes(df['fDataPkts'])

        df['fHeaderSizeMin'] = d.normalize(df['fHeaderSizeMin'])
        df['fHeaderSizeMin'] = d.convert_datatypes(df['fHeaderSizeMin'])
        d.check_size_dtypes(df['fHeaderSizeMin'])

        df['total_fhlen'] = d.normalize(df['total_fhlen'])
        df['total_fhlen'] = d.convert_datatypes(df['total_fhlen'])
        d.check_size_dtypes(df['total_fhlen'])

        df['min_idle_s'] = d.normalize(df['min_idle_s'])
        df['min_idle_s'] = d.convert_datatypes(df['min_idle_s'])
        d.check_size_dtypes(df['min_idle_s'])

        df['max_idle_s'] = d.normalize(df['max_idle_s'])
        df['max_idle_s'] = d.convert_datatypes(df['max_idle_s'])
        d.check_size_dtypes(df['max_idle_s'])

        df['std_idle_s'] = d.normalize(df['std_idle_s'])
        df['std_idle_s'] = d.convert_datatypes(df['std_idle_s'])
        d.check_size_dtypes(df['std_idle_s'])

        df['mean_idle_s'] = d.normalize(df['mean_idle_s'])
        df['mean_idle_s'] = d.convert_datatypes(df['mean_idle_s'])
        d.check_size_dtypes(df['mean_idle_s'])

        df['flow_urg'] = d.normalize(df['flow_urg'])
        df['flow_urg'] = d.convert_datatypes(df['flow_urg'])
        d.check_size_dtypes(df['flow_urg'])

        df['fHeaderSizeMin'] = d.normalize(df['fHeaderSizeMin'])
        df['fHeaderSizeMin'] = d.convert_datatypes(df['fHeaderSizeMin'])
        d.check_size_dtypes(df['fHeaderSizeMin'])

        '''
            39  URG Flag Count               87 non-null     float64 'flow_urg'
            26  Fwd Header Length            0 non-null      float64  'fHeaderSizeMin'

                Idle Mean                    87 non-null     float64  'mean_idle_s', 'std_idle_s', 'max_idle_s', 'min_idle_s'
            52  Idle Std                     87 non-null     float64
            53  Idle Max                     87 non-null     float64
            54  Idle Min                     87 non-null     float64

        '''

        rc.log("[magenta]Data information: \n{}[/]".format(df.info()))


if __name__ == "__main__":

    filename = 'csvs/merged_data.csv'

    df = pd.read_csv(filename)
    rc.log("[cyan][*_*] - Preprocessing the captured Data - [*_*][/]\n\n")

    rc.log("[yellow]Columns/ Features in captured data: \n{}[/]".format(df.columns))
    rc.log("[blue]Shape of captured data: \n{}[/]".format(df.shape))
    d = Preprocessing(df)
    d.dropna()
    d.rm_col()
    d.apply_fn()
    l = d.col_rename()
    col = []
    for i in l:
        # col.append(i)
        rc.log("[cyan]<------- {} ------->[/]".format(i))
    # l.info()

    rc.log("[good][ DONE ] - File is ready to fed to ML/ DL model. [magenta][ *in HDF5 Format ][/][/]")

    filename1 = 'prediction_data/normed_data.h5'
    df.to_hdf(filename1, 'data', mode='w', format='table')
    rc.log(df.columns)
    rc.log("[bold blue][ *** ] - Shape of captured data: {}[/]".format(df.shape))

    rc.save_html("norm-report.html")

    # df = pd.read_csv(filename)
    # rc.log("[cyan][*_*] - Preprocessing the captured Data - [*_*][/]\n\n")

    # rc.log("[yellow]Columns/ Features in captured data: \n{}[/]".format(df.columns))
    # # df.replace([np.inf, -np.inf], np.nan).dropna(axis=1)

    # rc.log("[blue]Shape of captured data: \n{}[/]".format(df.shape))
    # d = Preprocessing(df)
    # df = d.r_csv(filename)

    # rc.log(df)

    # rc.log("[purple]Droping NaN values.....\n[/]")
    # d.dropna()

    # # # df.replace([np.inf, -np.inf], np.nan).dropna(axis=1)
    # # df.replace([np.inf, -np.inf], np.nan, inplace=True)
    # # # Dropping all the rows with nan valuess
    # # df.dropna(inplace=True)

    # rc.log("[bold bad]Removing unwanted columns...\n[/]")
    # d.rm_col()

    # d.apply_fn()

    # rc.log("[good]Giving Columns a meaningful name...[/]")
    # l = d.col_rename()

    # rc.log("[cyan]Data info(): \n[/] \n")
    # l.info()

    # rc.log("[magenta][*_*] - Saving preprocessed_data.csv,..[/]")
    # df.to_csv("preprocessed_csv/preprocessed_data.csv", encoding='utf-8')
    # rc.log("\n[good][*_*] - Saved Preprocessed csv[/]\n")

    # rc.log("[good][ DONE ] - File is ready to fed to ML/ DL model. [magenta][ *in HDF5 Format ][/][/]")
    # d.save_to_hdf()
    # rc.log(df.columns)
    # rc.log("[bold blue][ *** ] - Shape of captured data: {}[/]".format(df.shape))

    # rc.save_html("norm-report.html")
