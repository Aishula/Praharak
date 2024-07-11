import numpy as np
from tensorflow.keras.models import load_model
from datetime import datetime


def convert_to_numeric(data):
    if isinstance(data[0], list):
        # Multiple rows
        numeric_data = np.array([[float(x) for x in row] for row in data], dtype=float)
    else:
        # Single row
        numeric_data = np.array([float(x) for x in data], dtype=float)
    return numeric_data


# Function to convert timestamp string to Unix timestamp
def convert_timestamp_to_int(timestamp):
    dt = datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S')
    unix_timestamp = int(dt.timestamp())
    return unix_timestamp


class AIModel:
    def __init__(self, model_path, sequence_length=10):
        self.model = load_model(model_path)
        self.sequence_length = sequence_length
        self.buffer = []

    def preprocess_data(self, data):
        data = convert_to_numeric(data)
        return data

    def create_sequence(self, data):
        self.buffer.append(data)
        # print("Buffer:", self.buffer)
        if len(self.buffer) < self.sequence_length:
            return None  # Insufficient data for a full sequence
        else:
            # Extract the last 'sequence_length' elements from buffer
            print("sequence is creating...")
            sequence = self.buffer[-self.sequence_length:]
            # sequence = self.preprocess_data(sequence)
            return sequence

    def predict(self, data):
        print("Predicting...")
        # Predict for a single data row
        data = self.preprocess_data(data)
        # print("After preprocessing:", data)
        sequence = self.create_sequence(data)
        # print("after sequence:", sequence)
        if sequence is None:
            print("Insufficient data to make prediction")
            return None

        sequence = np.array(sequence)
        # Reshape for LSTM input (assuming sequence_length x num_features)
        sequence = sequence.reshape((1, self.sequence_length, sequence.shape[1]))

        # Debugging: Check the reshaped sequence shape
        print("Reshaped sequence shape:", sequence.shape)
        prediction = self.model.predict(sequence)[0][0]
        # After prediction, remove the oldest element from the buffer
        self.buffer.pop(0)
        return (prediction > 0.5).astype(int)


ai_model = AIModel("utils/model_train_praharak_v1.h5")


"""
' Destination Port', ' Protocol', ' Timestamp', ' Flow Duration',
       ' Total Fwd Packets', ' Total Backward Packets',
       'Total Length of Fwd Packets', ' Total Length of Bwd Packets',
       ' Fwd Packet Length Max', ' Fwd Packet Length Min',
       ' Fwd Packet Length Mean', ' Fwd Packet Length Std',
       'Bwd Packet Length Max', ' Bwd Packet Length Min',
       ' Bwd Packet Length Mean', ' Bwd Packet Length Std', 'Flow Bytes/s',
       ' Flow Packets/s', ' Flow IAT Mean', ' Flow IAT Std', ' Flow IAT Max',
       ' Flow IAT Min', 'Fwd IAT Total', ' Fwd IAT Mean', ' Fwd IAT Std',
       ' Fwd IAT Max', ' Fwd IAT Min', 'Bwd IAT Total', ' Bwd IAT Mean',
       ' Bwd IAT Std', ' Bwd IAT Max', ' Bwd IAT Min', 'Fwd PSH Flags',
       ' Fwd Header Length', ' Bwd Header Length', 'Fwd Packets/s',
       ' Bwd Packets/s', ' Min Packet Length', ' Max Packet Length',
       ' Packet Length Mean', ' Packet Length Std', ' Packet Length Variance',
       'FIN Flag Count', ' SYN Flag Count', ' RST Flag Count',
       ' PSH Flag Count', ' ACK Flag Count', ' URG Flag Count',
       ' ECE Flag Count', ' Down/Up Ratio', ' Average Packet Size',
       ' Avg Fwd Segment Size', ' Avg Bwd Segment Size',
       'Subflow Fwd Packets', ' Subflow Fwd Bytes',
       ' Subflow Bwd Packets', ' Subflow Bwd Bytes', 'Init_Win_bytes_forward',
       ' Init_Win_bytes_backward', ' act_data_pkt_fwd',
       ' min_seg_size_forward', 'Active Mean', ' Active Std', ' Active Max',
       ' Active Min', 'Idle Mean', ' Idle Std', ' Idle Max', ' Idle Min'
"""

"""

    features = [
        data["dst_port"],                   # 1
        data["protocol"],                   # 2
        data["timestamp"],                  # 3
        data["flow_duration"],              # 4
        data["total_fwd_pkts"],             # 5
        data["total_bwd_pkts"],             # 6
        data["tot_len_of_fwd_pkt"],         # 7
        data["tot_len_of_bwd_pkt"],         # 8
        data["fwd_pkt_len_max"],            # 9
        data["fwd_pkt_len_min"],            # 10
        data["fwd_pkt_len_mean"],           # 11
        data["fwd_pkt_len_std"],            # 12
        data["bwd_pkt_len_max"],            # 13
        data["bwd_pkt_len_min"],            # 14
        data["bwd_pkt_len_mean"],           # 15
        data["bwd_pkt_len_std"],            # 16
        data["flow_bytes_s"],               # 17
        data["flow_pkts_s"],                # 18
        data["flow_iat_mean"],              # 19
        data["flow_iat_std"],               # 20
        data["flow_iat_max"],               # 21
        data["flow_iat_min"],               # 22
        data["fwd_iat_tot"],                # 23
        data["fwd_iat_mean"],               # 24
        data["fwd_iat_std"],                # 25
        data["fwd_iat_max"],                # 26
        data["fwd_iat_min"],                # 27
        data["bwd_iat_tot"],                # 28
        data["bwd_iat_mean"],               # 29
        data["bwd_iat_std"],                # 30
        data["bwd_iat_max"],                # 31
        data["bwd_iat_min"],                # 32
        data["fwd_psh_flags"],              # 33
        data["fwd_header_len"],             # 34
        data["bwd_header_len"],             # 35
        data["fwd_pkts_s"],                 # 36
        data["bwd_pkts_s"],                 # 37
        data["pkt_len_min"],                # 38
        data["pkt_len_max"],                # 39
        data["pkt_len_mean"],               # 40
        data["pkt_len_std"],                # 41
        data["pkt_len_var"],                # 42
        data["fin_flag_cnt"],               # 43
        data["syn_flag_cnt"],               # 44
        data["rst_flag_cnt"],               # 45
        data["psh_flag_cnt"],               # 46
        data["ack_flag_cnt"],               # 47
        data["urg_flag_cnt"],               # 48
        data["ece_flag_cnt"],               # 49
        data["down_up_ratio"],              # 50
        data["pkt_size_avg"],               # 51
        data["fwd_seg_size_avg"],           # 52
        data["bwd_seg_size_avg"],           # 53
        data["subflow_fwd_pkts"],           # 54
        data["subflow_fwd_byts"],           # 55
        data["subflow_bwd_pkts"],           # 56
        data["subflow_bwd_byts"],           # 57
        data["init_fwd_win_byts"],          # 58
        data["init_bwd_win_byts"],          # 59
        data["fwd_act_data_pkts"],          # 60
        data["fwd_seg_size_min"],           # 61
        data["active_mean"],                # 62
        data["active_std"],                 # 63
        data["active_max"],                 # 64
        data["active_min"],                 # 65
        data["idle_mean"],                  # 66
        data["idle_std"],                   # 67
        data["idle_max"],                   # 68
        data["idle_min"],                   # 69
    ]

"""
