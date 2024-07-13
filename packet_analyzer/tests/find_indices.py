# List of all features
features = [
    "dst_port",  # 0
    "protocol",  # 1
    "timestamp",  # 2
    "flow_duration",  # 3
    "total_fwd_pkts",  # 4
    "total_bwd_pkts",  # 5
    "tot_len_of_fwd_pkt",  # 6
    "tot_len_of_bwd_pkt",  # 7
    "fwd_pkt_len_max",  # 8
    "fwd_pkt_len_min",  # 9
    "fwd_pkt_len_mean",  # 10
    "fwd_pkt_len_std",  # 11
    "bwd_pkt_len_max",  # 12
    "bwd_pkt_len_min",  # 13
    "bwd_pkt_len_mean",  # 14
    "bwd_pkt_len_std",  # 15
    "flow_bytes_s",  # 16
    "flow_pkts_s",  # 17
    "flow_iat_mean",  # 18
    "flow_iat_std",  # 19
    "flow_iat_max",  # 20
    "flow_iat_min",  # 21
    "fwd_iat_tot",  # 22
    "fwd_iat_mean",  # 23
    "fwd_iat_std",  # 24
    "fwd_iat_max",  # 25
    "fwd_iat_min",  # 26
    "bwd_iat_tot",  # 27
    "bwd_iat_mean",  # 28
    "bwd_iat_std",  # 29
    "bwd_iat_max",  # 30
    "bwd_iat_min",  # 31
    "fwd_psh_flags",  # 32
    "fwd_header_len",  # 33
    "bwd_header_len",  # 34
    "fwd_pkts_s",  # 35
    "bwd_pkts_s",  # 36
    "pkt_len_min",  # 37
    "pkt_len_max",  # 38
    "pkt_len_mean",  # 39
    "pkt_len_std",  # 40
    "pkt_len_var",  # 41
    "fin_flag_cnt",  # 42
    "syn_flag_cnt",  # 43
    "rst_flag_cnt",  # 44
    "psh_flag_cnt",  # 45
    "ack_flag_cnt",  # 46
    "urg_flag_cnt",  # 47
    "ece_flag_cnt",  # 48
    "down_up_ratio",  # 49
    "pkt_size_avg",  # 50
    "fwd_seg_size_avg",  # 51
    "bwd_seg_size_avg",  # 52
    "subflow_fwd_pkts",  # 53
    "subflow_fwd_byts",  # 54
    "subflow_bwd_pkts",  # 55
    "subflow_bwd_byts",  # 56
    "init_fwd_win_byts",  # 57
    "init_bwd_win_byts",  # 58
    "fwd_act_data_pkts",  # 59
    "fwd_seg_size_min",  # 60
    "active_mean",  # 61
    "active_std",  # 62
    "active_max",  # 63
    "active_min",  # 64
    "idle_mean",  # 65
    "idle_std",  # 66
    "idle_max",  # 67
    "idle_min"  # 68
]

# Non-binary features
non_binary_features = [
    "dst_port", "protocol", "timestamp", "flow_duration", "total_fwd_pkts", "total_bwd_pkts",
    "tot_len_of_fwd_pkt", "tot_len_of_bwd_pkt", "fwd_pkt_len_max", "fwd_pkt_len_min",
    "fwd_pkt_len_mean", "fwd_pkt_len_std", "bwd_pkt_len_max", "bwd_pkt_len_min",
    "bwd_pkt_len_mean", "bwd_pkt_len_std", "flow_bytes_s", "flow_pkts_s", "flow_iat_mean",
    "flow_iat_std", "flow_iat_max", "flow_iat_min", "fwd_iat_tot", "fwd_iat_mean",
    "fwd_iat_std", "fwd_iat_max", "fwd_iat_min", "bwd_iat_tot", "bwd_iat_mean",
    "bwd_iat_std", "bwd_iat_max", "bwd_iat_min", "fwd_header_len", "bwd_header_len",
    "fwd_pkts_s", "bwd_pkts_s", "pkt_len_min", "pkt_len_max", "pkt_len_mean",
    "pkt_len_std", "pkt_len_var", "down_up_ratio", "pkt_size_avg", "fwd_seg_size_avg",
    "bwd_seg_size_avg", "subflow_fwd_pkts", "subflow_fwd_byts", "subflow_bwd_pkts",
    "subflow_bwd_byts", "init_fwd_win_byts", "init_bwd_win_byts", "fwd_act_data_pkts",
    "fwd_seg_size_min", "active_mean", "active_std", "active_max", "active_min",
    "idle_mean", "idle_std", "idle_max", "idle_min"
]

# Binary features
binary_features = [
    "fwd_psh_flags", "fin_flag_cnt", "syn_flag_cnt", "rst_flag_cnt", "psh_flag_cnt",
    "ack_flag_cnt", "urg_flag_cnt", "ece_flag_cnt"
]

# Get the indices for non-binary and binary features
non_binary_indices = [features.index(feature) for feature in non_binary_features]
binary_indices = [features.index(feature) for feature in binary_features]

print("Non-binary indices:", non_binary_indices)
print("Binary indices:", binary_indices)
