import pandas as pd
import numpy as np
from pandas_profiling import ProfileReport
from sklearn.preprocessing import StandardScaler
import gzip
import pickle
import matplotlib.pyplot as plt
import matplotlib as mpl
import seaborn as sns


def pre_process_df(df):
    constants_c = ["su_attempted", "root_shell", "num_root", "num_file_creations", "num_shells",
                   "num_access_files", "num_outbound_cmds", "is_host_login", "is_guest_login", "duration", "land",
                   "wrong_fragment", "urgent", "hot", "num_failed_logins", "num_compromised"
                   ]
    df = df.drop(constants_c, axis=1)
    df["src_bytes"] = np.sqrt(df["src_bytes"])
    df["src_bytes"] = df["src_bytes"].apply(
        lambda x: x if x == 0 else np.log(x))
    df["dst_bytes"] = df["dst_bytes"].apply(
        lambda x: x if x == 0 else np.log(x))
    df["dst_bytes"].skew()  # Botar las columnas que no nos son útiles
    df = df.drop(
        [
            "srv_serror_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
            "srv_rerror_rate", "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "dst_host_same_srv_rate"
        ],
        axis=1
    )
    df = pd.get_dummies(df, columns=['protocol_type', "flag", "service"])
    map_class = {
        "normal": 0,
        "anomaly": 1
    }

    features = list(filter(lambda x: x != "class", df.columns))

    X = df.loc[:, features].values
    return X
