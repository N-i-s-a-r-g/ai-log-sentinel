def auto_block_ips(df):
    BLOCK_THRESHOLD = 5

    ip_scores = df.groupby("ip")["score"].sum()
    blocked_ips = ip_scores[ip_scores >= BLOCK_THRESHOLD]

    return blocked_ips