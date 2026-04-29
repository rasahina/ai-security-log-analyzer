import plotly.graph_objects as go


#グラフ描画関数
def create_timeline_chart(time_df, title):
    fig = go.Figure()

    fig.add_trace(go.Scatter(
        x=time_df["time_bucket"],
        y=time_df["access_count"],
        mode="lines",
        name="Access Count"
    ))

    fig.add_trace(go.Scatter(
        x=time_df["time_bucket"],
        y=time_df["failed_count"],
        mode="lines",
        name="Failed Count"
    ))

    anomaly_df = time_df[time_df["is_anomaly"]]

    fig.add_trace(go.Scatter(
        x=anomaly_df["time_bucket"],
        y=anomaly_df["access_count"],
        mode="markers",
        name="Anomaly",
        marker=dict(color="red", size=10),
        text=anomaly_df["anomaly_reason"],
        customdata=anomaly_df[["ip", "anomaly_reason"]],
        hovertemplate=(
            "Time: %{x}<br>"
            "IP: %{customdata[0]}<br>"
            "Access Count: %{y}<br>"
            "Reason: %{text}<extra></extra>"
        )
    ))

    fig.update_layout(
        title=title,
        xaxis_title="Time",
        yaxis_title="Count",
        hovermode="x unified"
    )

    return fig
