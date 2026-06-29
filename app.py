import streamlit as st
import sqlite3
import pandas as pd
import plotly.express as px

conn = sqlite3.connect("cyber_cafe.db", check_same_thread=False)

def authenticate(username, password):
    cursor = conn.cursor()

    cursor.execute(
        "SELECT * FROM users WHERE username=? AND password=?",
        (username, password)
    )

    return cursor.fetchone()

st.set_page_config(layout="wide")

if "logged_in" not in st.session_state:
    st.session_state.logged_in = False

if "username" not in st.session_state:
    st.session_state.username = ""

if st.session_state.logged_in:
    st.sidebar.success(
        f"Logged in as {st.session_state.username}"
    )

    if st.sidebar.button("Logout"):
        st.session_state.logged_in = False
        st.session_state.username = ""
        st.rerun()


if not st.session_state.logged_in:

    st.title("Cyber Café Login")

    username = st.text_input("Username")
    password = st.text_input(
        "Password",
        type="password"
    )

    if st.button("Login"):

        user = authenticate(
            username,
            password
        )

        if user:
            st.session_state.logged_in = True
            st.session_state.username = username
            st.success("Login Successful")
            st.rerun()

        else:
            st.error("Invalid Username or Password")

    st.stop()

st.title("Cyber Café Threat Monitoring Dashboard")
st.subheader(
"Real-Time Suspicious Login and Attack Monitoring System"
)


menu = st.sidebar.radio(
    "Navigation",
    [
        "Home",
        "Login Attempts",
        "Suspicious IPs",
        "Brute Force Detection",
        "Attack Logs",
        "Blocked Systems",
        "Threat Analytics",
        "Incident Reports",
        "Admin Panel"
    ]
)

if menu=="Home":

    st.metric(
        "Total Login Attempts",
        pd.read_sql(
            "SELECT * FROM login_attempts",
            conn
        ).shape[0]
    )

if menu=="Login Attempts":

    df = pd.read_sql(
        "SELECT * FROM login_attempts",
        conn
    )

    st.dataframe(df)

if menu=="Suspicious IPs":

    df = pd.read_sql(
        "SELECT * FROM suspicious_ips",
        conn
    )

    st.dataframe(df)

    st.warning("High Risk IPs Detected")

if menu=="Brute Force Detection":

    query="""
    SELECT ip_address,
    COUNT(*) as failures
    FROM login_attempts
    WHERE attempt_status='Failed'
    GROUP BY ip_address
    HAVING COUNT(*)>5
    """

    df=pd.read_sql(query,conn)

    st.dataframe(df)

    st.error("Brute Force Suspects")

if menu=="Attack Logs":

    df = pd.read_sql(
        "SELECT * FROM attack_logs",
        conn
    )

    st.dataframe(df)

if menu=="Blocked Systems":

    df = pd.read_sql(
        "SELECT * FROM blocked_systems",
        conn
    )

    st.table(df)

    if st.button("Unblock Selected"):
        st.success("Simulation Successful")

if menu=="Threat Analytics":

    attack_df = pd.read_sql(
        "SELECT * FROM attack_logs",
        conn
    )

    st.metric(
        "Total Attacks",
        len(attack_df)
    )

    fig = px.pie(
        attack_df,
        names="attack_type",
        title="Attack Types"
    )

    st.plotly_chart(fig)

    fig2 = px.histogram(
        attack_df,
        x="severity_score"
    )

    st.plotly_chart(fig2)

if menu == "Incident Reports":
    st.info("Incident Report Generator")

    # Collect data
    login_df = pd.read_sql("SELECT * FROM login_attempts", conn)
    attack_df = pd.read_sql("SELECT * FROM attack_logs", conn)
    suspicious_df = pd.read_sql("SELECT * FROM suspicious_ips", conn)
    blocked_df = pd.read_sql("SELECT * FROM blocked_systems", conn)

    # Summaries
    total_attempts = len(login_df)
    failed_attempts = login_df[login_df['attempt_status'] == 'Failed'].shape[0]
    blocked_attempts = login_df[login_df['attempt_status'] == 'Blocked'].shape[0]
    total_attacks = len(attack_df)
    high_risk_ips = suspicious_df[suspicious_df['threat_level'] == 'High'].shape[0]
    blocked_systems = len(blocked_df)

    # Top failure reasons
    failure_summary = login_df['failure_reason'].value_counts().head(5)

    # Build report text
    report = []
    report.append("Cyber Café Incident Report\n")
    report.append("="*40 + "\n\n")
    report.append(f"Total Login Attempts: {total_attempts}\n")
    report.append(f"Failed Attempts: {failed_attempts}\n")
    report.append(f"Blocked Attempts: {blocked_attempts}\n\n")
    report.append(f"Total Attacks Recorded: {total_attacks}\n")
    report.append(f"High Risk IPs: {high_risk_ips}\n")
    report.append(f"Blocked Systems: {blocked_systems}\n\n")
    report.append("Top Failure Reasons:\n")
    for reason, count in failure_summary.items():
        report.append(f"- {reason}: {count}\n")
    report.append("\nDetailed Attack Breakdown:\n")
    attack_counts = attack_df['attack_type'].value_counts()
    for attack, count in attack_counts.items():
        report.append(f"- {attack}: {count}\n")

    # Join into final text
    report_text = "".join(report)

    # Show preview
    st.text_area("Incident Report Preview", report_text, height=300)

    # Download button
    st.download_button(
        "Download Incident Report",
        report_text,
        file_name="incident_report.txt"
    )


if menu=="Admin Panel":

    st.header("Admin Dashboard")

    users = pd.read_sql(
        "SELECT * FROM users",
        conn
    )

    st.dataframe(users)