import streamlit as st
import pandas as pd
import json

from scanner import bulk_scan, enterprise_score

st.set_page_config(
    page_title="Quantum-Proof Scanner",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ Enterprise Quantum-Proof Asset Scanner")

st.caption("Cybersecurity Hackathon – Quantum Safe Crypto Discovery")

st.divider()

targets_text = st.text_area(
    "Enter Domains / IPs / CIDR ranges",
    """google.com
1.1.1.1
192.168.1.0/30"""
)

scan_button = st.button("Run Scan")


if scan_button:

    targets = [t.strip() for t in targets_text.split("\n") if t.strip()]

    with st.spinner("Scanning enterprise assets..."):

        results = bulk_scan(targets)

    df = pd.DataFrame(results)

    st.subheader("Enterprise Asset Dashboard")

    st.dataframe(df, use_container_width=True)

    st.divider()

    if "score" in df.columns:

        st.subheader("Security Score Distribution")

        st.bar_chart(df.set_index("endpoint")["score"])

    st.divider()

    enterprise = enterprise_score(results)

    st.subheader("Enterprise PQC Score")

    st.metric("Enterprise Score", f"{enterprise} / 1000")

    st.divider()

    st.subheader("Detailed Asset Analysis")

    for r in results:

        with st.expander(r["endpoint"]):

            if "error" in r:
                st.error(r["error"])
                continue

            st.write("Score:", r.get("score"))
            st.write("Tier:", r.get("tier"))
            st.write("TLS Version:", r.get("protocol"))
            st.write("Cipher:", r.get("cipher"))
            st.write("Key Algorithm:", r.get("key_algorithm"))
            st.write("Key Size:", r.get("key_size"))
            st.write("PQC Status:", r.get("pqc_label"))
            st.write("Vulnerabilities:", r.get("vulnerabilities"))

            st.warning(r.get("recommendations"))

    st.divider()

    st.subheader("Download Reports")

    json_report = json.dumps(results, indent=4)

    st.download_button(
        "Download JSON",
        json_report,
        "crypto_scan.json"
    )

    csv_report = df.to_csv(index=False)

    st.download_button(
        "Download CSV",
        csv_report,
        "crypto_scan.csv"
    )