import streamlit as st


def show_home():

    st.title("🛡 AI Code Guardian")

    repo_url = st.text_input("GitHub Repository URL")

    analyze = st.button("Analyze Repository")

    return repo_url, analyze