import streamlit as st


def show_source_code(content):

    st.subheader("📄 Source Code")

    st.code(content, language="python")