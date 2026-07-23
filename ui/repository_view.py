import streamlit as st


def show_repository(repo):

    st.subheader("📦 Repository Information")

    col1, col2, col3 = st.columns(3)

    with col1:
        st.metric("Repository", repo["name"])
        st.metric("Owner", repo["owner"])

    with col2:
        st.metric("Language", repo["language"])
        st.metric("Stars", repo["stars"])

    with col3:
        st.metric("Branch", repo["branch"])
        st.metric("Forks", repo["forks"])