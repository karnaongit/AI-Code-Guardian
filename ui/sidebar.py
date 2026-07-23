import streamlit as st


def show_sidebar(files):

    with st.sidebar:

        st.title("📂 Repository Explorer")

        selected = st.selectbox(
            "Python Files",
            files,
            format_func=lambda x: x["path"]
        )

    return selected