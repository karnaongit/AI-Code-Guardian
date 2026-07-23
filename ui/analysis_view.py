import streamlit as st


def show_analysis(analysis):

    st.subheader("📊 Code Analysis")

    tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs(
        [
            "Functions",
            "Classes",
            "Imports",
            "Variables",
            "Calls",
            "Metrics"
        ]
    )

    with tab1:

        if analysis["functions"]:

            for function in analysis["functions"]:
                st.code(function)

        else:
            st.info("No functions found.")

    with tab2:

        if analysis["classes"]:

            for cls in analysis["classes"]:
                st.code(cls)

        else:
            st.info("No classes found.")

    with tab3:

        if analysis["imports"]:

            for imp in analysis["imports"]:
                st.code(imp)

        else:
            st.info("No imports found.")

    with tab4:

        if analysis["variables"]:

            for variable in analysis["variables"]:
                st.code(variable)

        else:
            st.info("No variables found.")

    with tab5:

        col1, col2 = st.columns(2)

        with col1:

            st.markdown("### Function Calls")

            if analysis["calls"]:

                for call in analysis["calls"]:
                    st.code(call)

            else:
                st.info("No calls found.")

        with col2:

            st.markdown("### Dangerous Calls")

            if analysis["dangerous_calls"]:

                for call in analysis["dangerous_calls"]:

                    st.error(
                        f"{call['function']} (Line {call['line']})"
                    )

            else:

                st.success("No dangerous calls detected.")

    with tab6:

        metrics = analysis["metrics"]

        c1, c2, c3 = st.columns(3)

        with c1:
            st.metric("Lines", metrics["lines"])
            st.metric("Functions", metrics["functions"])

        with c2:
            st.metric("Classes", metrics["classes"])
            st.metric("Imports", metrics["imports"])

        with c3:
            st.metric("Variables", metrics["variables"])