import streamlit as st


def show_security(scan):

    severity_count = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0
    }

    for finding in scan.findings:

        if finding.severity in severity_count:
            severity_count[finding.severity] += 1

    c1, c2, c3, c4 = st.columns(4)

    with c1:
        st.metric("🔴 Critical", severity_count["Critical"])

    with c2:
        st.metric("🟠 High", severity_count["High"])

    with c3:
        st.metric("🟡 Medium", severity_count["Medium"])

    with c4:
        st.metric("🟢 Low", severity_count["Low"])

    st.divider()

    if not scan.findings:

        st.success("✅ No vulnerabilities detected.")

        return

    for finding in scan.findings:

        if finding.severity == "Critical":

            st.error(
                f"""
### {finding.category}

**Severity:** {finding.severity}

**File:** {finding.file}

**Line:** {finding.line}

**Code:** `{finding.snippet}`

**Recommendation**

{finding.recommendation}
"""
            )

        elif finding.severity == "High":

            st.warning(
                f"""
### {finding.category}

**Severity:** {finding.severity}

**File:** {finding.file}

**Line:** {finding.line}

**Code:** `{finding.snippet}`

**Recommendation**

{finding.recommendation}
"""
            )

        else:

            st.info(
                f"""
### {finding.category}

**Severity:** {finding.severity}

**File:** {finding.file}

**Line:** {finding.line}

**Code:** `{finding.snippet}`

**Recommendation**

{finding.recommendation}
"""
            )