import streamlit as st
import requests
import pandas as pd
from streamlit_folium import st_folium
import folium
import jwt

API_URL = "http://localhost:8000"
JWT_SECRET = "supersecretjwtkey"
JWT_ALGORITHM = "HS256"
DEPARTMENTS = ["Sanitation", "Water", "Electricity", "Roads"]

def get_auth_header():
    if "token" not in st.session_state or not st.session_state.token:
        return {}
    return {"Authorization": f"Bearer {st.session_state.token}"}

# --- Session Persistence ---
def set_persistent_session(token, user, role, department=None):
    js = f"""
    <script>
    window.localStorage.setItem("token", "{token}");
    window.localStorage.setItem("user", "{user}");
    window.localStorage.setItem("role", "{role}");
    window.localStorage.setItem("department", "{department if department else ''}");
    </script>
    """
    st.components.v1.html(js, height=0)
def clear_persistent_session():
    js = """
    <script>
    window.localStorage.removeItem("token");
    window.localStorage.removeItem("user");
    window.localStorage.removeItem("role");
    window.localStorage.removeItem("department");
    </script>
    """
    st.components.v1.html(js, height=0)

# --- Register & Login ---
def login_form():
    with st.sidebar.form("login_form"):
        st.markdown("**🔐 Login**")
        username = st.text_input("Username", key="loginuser")
        password = st.text_input("Password", type="password", key="loginpass")
        submitted = st.form_submit_button("Login")
        if submitted:
            try:
                response = requests.post(
                    f"{API_URL}/login",
                    json={"username": username, "password": password}
                )
                if response.status_code == 200:
                    token = response.json()["access_token"]
                    payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
                    st.session_state.token = token
                    st.session_state.user = username
                    st.session_state.role = payload.get("role", "citizen")
                    st.session_state.department = payload.get("department", "")
                    set_persistent_session(token, username, st.session_state.role, st.session_state.department)
                    st.success("Logged in as " + username)
                    st.experimental_rerun()
                else:
                    st.error(response.json().get("detail", "Login failed"))
            except Exception as e:
                st.error(f"Connection error: {e}")

def register_form():
    with st.sidebar.form("register_form"):
        st.markdown("**📝 Register**")
        username = st.text_input("RegUsername")
        password = st.text_input("RegPassword", type="password")
        confirm = st.text_input("Confirm Password", type="password")
        role = st.selectbox("Role", ["citizen", "staff", "dept_head", "admin"])
        department = st.selectbox("Department (Staff/Head)", [""] + DEPARTMENTS) if role in ["staff", "dept_head"] else None
        if st.form_submit_button("Register"):
            if password != confirm:
                st.error("Passwords do not match")
                return
            data = {"username": username, "password": password, "role": role}
            if department and department != "": data["department"] = department
            try:
                response = requests.post(
                    f"{API_URL}/register",
                    json=data
                )
                if response.status_code == 201:
                    st.success("Registered! Please log in.")
                else:
                    st.error(response.json().get("detail", "Registration failed"))
            except Exception as e:
                st.error(f"Error: {e}")

# --------- Citizen ----------
def citizen_dashboard():
    st.markdown("## 🙋 My Profile & Complaints")
    # -- Profile
    try:
        response = requests.get(f"{API_URL}/profile/me", headers=get_auth_header())
        data = response.json() if response.status_code == 200 else {}
        with st.expander("Edit Profile"):
            full_name = st.text_input("Full Name", data.get("full_name", ""))
            email = st.text_input("Email", data.get("email", ""))
            phone = st.text_input("Phone", data.get("phone", ""))
            if st.button("Save Profile"):
                r = requests.post(
                    f"{API_URL}/profile/save",
                    json={"full_name": full_name, "email": email, "phone": phone},
                    headers=get_auth_header()
                )
                if r.status_code == 200:
                    st.success("Profile saved")
                else:
                    st.error("Profile save failed")
    except Exception as e:
        st.error(f"Error: {str(e)}")
    st.divider()
    st.markdown("### Submit a Complaint")
    with st.form("complaint_form"):
        description = st.text_area("Describe the issue(s)")
        department = st.selectbox("Department", DEPARTMENTS)
        category = st.text_input("Category (e.g. Garbage, Leakage, etc)")
        m = folium.Map(location=[18.5204, 73.8567], zoom_start=12)
        m.add_child(folium.LatLngPopup())
        map_data = st_folium(m, width=700, height=400)
        address = st.text_input("Landmark/Address (optional)")
        if st.form_submit_button("Submit Complaint"):
            if not description or not map_data.get("last_clicked"):
                st.error("Enter description and select map location")
            else:
                lat = float(map_data["last_clicked"]["lat"])
                lng = float(map_data["last_clicked"]["lng"])
                resp = requests.post(
                    f"{API_URL}/complaints/",
                    json={
                        "description": description,
                        "latitude": lat,
                        "longitude": lng,
                        "address": address,
                        "department": department,
                        "category": category
                    },
                    headers=get_auth_header()
                )
                if resp.status_code == 200:
                    st.success(f"Complaint submitted!")
                else:
                    st.error("Error submitting complaint")
    st.divider()
    st.markdown("### My Complaints")
    try:
        response = requests.get(f"{API_URL}/complaints/", headers=get_auth_header())
        complaints = response.json() if response.status_code == 200 else []
        if complaints:
            df = pd.DataFrame(complaints)
            st.dataframe(df[["id", "description", "status", "department", "category", "priority", "created_at"]], hide_index=True)
            chosen = st.selectbox("Show details for complaint ID", df["id"])
            show_pipeline(chosen)
        else:
            st.info("You have no complaints submitted yet.")
    except Exception as e:
        st.error(f"Error: {e}")

# --------- Staff ----------
def staff_dashboard():
    st.markdown("## 🛠 Staff Dashboard")
    try:
        response = requests.get(f"{API_URL}/complaints/", headers=get_auth_header())
        complaints = response.json() if response.status_code == 200 else []
        if complaints:
            df = pd.DataFrame(complaints)
            st.dataframe(df[["id", "description", "status", "department", "category", "priority", "created_at"]], hide_index=True)
            for idx, complaint in df.iterrows():
                with st.expander(f"Complaint #{complaint['id']}"):
                    show_pipeline(complaint["id"])
                    with st.form(f"update_{complaint['id']}"):
                        status = st.selectbox("Update Status", ["In Progress", "Resolved", "Closed", "Escalated", "Assigned", "Rejected"], key=f"st{complaint['id']}")
                        notes = st.text_area("Add Notes", key=f"note_st{complaint['id']}")
                        if st.form_submit_button("Submit Update"):
                            resp = requests.post(
                                f"{API_URL}/complaints/{complaint['id']}/action",
                                json={"status": status, "notes": notes},
                                headers=get_auth_header()
                            )
                            if resp.status_code == 200:
                                st.success("Update added.")
                                st.experimental_rerun()
                            else:
                                st.error("Could not update complaint.")
        else:
            st.info("No assigned complaints.")
    except Exception as e:
        st.error(f"Error: {e}")

# --------- Department Head ----------
def dept_head_dashboard():
    st.markdown("## 🏢 Department Head Dashboard")
    st.write(f"Department: `{st.session_state.department if st.session_state.department else 'N/A'}`")
    try:
        response = requests.get(f"{API_URL}/complaints/", headers=get_auth_header())
        complaints = response.json() if response.status_code == 200 else []
        if complaints:
            df = pd.DataFrame(complaints)
            st.dataframe(df[["id", "description", "status", "department", "category", "priority", "assigned_staff", "created_at"]], hide_index=True)
            for idx, complaint in df.iterrows():
                with st.expander(f"Complaint #{complaint['id']}"):
                    show_pipeline(complaint["id"])
                    assign_staff_ui(complaint["id"], st.session_state.department)
                    with st.form(f"update_{complaint['id']}"):
                        status = st.selectbox("Update Status", ["Assigned", "In Progress", "Resolved", "Escalated", "Rejected"], key=f"head{complaint['id']}")
                        notes = st.text_area("Add Notes", key=f"note_head{complaint['id']}")
                        if st.form_submit_button("Add Dept Update"):
                            resp = requests.post(
                                f"{API_URL}/complaints/{complaint['id']}/action",
                                json={"status": status, "notes": notes},
                                headers=get_auth_header()
                            )
                            if resp.status_code == 200:
                                st.success("Update added.")
                                st.experimental_rerun()
                            else:
                                st.error("Unable to update status.")
        else:
            st.info("No complaints for your department.")
    except Exception as e:
        st.error(f"Error: {e}")

def assign_staff_ui(complaint_id, department):
    staff_list = get_users_by_role("staff", department)
    if staff_list:
        staff_usernames = [u["username"] for u in staff_list]
        staff_username = st.selectbox("Assign Staff Username", staff_usernames, key=f"staff_assign_{complaint_id}")
        if st.button(f"Assign #{complaint_id}"):
            resp2 = requests.post(
                f"{API_URL}/complaints/{complaint_id}/assign",
                json={"staff_username": staff_username},
                headers=get_auth_header()
            )
            if resp2.status_code == 200:
                st.success(f"Assigned to {staff_username}")
                st.experimental_rerun()
            else:
                st.error(resp2.text)
    else:
        st.info("No staff available.")

def get_users_by_role(role, department=None):
    params = {"role": role}
    if department: params["department"] = department
    try:
        resp = requests.get(f"{API_URL}/users_by_role", params=params, headers=get_auth_header())
        return resp.json() if resp.status_code==200 else []
    except:
        return []

# --------- Admin ----------
def admin_dashboard():
    st.markdown("## ⚡ Admin Dashboard")

    st.markdown("### Complaint Data Table")
    try:
        r = requests.get(f"{API_URL}/complaints/", headers=get_auth_header())
        if r.status_code == 200:
            df = pd.DataFrame(r.json())
            st.dataframe(df[["id","description","status","department","category","priority","assigned_staff","created_at"]], hide_index=True)
        else:
            st.warning("No complaint data found")
    except Exception as e:
        st.warning("Complaint data failed")
    st.markdown("### Change Complaint Priority")
    try:
        if not df.empty:
            for cid in df["id"]:
                with st.expander(f"Priority for Complaint {cid}"):
                    priority = st.selectbox("Set Priority", ["High","Medium","Low","Normal"], key=f"priority_{cid}")
                    if st.button(f"Update Priority {cid}"):
                        resp = requests.post(
                            f"{API_URL}/complaints/{cid}/priority",
                            json={"priority": priority},
                            headers=get_auth_header()
                        )
                        if resp.status_code == 200:
                            st.success("Priority updated.")
                        else:
                            st.error(resp.text)
    except Exception as e:
        st.info("No complaints for priority update.")

    st.divider()
    st.markdown("### 📊 Analytics")
    try:
        col1, col2, col3 = st.columns(3)
        with col1:
            r = requests.get(f"{API_URL}/analytics/counts-by-category", headers=get_auth_header())
            if r.status_code == 200: st.bar_chart(r.json())
        with col2:
            r = requests.get(f"{API_URL}/analytics/counts-by-department", headers=get_auth_header())
            if r.status_code == 200: st.bar_chart(r.json())
        with col3:
            r = requests.get(f"{API_URL}/analytics/counts-by-status", headers=get_auth_header())
            if r.status_code == 200: st.bar_chart(r.json())
    except Exception as e:
        st.warning("Analytics failed")

    st.markdown("### 🗺️ Complaints Heat Map")
    try:
        r = requests.get(f"{API_URL}/analytics/locations", headers=get_auth_header())
        if r.status_code == 200:
            m = folium.Map(location=[18.52, 73.85], zoom_start=12)
            for loc in r.json():
                color = {"Submitted":"orange","Resolved":"green"}.get(loc["status"],"blue")
                folium.CircleMarker(
                    location=[loc["lat"], loc["lon"]],
                    radius=7,
                    color=color, fill=True,
                    popup=f"Status: {loc['status']}"
                ).add_to(m)
            st_folium(m, width=1100, height=400)
    except Exception as e:
        st.info("Map not available.")

def show_pipeline(complaint_id):
    try:
        resp = requests.get(f"{API_URL}/complaints/{complaint_id}/pipeline", headers=get_auth_header())
        if resp.status_code == 200:
            data = resp.json()
            st.write(f"Status: **{data['complaint']['status']}** | Priority: **{data['complaint']['priority']}** | Assigned Staff: **{data['complaint'].get('assigned_staff','')}**")
            actions = pd.DataFrame(data["pipeline"])
            if not actions.empty:
                actions["created_at"] = pd.to_datetime(actions["created_at"])
                st.write("#### Timeline")
                st.table(actions[["created_at", "actor", "role", "new_status", "notes"]])
        else:
            st.warning("No timeline available.")
    except Exception as e:
        st.error(f"Error: {str(e)}")

def main():
    st.set_page_config(page_title="Smart City Complaints", page_icon="🏙️", layout="wide")
    st.markdown("<h1 style='text-align:center;color:#20639B;font-size:3rem;'>🏙️ GrievanceGrid - Smart City Municipal Complaint System</h1>",
                unsafe_allow_html=True)
    st.markdown(
        "<div style='color:#3CAEA3;text-align:center;'>Full-Stack Smart Municipal Dashboard</div>",
        unsafe_allow_html=True)
    if "token" not in st.session_state:
        st.session_state.token = None
        st.session_state.user = None
        st.session_state.role = None
        st.session_state.department = None
    with st.sidebar:
        st.title("🔑 Account")
        if not st.session_state.token:
            register_form()
            login_form()
        else:
            st.success(f"Logged in as: {st.session_state.user} ({st.session_state.role})")
            if st.button("Logout"):
                st.session_state.clear()
                clear_persistent_session()
                st.experimental_rerun()
    if st.session_state.token:
        st.sidebar.write("---")
        if st.session_state.role == "citizen": citizen_dashboard()
        elif st.session_state.role == "staff": staff_dashboard()
        elif st.session_state.role == "dept_head": dept_head_dashboard()
        elif st.session_state.role == "admin": admin_dashboard()
        else:
            st.warning("Unknown role")

if __name__ == "__main__":
    main()
