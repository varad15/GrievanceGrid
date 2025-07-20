from fastapi import FastAPI, Depends, HTTPException, Header, Body
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List
from sqlalchemy import (
    create_engine, Column, Integer, String, Boolean, Text, Float, DateTime,
    MetaData, Table, select, update, ForeignKey
)
from sqlalchemy.orm import sessionmaker
from passlib.context import CryptContext
import jwt
import datetime

JWT_SECRET = "supersecretjwtkey"
JWT_ALGORITHM = "HS256"
JWT_EXP_DELTA_SECONDS = 3600
DEPARTMENTS = ["Sanitation", "Water", "Electricity", "Roads"]

DATABASE_URL = "sqlite:///./test.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
metadata = MetaData()
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

users = Table(
    "users", metadata,
    Column("id", Integer, primary_key=True),
    Column("username", String, unique=True, index=True, nullable=False),
    Column("hashed_password", String, nullable=False),
    Column("role", String, default="citizen"),
    Column("department", String, nullable=True)
)

user_profiles = Table(
    "user_profiles", metadata,
    Column("id", Integer, primary_key=True),
    Column("username", String, unique=True),
    Column("full_name", String),
    Column("email", String),
    Column("phone", String)
)

alerts = Table(
    "alerts", metadata, Column("id", Integer, primary_key=True), Column("message", Text)
)
notices = Table(
    "notices", metadata, Column("id", Integer, primary_key=True), Column("message", Text)
)

complaints = Table(
    "complaints", metadata,
    Column("id", Integer, primary_key=True),
    Column("username", String),
    Column("description", Text),
    Column("latitude", Float),
    Column("longitude", Float),
    Column("address", String),
    Column("department", String),
    Column("category", String),
    Column("status", String, default="Submitted"),
    Column("priority", String, default="Normal"),
    Column("assigned_staff", String, nullable=True),
    Column("assigned_head", String, nullable=True),
    Column("created_at", String, default=lambda: str(datetime.datetime.utcnow()))
)

complaint_actions = Table(
    "complaint_actions", metadata,
    Column("id", Integer, primary_key=True),
    Column("complaint_id", Integer, ForeignKey("complaints.id")),
    Column("actor", String),
    Column("role", String),
    Column("new_status", String),
    Column("notes", Text),
    Column("created_at", DateTime, default=datetime.datetime.utcnow)
)

metadata.create_all(engine)

role_hierarchy = {
    "admin": 4,
    "dept_head": 3,
    "staff": 2,
    "citizen": 1
}

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain, hashed) -> bool:
    return pwd_context.verify(plain, hashed)

def create_jwt_token(username: str, role: str, department: Optional[str]=None) -> str:
    payload = {
        "username": username,
        "role": role,
        "department": department,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(seconds=JWT_EXP_DELTA_SECONDS)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def decode_jwt_token(token: str):
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

def get_current_user(authorization: str = Header(...)):
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid auth header")
    token = authorization[7:]
    return decode_jwt_token(token)

def require_role(*roles):
    def check(user=Depends(get_current_user)):
        if user["role"] not in roles:
            raise HTTPException(status_code=403, detail=f"Requires one of: {roles}")
        return user
    return check

class UserCreate(BaseModel):
    username: str
    password: str
    role: Optional[str] = "citizen"
    department: Optional[str] = None

class UserLogin(BaseModel):
    username: str
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"

class UserProfileIn(BaseModel):
    full_name: Optional[str]
    email: Optional[str]
    phone: Optional[str]

class AlertIn(BaseModel):
    message: str

class NoticeIn(BaseModel):
    message: str

class ComplaintIn(BaseModel):
    description: str
    latitude: float
    longitude: float
    address: Optional[str]
    department: str
    category: str

class ComplaintActionIn(BaseModel):
    status: str
    notes: Optional[str] = None

app = FastAPI(
    title="Smart City Complaint System",
    description="All analytics, heat map, tables, role-locked status. Admin can't change status.",
    version="5.0.0"
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_credentials=True,
    allow_methods=["*"], allow_headers=["*"]
)

@app.post("/register", status_code=201)
def register(user: UserCreate):
    with SessionLocal() as session:
        result = session.execute(select(users).where(users.c.username == user.username))
        if result.first():
            raise HTTPException(status_code=400, detail="Username already exists")
        if user.role in ["dept_head", "staff"]:
            if user.department not in DEPARTMENTS:
                raise HTTPException(status_code=400, detail="Staff/head registration requires valid department.")
        session.execute(users.insert().values(
            username=user.username,
            hashed_password=hash_password(user.password),
            role=user.role,
            department=user.department if user.role in ["dept_head", "staff"] else None
        ))
        session.commit()
    return {"message": "User registered successfully"}

@app.post("/login", response_model=TokenResponse)
def login(user: UserLogin):
    with SessionLocal() as session:
        result = session.execute(select(users).where(users.c.username == user.username))
        row = result.mappings().first()
        if not row or not verify_password(user.password, row["hashed_password"]):
            raise HTTPException(status_code=401, detail="Invalid credentials")
        token = create_jwt_token(row["username"], row["role"], row["department"])
        return TokenResponse(access_token=token)

@app.get("/profile/me")
def get_profile(current_user=Depends(get_current_user)):
    with SessionLocal() as session:
        result = session.execute(select(user_profiles).where(user_profiles.c.username == current_user["username"]))
        row = result.mappings().first()
        return dict(row) if row else {}

@app.post("/profile/save")
def save_profile(profile: UserProfileIn, current_user=Depends(get_current_user)):
    with SessionLocal() as session:
        result = session.execute(select(user_profiles).where(user_profiles.c.username == current_user["username"]))
        if result.first():
            session.execute(
                update(user_profiles)
                .where(user_profiles.c.username == current_user["username"])
                .values(**profile.dict())
            )
        else:
            session.execute(
                user_profiles.insert().values(username=current_user["username"], **profile.dict())
            )
        session.commit()
    return {"message": "Profile saved"}

@app.get("/alerts")
def get_alerts():
    with SessionLocal() as session:
        result = session.execute(select(alerts))
        return [dict(r) for r in result.mappings().all()]

@app.post("/alerts", dependencies=[Depends(require_role("admin", "dept_head"))])
def post_alert(alert: AlertIn):
    with SessionLocal() as session:
        session.execute(alerts.insert().values(message=alert.message))
        session.commit()
    return {"message": "Alert posted"}

@app.get("/notices")
def get_notices():
    with SessionLocal() as session:
        result = session.execute(select(notices))
        return [dict(r) for r in result.mappings().all()]

@app.post("/notices", dependencies=[Depends(require_role("admin", "dept_head"))])
def post_notice(notice: NoticeIn):
    with SessionLocal() as session:
        session.execute(notices.insert().values(message=notice.message))
        session.commit()
    return {"message": "Notice posted"}

@app.post("/complaints/")
def submit_complaint(c: ComplaintIn, current_user=Depends(require_role("citizen", "admin"))):
    with SessionLocal() as session:
        result = session.execute(complaints.insert().values(
            username=current_user["username"],
            description=c.description,
            latitude=c.latitude, longitude=c.longitude, address=c.address,
            department=c.department, category=c.category, priority="Normal",
            status="Submitted",
            created_at=str(datetime.datetime.utcnow())
        ))
        complaint_id = result.lastrowid if hasattr(result, "lastrowid") else None
        session.execute(complaint_actions.insert().values(
            complaint_id=complaint_id,
            actor=current_user["username"],
            role=current_user["role"],
            new_status="Submitted",
            notes="Complaint submitted",
            created_at=datetime.datetime.utcnow()
        ))
        session.commit()
        return {"message": "Complaint submitted", "id": complaint_id, "department": c.department, "category": c.category}

@app.get("/complaints/")
def list_user_complaints(current_user=Depends(get_current_user)):
    with SessionLocal() as session:
        if current_user["role"] == "citizen":
            query = select(complaints).where(complaints.c.username == current_user["username"])
        elif current_user["role"] == "staff":
            query = select(complaints).where(complaints.c.assigned_staff == current_user["username"])
        elif current_user["role"] == "dept_head":
            query = select(complaints).where(complaints.c.department == current_user["department"])
        else:  # admin
            query = select(complaints)
        result = session.execute(query)
        return [dict(r) for r in result.mappings().all()]

@app.get("/complaints/{complaint_id}/pipeline")
def get_complaint_pipeline(complaint_id: int, current_user=Depends(get_current_user)):
    with SessionLocal() as session:
        c_row = session.execute(select(complaints).where(complaints.c.id == complaint_id)).mappings().first()
        if not c_row:
            raise HTTPException(404, detail="Complaint not found.")
        allowed = (
            current_user["role"] in ["admin"] or
            c_row["username"] == current_user["username"] or
            (current_user["role"] == "dept_head" and c_row["department"] == current_user.get("department")) or
            (current_user["role"] == "staff" and c_row["assigned_staff"] == current_user["username"])
        )
        if not allowed:
            raise HTTPException(403, detail="Access denied.")
        actions = session.execute(
            select(complaint_actions).where(complaint_actions.c.complaint_id == complaint_id).order_by(complaint_actions.c.created_at)
        ).mappings().all()
        return {"complaint": dict(c_row), "pipeline": [dict(a) for a in actions]}

@app.post("/complaints/{complaint_id}/assign")
def assign_complaint(
    complaint_id: int,
    staff_username: str = Body(..., embed=True),
    current_user=Depends(require_role("dept_head"))
):
    with SessionLocal() as session:
        c_row = session.execute(select(complaints).where(complaints.c.id == complaint_id)).mappings().first()
        if not c_row or c_row["department"] != current_user.get("department"):
            raise HTTPException(403, detail="Cannot assign complaint outside your department.")
        s_row = session.execute(
            select(users).where(users.c.username == staff_username).where(users.c.role == "staff")
        ).mappings().first()
        if not s_row or s_row["department"] != current_user["department"]:
            raise HTTPException(403, detail="Selected staff not in your department.")
        session.execute(update(complaints).where(complaints.c.id == complaint_id)
                       .values(assigned_staff=staff_username, assigned_head=current_user["username"], status="Assigned"))
        session.execute(complaint_actions.insert().values(
            complaint_id=complaint_id,
            actor=current_user["username"],
            role=current_user["role"],
            new_status="Assigned",
            notes=f"Assigned to staff: {staff_username}",
            created_at=datetime.datetime.utcnow()
        ))
        session.commit()
        return {"message": f"Complaint assigned to {staff_username}"}

@app.post("/complaints/{complaint_id}/action")
def update_complaint_status(
    complaint_id: int,
    action: ComplaintActionIn,
    current_user=Depends(require_role("staff", "dept_head"))
):
    with SessionLocal() as session:
        c_row = session.execute(select(complaints).where(complaints.c.id == complaint_id)).mappings().first()
        if not c_row:
            raise HTTPException(404, detail="Complaint not found.")
        allowed = (
            (current_user["role"] == "dept_head" and c_row["department"] == current_user.get("department")) or
            (current_user["role"] == "staff" and c_row["assigned_staff"] == current_user["username"])
        )
        if not allowed:
            raise HTTPException(403, detail="Not authorized to update this complaint.")
        session.execute(update(complaints).where(complaints.c.id == complaint_id)
                       .values(status=action.status))
        session.execute(complaint_actions.insert().values(
            complaint_id=complaint_id,
            actor=current_user["username"],
            role=current_user["role"],
            new_status=action.status,
            notes=action.notes or "",
            created_at=datetime.datetime.utcnow()
        ))
        session.commit()
        return {"message": f"Complaint status updated to {action.status}"}

@app.post("/complaints/{complaint_id}/priority")
def set_priority(
    complaint_id: int,
    priority: str = Body(..., embed=True),
    current_user=Depends(require_role("admin"))
):
    if priority not in ["High", "Medium", "Low", "Normal"]:
        raise HTTPException(400, detail="Invalid priority")
    with SessionLocal() as session:
        session.execute(update(complaints).where(complaints.c.id == complaint_id).values(priority=priority))
        session.commit()
    return {"message": "Priority updated"}

@app.get("/users_by_role")
def users_by_role(
    role: str,
    department: Optional[str] = None,
    user=Depends(get_current_user)
):
    with SessionLocal() as session:
        query = select(users).where(users.c.role == role)
        if department:
            query = query.where(users.c.department == department)
        result = session.execute(query)
        return [dict(u) for u in result.mappings().all()]

@app.get("/admin/user-count")
def admin_user_count(user=Depends(require_role("admin"))):
    with SessionLocal() as session:
        result = session.execute(select(users.c.id))
        return {"user_count": len(result.fetchall())}

@app.get("/analytics/counts-by-status")
def analytics_counts_by_status(user=Depends(require_role("admin", "dept_head"))):
    with SessionLocal() as session:
        result = session.execute(select(complaints.c.status))
        stat_counts = {}
        for row in result.fetchall():
            k = row[0]
            stat_counts[k] = stat_counts.get(k,0)+1
        return stat_counts

@app.get("/analytics/counts-by-category")
def analytics_counts_by_category(user=Depends(require_role("admin", "dept_head"))):
    with SessionLocal() as session:
        result = session.execute(select(complaints.c.category))
        cat_counts = {}
        for row in result.fetchall():
            k = row[0]
            cat_counts[k] = cat_counts.get(k,0)+1
        return cat_counts

@app.get("/analytics/counts-by-department")
def analytics_counts_by_department(user=Depends(require_role("admin", "dept_head"))):
    with SessionLocal() as session:
        result = session.execute(select(complaints.c.department))
        dep_counts = {}
        for row in result.fetchall():
            k = row[0]
            dep_counts[k] = dep_counts.get(k,0)+1
        return dep_counts

@app.get("/analytics/locations")
def analytics_locations(user=Depends(require_role("admin", "dept_head"))):
    with SessionLocal() as session:
        result = session.execute(select(complaints.c.latitude, complaints.c.longitude, complaints.c.status))
        locations = []
        for lat, lon, status in result.fetchall():
            try:
                latf, lonf = float(lat), float(lon)
                locations.append({"lat": latf, "lon": lonf, "status": status})
            except Exception:
                continue
        return locations
#uvicorn backend:app --reload --host 0.0.0.0 --port 8000