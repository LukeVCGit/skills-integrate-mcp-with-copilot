"""
High School Management System API

A super simple FastAPI application that allows students to view and sign up
for extracurricular activities at Mergington High School.
"""

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse
import hashlib
import hmac
import json
import os
from pathlib import Path

app = FastAPI(title="Mergington High School API",
              description="API for viewing and signing up for extracurricular activities")

# Mount the static files directory
current_dir = Path(__file__).parent
app.mount("/static", StaticFiles(directory=os.path.join(Path(__file__).parent,
          "static")), name="static")

TEACHERS_FILE = current_dir / "teachers.json"
SESSION_COOKIE = "teacher_session"
SESSION_SECRET = os.getenv("TEACHER_SESSION_SECRET", "mergington-dev-session-secret")


def load_teachers():
    if not TEACHERS_FILE.exists():
        return {}
    with open(TEACHERS_FILE, "r", encoding="utf-8") as file:
        data = json.load(file)
    return data if isinstance(data, dict) else {}


def verify_password(stored_password: str, password: str) -> bool:
    candidate_hash = hashlib.sha256(password.encode("utf-8")).hexdigest()
    return hmac.compare_digest(str(stored_password), candidate_hash)


def sign_username(username: str) -> str:
    signature = hmac.new(
        SESSION_SECRET.encode("utf-8"),
        username.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return f"{username}:{signature}"


def verify_session(request: Request) -> str | None:
    signed_session = request.cookies.get(SESSION_COOKIE)
    if not signed_session or ":" not in signed_session:
        return None

    username, _ = signed_session.rsplit(":", 1)
    if not hmac.compare_digest(sign_username(username), signed_session):
        return None
    if username not in load_teachers():
        return None
    return username


def require_teacher(request: Request) -> str:
    username = verify_session(request)
    if not username:
        raise HTTPException(status_code=401, detail="Teacher login required")
    return username

# In-memory activity database
activities = {
    "Chess Club": {
        "description": "Learn strategies and compete in chess tournaments",
        "schedule": "Fridays, 3:30 PM - 5:00 PM",
        "max_participants": 12,
        "participants": ["michael@mergington.edu", "daniel@mergington.edu"]
    },
    "Programming Class": {
        "description": "Learn programming fundamentals and build software projects",
        "schedule": "Tuesdays and Thursdays, 3:30 PM - 4:30 PM",
        "max_participants": 20,
        "participants": ["emma@mergington.edu", "sophia@mergington.edu"]
    },
    "Gym Class": {
        "description": "Physical education and sports activities",
        "schedule": "Mondays, Wednesdays, Fridays, 2:00 PM - 3:00 PM",
        "max_participants": 30,
        "participants": ["john@mergington.edu", "olivia@mergington.edu"]
    },
    "Soccer Team": {
        "description": "Join the school soccer team and compete in matches",
        "schedule": "Tuesdays and Thursdays, 4:00 PM - 5:30 PM",
        "max_participants": 22,
        "participants": ["liam@mergington.edu", "noah@mergington.edu"]
    },
    "Basketball Team": {
        "description": "Practice and play basketball with the school team",
        "schedule": "Wednesdays and Fridays, 3:30 PM - 5:00 PM",
        "max_participants": 15,
        "participants": ["ava@mergington.edu", "mia@mergington.edu"]
    },
    "Art Club": {
        "description": "Explore your creativity through painting and drawing",
        "schedule": "Thursdays, 3:30 PM - 5:00 PM",
        "max_participants": 15,
        "participants": ["amelia@mergington.edu", "harper@mergington.edu"]
    },
    "Drama Club": {
        "description": "Act, direct, and produce plays and performances",
        "schedule": "Mondays and Wednesdays, 4:00 PM - 5:30 PM",
        "max_participants": 20,
        "participants": ["ella@mergington.edu", "scarlett@mergington.edu"]
    },
    "Math Club": {
        "description": "Solve challenging problems and participate in math competitions",
        "schedule": "Tuesdays, 3:30 PM - 4:30 PM",
        "max_participants": 10,
        "participants": ["james@mergington.edu", "benjamin@mergington.edu"]
    },
    "Debate Team": {
        "description": "Develop public speaking and argumentation skills",
        "schedule": "Fridays, 4:00 PM - 5:30 PM",
        "max_participants": 12,
        "participants": ["charlotte@mergington.edu", "henry@mergington.edu"]
    }
}


@app.get("/")
def root():
    return RedirectResponse(url="/static/index.html")


@app.get("/activities")
def get_activities():
    return activities


@app.post("/login")
def login(username: str, password: str, response: Response):
    teachers = load_teachers()
    stored_password = teachers.get(username)
    if stored_password is None or not verify_password(stored_password, password):
        raise HTTPException(status_code=401, detail="Invalid username or password")

    response.set_cookie(
        key=SESSION_COOKIE,
        value=sign_username(username),
        httponly=True,
        samesite="lax",
    )
    return {"message": f"Logged in as {username}", "username": username}


@app.post("/logout")
def logout(response: Response):
    response.delete_cookie(key=SESSION_COOKIE)
    return {"message": "Logged out"}


@app.get("/session")
def get_session(request: Request):
    username = verify_session(request)
    if not username:
        return {"authenticated": False}
    return {"authenticated": True, "username": username}


@app.post("/activities/{activity_name}/signup")
def signup_for_activity(request: Request, activity_name: str, email: str):
    """Sign up a student for an activity"""
    require_teacher(request)

    # Validate activity exists
    if activity_name not in activities:
        raise HTTPException(status_code=404, detail="Activity not found")

    # Get the specific activity
    activity = activities[activity_name]

    # Validate student is not already signed up
    if email in activity["participants"]:
        raise HTTPException(
            status_code=400,
            detail="Student is already signed up"
        )

    # Add student
    activity["participants"].append(email)
    return {"message": f"Signed up {email} for {activity_name}"}


@app.delete("/activities/{activity_name}/unregister")
def unregister_from_activity(request: Request, activity_name: str, email: str):
    """Unregister a student from an activity"""
    require_teacher(request)

    # Validate activity exists
    if activity_name not in activities:
        raise HTTPException(status_code=404, detail="Activity not found")

    # Get the specific activity
    activity = activities[activity_name]

    # Validate student is signed up
    if email not in activity["participants"]:
        raise HTTPException(
            status_code=400,
            detail="Student is not signed up for this activity"
        )

    # Remove student
    activity["participants"].remove(email)
    return {"message": f"Unregistered {email} from {activity_name}"}
