"""High School Management System API."""

import hashlib
import hmac
import json
import os
import secrets
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException, Query, status
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

app = FastAPI(
    title="Mergington High School API",
    description="API for viewing and signing up for extracurricular activities",
)

current_dir = Path(__file__).parent
app.mount(
    "/static",
    StaticFiles(directory=os.path.join(current_dir, "static")),
    name="static",
)

USERS_FILE = current_dir / "users.json"
MUTATION_ROLES = {"admin", "staff"}


class LoginRequest(BaseModel):
    username: str
    password: str


def load_users() -> dict[str, dict[str, str]]:
    with USERS_FILE.open("r", encoding="utf-8") as users_file:
        users = json.load(users_file)

    return {user["username"]: user for user in users}


users = load_users()
active_tokens: dict[str, dict[str, str]] = {}


def verify_password(password: str, password_hash: str) -> bool:
    algorithm, iterations, salt, expected_hash = password_hash.split("$", 3)
    if algorithm != "pbkdf2_sha256":
        return False

    derived_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        int(iterations),
    ).hex()
    return hmac.compare_digest(derived_hash, expected_hash)


def create_access_token(user: dict[str, str]) -> str:
    token = secrets.token_urlsafe(32)
    active_tokens[token] = {
        "username": user["username"],
        "role": user["role"],
    }
    return token


def get_current_user(authorization: str | None = Header(default=None)) -> dict[str, str]:
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )

    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authorization header",
        )

    user = active_tokens.get(token)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired session",
        )

    return user


def require_mutation_role(
    current_user: dict[str, str] = Depends(get_current_user),
) -> dict[str, str]:
    if current_user["role"] not in MUTATION_ROLES:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin or staff access is required",
        )

    return current_user

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


@app.post("/auth/login")
def login(credentials: LoginRequest):
    user = users.get(credentials.username)
    if not user or not verify_password(credentials.password, user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    access_token = create_access_token(user)
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "username": user["username"],
            "role": user["role"],
        },
    }


@app.get("/auth/session")
def read_session(current_user: dict[str, str] = Depends(get_current_user)):
    return {"user": current_user}


@app.post("/auth/logout")
def logout(authorization: str | None = Header(default=None)):
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )

    _, _, token = authorization.partition(" ")
    if token in active_tokens:
        del active_tokens[token]

    return {"message": "Logged out successfully"}


@app.get("/activities")
def get_activities():
    return activities


@app.post("/activities/{activity_name}/signup")
def signup_for_activity(
    activity_name: str,
    email: str = Query(...),
    current_user: dict[str, str] = Depends(require_mutation_role),
):
    """Sign up a student for an activity."""
    if activity_name not in activities:
        raise HTTPException(status_code=404, detail="Activity not found")

    activity = activities[activity_name]

    if email in activity["participants"]:
        raise HTTPException(
            status_code=400,
            detail="Student is already signed up"
        )

    activity["participants"].append(email)
    return {
        "message": f"Signed up {email} for {activity_name}",
        "performed_by": current_user["username"],
    }


@app.delete("/activities/{activity_name}/unregister")
def unregister_from_activity(
    activity_name: str,
    email: str = Query(...),
    current_user: dict[str, str] = Depends(require_mutation_role),
):
    """Unregister a student from an activity."""
    if activity_name not in activities:
        raise HTTPException(status_code=404, detail="Activity not found")

    activity = activities[activity_name]

    if email not in activity["participants"]:
        raise HTTPException(
            status_code=400,
            detail="Student is not signed up for this activity"
        )

    activity["participants"].remove(email)
    return {
        "message": f"Unregistered {email} from {activity_name}",
        "performed_by": current_user["username"],
    }
