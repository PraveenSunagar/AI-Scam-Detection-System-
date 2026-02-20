from fastapi import FastAPI, Request, Form
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from backend.services.auth_service import register_user, login_user
from pymongo import MongoClient
from passlib.context import CryptContext

app = FastAPI()

# Static folder
app.mount("/static", StaticFiles(directory="frontend/static"), name="static")

templates = Jinja2Templates(directory="frontend/templates")
pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")

# MongoDB connection
client = MongoClient("mongodb://127.0.0.1:27017")
db = client["scam_app"]
users = db["users"]

# ---------------- REGISTER ----------------
@app.post("/register")
def register(
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...)
):
    if not register_user(username, email, password):
        return {"error": "User already exists"}
    return {"message": "Register success"}

# ---------------- LOGIN ----------------
@app.post("/login")
def login(
    email: str = Form(...),
    password: str = Form(...)
):
    user = login_user(email, password)
    if not user:
        return {"error": "Invalid login"}

    return {
        "message": "Login success",
        "username": user["username"]   # 🔥 important for frontend
    }

# ---------------- HOME PAGE ----------------
@app.get("/")
def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

# ---------------- REGISTER PAGE ----------------
@app.get("/register")
def register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})

# ---------------- FEEDBACK PAGE ----------------
@app.get("/feedback")
def feedback_page(request: Request):
    return templates.TemplateResponse("feedback.html", {"request": request})

# ---------------- RESET PASSWORD ----------------
@app.post("/reset-password")
def reset_password(
    email: str = Form(...),
    new_password: str = Form(...)
):
    user = users.find_one({"email": email})
    if not user:
        return {"error": "Email not found"}

    hashed = pwd.hash(new_password)

    users.update_one(
        {"email": email},
        {"$set": {"password": hashed}}
    )

    return {"message": "Password reset success"}








