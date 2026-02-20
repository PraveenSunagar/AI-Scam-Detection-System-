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







