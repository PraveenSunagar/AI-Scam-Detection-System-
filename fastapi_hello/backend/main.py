from fastapi import FastAPI, Request, Form
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from backend.services.auth_service import register_user, login_user
from pymongo import MongoClient
from passlib.context import CryptContext






