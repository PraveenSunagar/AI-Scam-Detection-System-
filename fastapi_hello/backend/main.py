from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

app = FastAPI()

app.mount("/static", StaticFiles(directory="frontend/static"), name="static")

templates = Jinja2Templates(directory="frontend/templates")

# Home page
@app.get("/")
def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

# Register page
@app.get("/register")
def register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})

@app.get("/feedback")
def feedback_page(request: Request):
    return templates.TemplateResponse("feedback.html", {"request": request})

