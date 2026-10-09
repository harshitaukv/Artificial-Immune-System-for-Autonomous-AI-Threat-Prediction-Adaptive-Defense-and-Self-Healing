from fastapi.middleware.cors import CORSMiddleware

DEBUG = True
HOST = "0.0.0.0"


def configure(app):
    app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True)
