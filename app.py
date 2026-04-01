from flask import Flask
from flask_jwt_extended import JWTManager
from flask_cors import CORS
from dotenv import load_dotenv
from datetime import timedelta
import os

from models import db
from auth import register_routes as register_auth_routes
from device import register_device_routes
from siem import register_siem_routes
from soar import register_soar_routes
from blockchain_engine import create_genesis_block


def create_app():
    load_dotenv()

    app = Flask(__name__)

    # ------------------------------------------
    # Database Configuration
    # ------------------------------------------
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///secure_iot.db"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    # ------------------------------------------
    # JWT Configuration
    # ------------------------------------------
    app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY")

    if not app.config["JWT_SECRET_KEY"]:
        raise ValueError("JWT_SECRET_KEY not found in environment variables")

    # SAFE FIX: set explicit token expiry (default was 15 min from flask-jwt-extended,
    # but it is safer to declare it explicitly so it is never accidentally removed)
    app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(
        minutes=int(os.getenv("JWT_EXPIRES_MINUTES", "60"))
    )

    # ------------------------------------------
    # CORS — only allow your Lovable frontend
    # SAFE FIX: was missing entirely; any origin
    # could call the API from a browser.
    # Replace the URL below with your actual frontend domain.
    # ------------------------------------------
    allowed_origins = os.getenv(
        "CORS_ORIGINS",
        "http://localhost:5173"          # Lovable dev default
    ).split(",")

    CORS(app, origins=allowed_origins, supports_credentials=True)

    # ------------------------------------------
    # Initialize Extensions
    # ------------------------------------------
    db.init_app(app)
    JWTManager(app)

    # ------------------------------------------
    # Register All Route Modules
    # ------------------------------------------
    register_auth_routes(app)
    register_device_routes(app)
    register_siem_routes(app)
    register_soar_routes(app)

    # ------------------------------------------
    # Create Database Tables + Genesis Block
    # ------------------------------------------
    with app.app_context():
        db.create_all()
        create_genesis_block()

    return app


if __name__ == "__main__":
    app = create_app()

    # SAFE FIX: debug=True in production exposes an interactive
    # debugger that allows arbitrary code execution.
    # Read from env; default to False (safe).
    debug_mode = os.getenv("FLASK_DEBUG", "false").lower() == "true"

    app.run(host="0.0.0.0", port=5000, debug=debug_mode)