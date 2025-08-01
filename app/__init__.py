import os
from flask import Flask
from flask_cors import CORS  # 🔥 Add CORS
from dotenv import load_dotenv

load_dotenv()

from .routes import main, encryption_bp, chatbot_bp

def create_app():
    # Serve static assets like style.css and firebase-auth.js
    static_folder_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'static'))

    app = Flask(__name__, static_folder=static_folder_path, static_url_path='/static')

    app.secret_key = os.environ.get("SECRET_KEY", "supersecretkey")

    # ✅ Enable CORS for all origins and credentials support
    CORS(app, supports_credentials=True)

    # Register all blueprints
    app.register_blueprint(main)
    app.register_blueprint(encryption_bp)
    app.register_blueprint(chatbot_bp)

    return app
