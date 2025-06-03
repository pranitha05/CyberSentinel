import os
from flask import Flask
from .routes import main

def create_app():
    # Calculate absolute path to the 'static' folder (which is outside 'app')
    static_folder_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'static'))
    
    app = Flask(__name__, static_folder=static_folder_path, static_url_path='/static')
    app.register_blueprint(main)
    return app
