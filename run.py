import os
from pathlib import Path
from app import create_app

app = create_app()

if __name__ == '__main__':
    # For Render: bind to 0.0.0.0 and use the PORT env variable
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 10000)), debug=True)
