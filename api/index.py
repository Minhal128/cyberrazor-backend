import sys
import os

# Add the parent directory to the path so we can import main_mongo
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from main_mongo import app

# This is the entry point for Vercel
app = app
