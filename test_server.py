import uvicorn
from main import app

if __name__ == "__main__":
    print("Starting CyberRazor backend server...")
    uvicorn.run(app, host="127.0.0.1", port=8080, log_level="info") 