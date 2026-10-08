import uvicorn
from backend.config import HOST, PORT, LOG_LEVEL

if __name__ == "__main__":
    uvicorn.run("backend.main:app", host=HOST, port=PORT, log_level=LOG_LEVEL.lower(), reload=False)
