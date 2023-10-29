import os
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
import pymongo
import json

load_dotenv()

mongo_client = pymongo.MongoClient(f"mongodb://{os.getenv('MONGO_HOST')}:{os.getenv('MONGO_PORT')}")
db = mongo_client[os.getenv('DB_NAME')]
collection = db["default"]
# data = {
#     "pid": 1,
#     "event_type": "example",
#     "path": "/example123",
#     "int1": 42,
#     "int2": 100
# }

# collection.insert_one(data)

app = FastAPI()

@app.get("/")
def read_root():
    data = list(collection.find({}))
    print(data)
    return json.dumps(data, default=str)

@app.post("/log")
async def log_one(request: Request):
    try:
        data = await request.json()
        collection.insert_one(data)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error inserting data: {str(e)}")