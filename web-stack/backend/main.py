import os
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request, Query
from fastapi.middleware.cors import CORSMiddleware
import pymongo
import json

load_dotenv()

mongo_client = pymongo.MongoClient(f"mongodb://{os.getenv('MONGO_HOST')}:{os.getenv('MONGO_PORT')}")
db = mongo_client[os.getenv('DB_NAME')]
collection = db["default"]

app = FastAPI()
origins = ["*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def read_root():
    return "Hello!!!"

@app.get("/get_recent")
def get_new_data(last_timestamp = Query(None)):
    try:
        last_timestamp = int(last_timestamp)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Bad request. Expecting ?last_timestamp=INTEGER. {str(e)}")
    data = list(collection.find({"timestamp": {"$gt": int(last_timestamp)}}))
    #print(data)
    return json.dumps(data, default=str)

@app.get("/get_all")
def get_all_data():
    data = list(collection.find({}))
    #print(data)
    return json.dumps(data, default=str)

@app.post("/log")
async def log_one(request: Request):
    try:
        data = await request.json()
        collection.insert_one(data)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error inserting data: {str(e)}")