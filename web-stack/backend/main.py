import os
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request, Query
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime
import pymongo
import json
import config

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
    format_data(data)
    return json.dumps(data, default=str)

# Dump everything, unformatted
@app.get("/get_all")
def get_all_data():
    data = list(collection.find({}))
    return json.dumps(data, default=str)

@app.post("/log")
async def log_one(request: Request):
    try:
        data = await request.json()
        collection.insert_one(data)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error inserting data: {str(e)}")

# TODO - change
def color(row):
    if row[config.COLUMNS["type"]] == "fork":
        row["color"] = "blue"
    elif row[config.COLUMNS["type"]] == "open":
        row["color"] = "white"
    elif row[config.COLUMNS["type"]] == "exec":
        row["color"] = "red"
    elif row[config.COLUMNS["type"]] == "connect":
        row["color"] = "green"

def format_data(data):
    for row in data:
        row.pop(config.COLUMNS["id"]) # remove mongo _id
        row[config.COLUMNS["type"]] = config.EVENTS[str(row[config.COLUMNS["type"]])] # replace event_type (integer) with text equivalent
        color(row) # apply correct color to the data row
    return data