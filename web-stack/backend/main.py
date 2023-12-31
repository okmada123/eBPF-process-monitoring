import os
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request, Query
from fastapi.middleware.cors import CORSMiddleware
import pymongo
import json
import config
import re

load_dotenv()

mongo_client = pymongo.MongoClient(f"mongodb://{os.getenv('MONGO_HOST')}:{os.getenv('MONGO_PORT')}")
db = mongo_client[os.getenv('DB_NAME')]
collection = db["default"]

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def read_root():
    return "Hello, you've reached the API!!!"

@app.get("/delete_all")
def delete_all_rows():
    try:
        collection.delete_many({})
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Removing the rows failed. {str(e)}")

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
        raise HTTPException(status_code=400, detail=f"Error inserting data. {str(e)}")

@app.get("/get_recent")
def get_new_data(last_timestamp = Query(None)):
    try:
        last_timestamp = int(last_timestamp)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Bad request. Expecting ?last_timestamp=INTEGER. {str(e)}")
    data = list(collection.find({"timestamp": {"$gt": int(last_timestamp)}}))
    format_data(data)
    return json.dumps(data, default=str)

def format_data(data):
    for row in data:
        row.pop(config.COLUMNS["id"]) # remove mongo _id
        row[config.COLUMNS["type"]] = config.EVENTS[str(row[config.COLUMNS["type"]])] # replace event_type (integer) with text equivalent
        apply_rules(row) # apply rules to the data row
    return data

def get_rules(event_type):
    # Afaik, there is no better way to do this in Python, so I will leave this stupid double try/except code here :)
    allow_regexes = None
    deny_regexes = None
    try:
        allow_regexes = config.RULES[event_type]["Allow"]
    except KeyError:
        pass
    try:
        deny_regexes = config.RULES[event_type]["Deny"]
    except KeyError:
        pass
    if allow_regexes is not None and deny_regexes is not None:
        raise RuntimeError("Bad config. Only one of the fields 'Allow' and 'Deny' is allowed in 'config-rules.json' for an event.")
    return allow_regexes, deny_regexes

def is_matching(path, regexes):
    for rgx in regexes:
        if re.search(rgx, path) is not None:
            return True
    return False

def apply_rules(row):
    default_alert_level = config.ALERT_ALLOW
    row["alert_level"] = default_alert_level
    
    event_type = row[config.COLUMNS["type"]]
    get_rules(event_type)
    allow_regexes, deny_regexes = get_rules(event_type)
    if allow_regexes is None and deny_regexes is None: # No rules for this event
        return
    
    regexes = []
    matching_alert_level = None
    if allow_regexes is not None: # non-empty allow list means that everything is denied by default
        default_alert_level = config.ALERT_DENY
        regexes = allow_regexes
        matching_alert_level = config.ALERT_ALLOW
    else:
        default_alert_level = config.ALERT_ALLOW # non-empty deny list means that everything is allowed by default
        regexes = deny_regexes
        matching_alert_level = config.ALERT_DENY

    match_against = None
    if event_type == config.EVENT_EXEC or event_type == config.EVENT_OPEN:
        match_against = row[config.COLUMNS["path"]]
    elif event_type == config.EVENT_CONNECT:
        match_against = row[config.COLUMNS["output2"]]
    elif event_type == config.EVENT_ACCEPT:
        match_against = row[config.COLUMNS["output1"]]
    
    if match_against is None:
        return
    
    if is_matching(match_against, regexes):
        row["alert_level"] = matching_alert_level
    else:
        row["alert_level"] = default_alert_level
