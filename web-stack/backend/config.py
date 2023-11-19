import json
ALLOW_COLOR = "white"
DENY_COLOR = "red"
NEUTRAL_COLOR = "white"

EVENTS = {}
RULES = {}
COLUMNS = {}

with open("config-events.json", "r") as file:
    EVENTS = dict(json.load(file))

with open("config-rules.json", "r") as file:
    RULES = dict(json.load(file))

with open("config-columns.json", "r") as file:
    COLUMNS = dict(json.load(file))
