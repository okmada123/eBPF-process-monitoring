import json

# Alert levels
ALERT_ALLOW = 0
ALERT_DENY = 1

# Because we want to use these strings in the config-rules.json
EVENT_FORK = "fork"
EVENT_EXEC = "exec"
EVENT_OPEN = "open"
EVENT_CONNECT = "connect"
EVENT_ACCEPT = "accept"

EVENTS = {}
RULES = {}
COLUMNS = {}

with open("config-events.json", "r") as file:
    EVENTS = dict(json.load(file))

with open("config-rules.json", "r") as file:
    RULES = dict(json.load(file))

with open("config-columns.json", "r") as file:
    COLUMNS = dict(json.load(file))
