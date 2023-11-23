const API_URL = "http://localhost:8080/api";
const RELOAD_INTERVAL = 1000 // ms
var data = [];
var show_only_alerts = false;
const ALERT_COLOR = "red"; // TODO - change

const COLOR_SETTINGS = {
    0: "white", // default color
    1: "red", // alert color
}

// Alert levels
const ALERT_ALLOW = 0
const ALERT_DENY = 1

const delete_all = async () => {
    const res = await fetch(`${API_URL}/delete_all`);
    if (res.status != 200) {
        const response_text = await res.text();
        alert("Deleting all failed " + response_text);
        return;
    }

    data = []; // clear the local data array
    // clear the table
    const table = document.getElementById("events-table");
    while (table.rows.length != 1) table.deleteRow(1);
}

const toggle_show_only_alerts = () => {
    show_only_alerts = !show_only_alerts;
    
    // clear the table
    const table = document.getElementById("events-table");
    while (table.rows.length != 1) table.deleteRow(1);

    data.forEach(element => {
        if (show_only_alerts) {
            if (element.alert_level == ALERT_DENY) {
                add_table_row(element);
            }
        }
        else add_table_row(element);
    })
}

const fetch_data = async () => {
    let last_ts = (data.length > 0 ? data[data.length-1].timestamp : 0)
    const res = await fetch(`${API_URL}/get_recent?last_timestamp=${last_ts}`);
    const response_text = await res.json();
    const new_data = JSON.parse(response_text);
    
    new_data.forEach(element => {
        data.push(element); // store locally
        
        if (show_only_alerts) {
            if (element.alert_level == ALERT_DENY) {
                add_table_row(element);
            }
        }
        else add_table_row(element);
    });
}

const add_table_row = (element) => {
    const table = document.getElementById("events-table");
    const row = table.insertRow(1);
    let formatted_timestamp = new Date(element["timestamp"]).toISOString().slice(-13, -1) // source: https://stackoverflow.com/questions/847185/convert-a-unix-timestamp-to-time-in-javascript
    row.innerHTML += `<th>${formatted_timestamp}</th>`
    row.innerHTML += `<th>${element["pid"]}</th>`
    row.innerHTML += `<th>${element["event_type"]}</th>`
    row.innerHTML += `<th>${element["path"]}</th>`
    row.innerHTML += `<th>${element["event_output_1"]}</th>`
    row.innerHTML += `<th>${element["event_output_2"]}</th>`
    row.style.backgroundColor = COLOR_SETTINGS[element["alert_level"]]
}

const mainloop = async () => {
    while (true) {
        try {
            await fetch_data();
        } catch (err) {
            console.error(err);
            break;
        }
        await new Promise(resolve => setTimeout(resolve, RELOAD_INTERVAL));
    }
}

mainloop();