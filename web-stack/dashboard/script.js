const API_URL = "http://localhost:8000";
const RELOAD_INTERVAL = 1000 // ms
var data = [];

const fetch_data = async () => {
    let last_ts = (data.length > 0 ? data[data.length-1].timestamp : 0)
    const res = await fetch(`${API_URL}/get_recent?last_timestamp=${last_ts}`);
    const response_text = await res.json();
    const new_data = JSON.parse(response_text);
    
    new_data.forEach(element => {
        data.push(element); // store locally
        add_table_row(element);
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
    row.innerHTML += `<th>${element["event_output_int_1"]}</th>`
    row.innerHTML += `<th>${element["event_output_int_2"]}</th>`
    row.style.backgroundColor = element["color"]
    
    // This dumps the row in the order that it comes in from backend
    // for (var key of Object.keys(element)) {
    //     row.innerHTML += `<th>${element[key]}</th>`
    // }
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