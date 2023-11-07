const API_URL = "http://localhost:8000";
const RELOAD_INTERVAL = 1000 // ms
var data = [];

const fetch_data = async () => {
    let last_ts = (data.length > 0 ? data[data.length-1].timestamp : 0)
    const res = await fetch(`${API_URL}/get_recent?last_timestamp=${last_ts}`);
    const response_text = await res.json();
    const new_data = await JSON.parse(response_text);
    
    new_data.forEach(element => {
        data.push(element); // store locally
        add_table_row(element);
    });
}

const add_table_row = (element) => {
    const table = document.getElementById("events-table");
    const row = table.insertRow(1);
    for (var key of Object.keys(element)) {
        row.innerHTML += `<th>${element[key]}</th>`
    }
}

// const print_rows = (data) => {
//     const dashboard_div = document.getElementById("rows");
//     dashboard_div.innerHTML = '';

//     data.forEach((item, index) => {
//         const p = document.createElement("p");
//         p.textContent = JSON.stringify(item);
//         dashboard_div.appendChild(p);
//     });
// }

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