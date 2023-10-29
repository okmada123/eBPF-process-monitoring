const conn = new Mongo();
const dbs = conn.getDBNames();

if (dbs.indexOf('monitoringDb') == -1) {
  const db = conn.getDB('monitoringDb');

  db.createCollection('default');
//   const collection = db.pid;
//   // collection.createIndex({ pid: 1 });
//   collection.insertOne(
//     {
//       pid: 1,
//       event_type: "event1",
//       path: "/path1",
//       int1: 42,
//       int2: 100,
//     }
//   );
}