module.exports = {
  client: "mysql2",
  connection: {
    host: "localhost",
    database: "TaskMate",
    user: "root",
    password: process.env.DATABASE_PASSWORD  // put password here
  }
}
