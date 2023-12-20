const mysql = require("mysql2");
require('dotenv').config();

const dbHost = process.env.DB_HOST;
const dbUser = process.env.DB_USERNAME;
const dbPassword = process.env.DB_PASSWORD;
const database = process.env.DB_DBNAME;

const db = mysql.createConnection({
    host:dbHost,
    user:dbUser,
    password:dbPassword,
    database:database,
});

db.connect((err) => {
    if (err) {
      console.error('Error connecting to MySQL:', err);
      return;
    }
    console.log('Connected to MySQL!');
  });

module.exports = db;