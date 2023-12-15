const mysql = require("mysql2");

const dbHost = process.env.DB_HOST;
const dbUser = process.env.DB_USER;
const dbPassword = process.env.DB_PASSWORD;
const database = process.env.DATABASE;

const db = mysql.createConnection({
    host:dbHost,
    user:dbUser,
    password:dbPassword,
    database:database,
});

module.exports = db;