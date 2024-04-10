const { Pool } = require('pg');
const dotenv = require('dotenv');

dotenv.config();

// Connection to database notes-database

const client = new Pool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  database: process.env.DB_DATABASE,
  user: process.env.DB_USERNAME,
  password: process.env.DB_PASSWORD,
});

client.connect();

if (client.connect()) {
  console.log(`Connected to database ${process.env.DB_DATABASE}`);
}

module.exports = client;
