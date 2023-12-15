const express = require('express');
const nodemailer = require('nodemailer');
const speakeasy = require('speakeasy');
const bodyParser = require('body-parser');
const cors = require('cors');
const authRoutes = require("./routes/auth")
require('dotenv').config();
const app = express();
const PORT = process.env.PORT


app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cors());
app.use("/", authRoutes);



app.listen(PORT, () => {
  console.log(`Server is currently running on port ${PORT}`);
});
