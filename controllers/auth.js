const db = require("../database/db");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const nodemailer = require('nodemailer');
const speakeasy = require('speakeasy');



const register = (req, res) => {
  const query = "SELECT * FROM users WHERE email = ? OR username = ?";
  const { email, username } = req.body;
  const secret = speakeasy.generateSecret({ length: 20 });

  const otp = speakeasy.totp({
      secret: secret.base32,
      encoding: 'base32',
      window: 1,
  });

  otpStorage.set(email, { otp, secret: secret.base32 });

  console.log('Recipient email:', email);  // Add this log statement

  const trimmedEmail = email.trim();
  const mailOptions = {
      from: 'eyidana001@gmail.com',
      to: trimmedEmail,
      subject: 'Your OTP for Verification',
      text: `Your OTP is ${otp}`,
  };

  if (!trimmedEmail || !/^\S+@\S+\.\S+$/.test(trimmedEmail)) {
      console.error('Invalid or empty email address');
      return res.status(400).send('Invalid or empty email address');
  }

  transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
          console.error('Error sending email:', error);
          return res.status(500).send('Internal Server Error');
      }

      // Continue with the database query only after sending the email
      db.query(query, [trimmedEmail, username], (err, data) => {
          if (err) {
              console.error('Database query error:', err);
              return res.status(500).json(err);
          }

          if (data.length) {
              return res.status(409).json("User already exists");
          }

          const salt = bcrypt.genSaltSync(10);
          const hash = bcrypt.hashSync(req.body.password, salt);

          const insertQuery = "INSERT INTO users(`username`, `email`, `password`) VALUES(?)";
          const values = [
              req.body.username,
              trimmedEmail,
              hash,
          ];

          db.query(insertQuery, [values], (insertErr, insertData) => {
              if (insertErr) {
                  console.error('Insert query error:', insertErr);
                  return res.status(500).json(insertErr);
              }

              return res.status(201).json("User created successfully");
          });
      });
  });
};


const login = (req, res) => {
  const query = "SELECT * FROM users WHERE email = ?";
  db.query(query, [req.body.email], (err, data) => {
      if (err) {
          console.error('Database query error:', err);
          return res.status(500).json(err);
      }
      
      if (data.length === 0) {
          return res.status(404).json("User not found!");
      }

      const isPasswordCorrect = bcrypt.compareSync(req.body.password, data[0].password);

      if (!isPasswordCorrect) {
          return res.status(400).json("Wrong username or password!");
      }

      try {
          const token = jwt.sign({ id: data[0].id }, "jwtkey");
          const { password, ...other } = data[0];

          res.cookie("access_token", token, {
              httpOnly: true
          }).status(200).json(other);
      } catch (jwtError) {
          console.error('JWT token creation error:', jwtError);
          return res.status(500).json(jwtError);
      }
  });
};



const otpStorage = new Map();

const transporter = nodemailer.createTransport({
  host: 'smtp.gmail.com',
  port: 587,
  secure: false, // true for 465, false for other ports
  auth: {
    user: 'eyidana001@gmail.com',
    pass: 'rukq qdrd enur cfrk', 
  },
});



const sendOtp = (req, res) => {
  const { email } = req.body;
  const secret = speakeasy.generateSecret({ length: 20 });

  const otp = speakeasy.totp({
    secret: secret.base32,
    encoding: 'base32',
    window: 1
  });

  otpStorage.set(email, { otp, secret: secret.base32 });

  const mailOptions = {
    from: 'eyidana001@gmail.com',
    to: email,
    subject: 'Your OTP for Verification',
    text: `Your OTP is ${otp}`,
  };

  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      console.error('Error sending email:', error);
      res.status(500).send('Internal Server Error');
    } else {
      console.log('Email sent:', mailOptions.text);
      res.status(200).send('OTP sent successfully');
    }
  });
};

const verifyOtp = (req, res) => {
  const { email, userOTP } = req.body;

  const storedData = otpStorage.get(email);

  if (!storedData) {
    console.log('No stored data for email:', email);
    res.status(401).send('Invalid email or OTP');
    return;
  }

  console.log('Stored Data:', storedData);

  const isValidOTP = speakeasy.totp.verify({
    secret: storedData.secret,
    encoding: 'base32',
    token: userOTP,
  });

  console.log('Is Valid OTP:', isValidOTP);

  if (isValidOTP) {
    otpStorage.delete(email);
    res.status(200).send('OTP Verified');
  } else {
    res.status(401).send('Invalid OTP');
  }
};


const resetPassword = (req, res) => {
  const { email, newPassword } = req.body;

  const storedData = otpStorage.get(email);

  if (!storedData) {
    return res.status(401).send('Email not verified or invalid');
  }

  const salt = bcrypt.genSaltSync(10);
  const hash = bcrypt.hashSync(newPassword, salt);

  const updateQuery = "UPDATE users SET password = ? WHERE email = ?";
  db.query(updateQuery, [hash, email], (updateErr, updateData) => {
    if (updateErr) {
      return res.status(500).json(updateErr);
    }

    otpStorage.delete(email);

    return res.status(200).json('Password reset successfully');
  });
};

const getUsers = (req, res) =>{
    const query = "SELECT * FROM users";
    db.query(query, (err,data)=>{
        if(err) return res.json(err)
        return res.json(data)
    })
}

const logout = (req, res)=>{
    res.clearCookie("access_token", {
        sameSite: "none",
        secure:true
    }).status(200).json("User has been logged out")
}

module.exports={login,register,logout,sendOtp,verifyOtp,getUsers,resetPassword}