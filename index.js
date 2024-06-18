import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import mysql from "mysql";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import nodemailer from "nodemailer";
import otpGenerator from "otp-generator";

const app = express();
app.use(express.json());
app.use(cors());
dotenv.config();

var con = mysql.createConnection({
  host: process.env.host,
  user: process.env.user,
  password: process.env.password,
  database: process.env.database,
});
con.connect(function (err) {
  if (err) throw err;
  console.log("Connected! on port " + process.env.port);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

// Setup nodemailer transporter
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL,
    pass: process.env.EMAIL_PASSWORD,
  },
});

app.get("/getall", async (req, res) => {
  con.query("select * from Users", function (err, result) {
    if (err) throw err;
    console.log(result);
    res.send(result);
  });
});

// Sign-in route
app.post("/signin", async (req, res) => {
  const { userID, emailid, mobileNo, password, SchoolName, FavHobby } =
    req.body;

  // Validate request data
  if (
    !userID ||
    !emailid ||
    !mobileNo ||
    !password ||
    !SchoolName ||
    !FavHobby
  ) {
    return res.status(400).send("All fields are required");
  }

  try {
    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert the new user into the database
    const sql = `INSERT INTO Users (userID, emailid, mobileNo, password, SchoolName, FavHobby) VALUES (?, ?, ?, ?, ?, ?)`;
    const values = [
      userID,
      emailid,
      mobileNo,
      hashedPassword,
      SchoolName,
      FavHobby,
    ];

    con.query(sql, values, function (err, result) {
      if (err) {
        console.error("Error executing query:", err);
        return res.status(500).send("Error executing query");
      }
      res.send("User signed in successfully");
    });
  } catch (err) {
    console.error("Error hashing password:", err);
    res.status(500).send("Error hashing password");
  }
});

// Login route
app.post("/login", async (req, res) => {
  const { userID, password } = req.body;

  // Validate request data
  if (!userID || !password) {
    return res.status(400).send("UserID and password are required");
  }

  // Retrieve the user from the database
  const sql = "SELECT * FROM Users WHERE userID = ?";
  con.query(sql, [userID], async (err, result) => {
    if (err) {
      console.error("Error executing query:", err);
      return res.status(500).send("Error executing query");
    }

    if (result.length === 0) {
      return res.status(400).send("Invalid userID or password");
    }

    const user = result[0];

    // Compare the password with the hashed password stored in the database
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).send("Invalid userID or password");
    }

    // Generate JWT token
    const token = jwt.sign(
      { userID: user.userID, emailid: user.emailid },
      process.env.JWT_SECRET,
      { expiresIn: "1h" } // Token expires in 1 hour
    );
    // console.log(`logged in user ${user.userID}`);
    // console.log(token);

    res.json({ message: "Login successful", token });
  });
});

// Route to generate OTP
app.post("/generate-otp", async (req, res) => {
  const { userInput } = req.body;

  if (!userInput) {
    return res.status(400).send("User ID, Email or Mobile Number is required");
  }

  // Query to find user
  const findUserQuery =
    "SELECT userID, emailid FROM Users WHERE userID = ? OR emailid = ? OR mobileNo = ?";

  con.query(findUserQuery, [userInput, userInput, userInput], (err, result) => {
    if (err) {
      console.error("Error executing query:", err);
      return res.status(500).send("Error executing query");
    }

    if (result.length === 0) {
      return res.status(400).send("User not found");
    }

    const userID = result[0].userID;
    const email = result[0].emailid;

    // Generate OTP
    const otp = otpGenerator.generate(6, {
      upperCase: false,
      specialChars: false,
    });

    // Update the database with the generated OTP
    const updateOtpQuery = "UPDATE Users SET otp = ? WHERE userID = ?";
    con.query(updateOtpQuery, [otp, userID], (updateErr, updateResult) => {
      if (updateErr) {
        console.error("Error updating OTP:", updateErr);
        return res.status(500).send("Error updating OTP");
      }

      // Send OTP to the user's email
      const mailOptions = {
        from: process.env.EMAIL,
        to: email,
        subject: "Your OTP for Password Reset",
        text: `Your OTP is ${otp}`,
      };

      transporter.sendMail(mailOptions, (mailError, info) => {
        if (mailError) {
          console.error("Error sending email:", mailError);
          return res.status(500).send("Error sending OTP");
        }
        res.send(userID);
        //at the client save this userID in state and pass it to the server again with otp to verify the otp
        console.log("Email sent: ", info.response);
      });
    });
  });
});

// Route to verify OTP
app.post("/verify-otp", (req, res) => {
  const { userID, otp } = req.body;

  // Validate request data
  if (!userID || !otp) {
    return res.status(400).send("UserID and OTP are required");
  }

  // Query to retrieve user and OTP from database
  const findUserQuery = "SELECT otp FROM Users WHERE userID = ?";

  con.query(findUserQuery, [userID], (err, result) => {
    if (err) {
      console.error("Error executing query:", err);
      return res.status(500).send("Error executing query");
    }

    if (result.length === 0) {
      return res.status(400).send("User not found");
    }

    const storedOTP = result[0].otp;

    // Compare OTPs
    if (otp !== storedOTP) {
      return res.status(400).send("Invalid OTP");
    }

    // Clear OTP from database (optional step after successful verification)
    const clearOtpQuery = "UPDATE Users SET otp = NULL WHERE userID = ?";
    con.query(clearOtpQuery, [userID], (updateErr, updateResult) => {
      if (updateErr) {
        console.error("Error clearing OTP:", updateErr);
      }

      // Respond with success message
      const token = jwt.sign({ userID }, process.env.JWT_SECRET, {
        expiresIn: "1h",
      });
      res.send('otp verified successfully \n'+token);
      // res.redirect(`/update-password?token=${token}`);
    });
  });
});

// Route to update password
app.get("/update-password", async (req, res) => {
  // const token = req.params;
  const { password , token } = req.body;
  console.log(token, password);

  // Validate token presence
  if (!token) {
    return res.status(400).json({ error: "Token is required" });
  }

  try {
    // Verify JWT token and extract userID
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const userID = decoded.userID;

    // Hash the new password
    const hashedPassword = await bcrypt.hash(password, 10);


    // Update the password in the database
    const updatePasswordQuery =
      "UPDATE Users SET password = ? WHERE userID = ?";
    con.query(
      updatePasswordQuery,
      [hashedPassword, userID],
      (updateErr, updateResult) => {
        if (updateErr) {
          console.error("Error updating password:", updateErr);
          return res.status(500).send("Error updating password");
        }

        // Password updated successfully
        res.send("Password updated successfully");
      }
    );
  } catch (err) {
    console.error("Error updating password:", err);
    return res.status(500).send("Error updating password");
  }
});


app.post('/update-password-with-question', async (req, res) => {
  const { userID, schoolName, favHobby, password } = req.body;

  // Validate inputs
  if (!userID || !schoolName || !favHobby || !password) {
    return res.status(400).json({ error: 'All fields are required' });
  }

  try {
    // Query to verify schoolName and favHobby for the given userID
    const verifyQuery = "SELECT schoolName, favHobby FROM Users WHERE userID = ?";
    con.query(verifyQuery, [userID], async (verifyErr, verifyResult) => {
      if (verifyErr) {
        console.error("Error verifying security questions:", verifyErr);
        return res.status(500).send("Error verifying security questions");
      }

      if (verifyResult.length === 0) {
        return res.status(404).send("User not found");
      }

      const user = verifyResult[0];

      // Check if schoolName and favHobby match
      if (user.schoolName !== schoolName || user.favHobby !== favHobby) {
        return res.status(400).send("School name or favorite hobby do not match");
      }

      // Hash the new password
      const hashedPassword = await bcrypt.hash(password, 10);

      // Update the password in the database
      const updatePasswordQuery = "UPDATE Users SET password = ? WHERE userID = ?";
      con.query(updatePasswordQuery, [hashedPassword, userID], (updateErr, updateResult) => {
        if (updateErr) {
          console.error("Error updating password:", updateErr);
          return res.status(500).send("Error updating password");
        }

        // Password updated successfully
        res.send("Password updated successfully");
      });
    });
  } catch (err) {
    console.error("Error updating password:", err);
    return res.status(500).send("Error updating password");
  }
});