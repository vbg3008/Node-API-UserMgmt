import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import mysql from "mysql";
import bcrypt from "bcrypt";
import csvParser from 'csv-parser';
import xlsx from 'xlsx';
import fs from 'fs';
import jwt from "jsonwebtoken";
import nodemailer from "nodemailer";
import otpGenerator from "otp-generator";
import multer from "multer";
import path from "path";
import {authenticateJWT} from "./Middleware/jwtAuth.js"

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
    return res.status(400).send("userID and password are required");
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
      { expiresIn: "1h" ,  } // Token expires in 1 hour
    );
    // console.log(`logged in user ${user.userID}`);
    console.log(token);

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
app.post("/update-password", async (req, res) => {
  // const token = req.params;
  const { password , token } = req.body;

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


// Restrict file type
const fileFilter = (req, file, cb) => {
  const fileTypes = /csv|xlsx/;
  const extname = fileTypes.test(path.extname(file.originalname).toLowerCase());
  if (extname) {
    cb(null, true);
  } else {
    cb('Error: Only CSV or Excel files are allowed');
  }
};

// Update multer storage configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname)); // Save with timestamp
  },
});

const upload = multer({ storage, fileFilter });



// File upload route (with table creation)
app.post('/upload', authenticateJWT, upload.single('file'), async (req, res) => {
  const { year, month, type } = req.body;
  const file = req.file;

  if (!file) {
    return res.status(400).send('No file uploaded');
  }

  const fileName = file.filename;  // Unique file name
  const filePath = file.path;      // Full path
  const userID = req.user.userID;  // Get userID from the authenticated user
  const uploadTimeStamp = new Date();

  // Determine file extension
  const ext = path.extname(file.originalname).toLowerCase();

  let columns = [];
  let dataRows = [];

  try {
    // Process CSV file
    if (ext === '.csv') {
      const csvData = [];
      fs.createReadStream(filePath)
        .pipe(csvParser())
        .on('headers', (headers) => {
          columns = headers;
        })
        .on('data', (row) => {
          csvData.push(row);
        })
        .on('end', () => {
          dataRows = csvData;
          createTableFromUpload(fileName, columns, dataRows, userID);
        });
    }

    // Process Excel file
    if (ext === '.xlsx') {
      const workbook = xlsx.readFile(filePath);
      const sheetName = workbook.SheetNames[0]; // Process first sheet
      const sheetData = xlsx.utils.sheet_to_json(workbook.Sheets[sheetName], {
        header: 1, // Use the first row for column headers
      });

      columns = sheetData[0];
      dataRows = sheetData.slice(1); // All rows after the headers
      createTableFromUpload(fileName, columns, dataRows, userID);
    }

    // Insert file details into `UserUploadFiles`
    const sql = `INSERT INTO UserUploadFiles (userID, fileName, uploadTimeStamp, year, month, type) VALUES (?, ?, ?, ?, ?, ?)`;
    const values = [userID, fileName, uploadTimeStamp, year, month, type];

    con.query(sql, values, function (err, result) {
      if (err) {
        console.error('Error executing query:', err);
        return res.status(500).send('Error saving file details');
      }
      res.send('File uploaded and table created successfully');
    });

  } catch (err) {
    console.error('Error processing file:', err);
    return res.status(500).send('Error processing file');
  }
});

// Helper function to create a new table from the uploaded file
function createTableFromUpload(fileName, columns, dataRows, userID) {
  // Sanitize file name and userID for table name
  const sanitizedFileName = fileName.replace(/\W+/g, '_'); // Replace non-word characters
  const sanitizedUserID = userID.replace(/\W+/g, '_');     // Sanitize userID

  // Use the format UserID-TableName
  const tableName = `${sanitizedUserID}_${sanitizedFileName}`; // e.g., user001_myfile.csv -> user001_myfile_csv

  // Sanitize columns: replace spaces or invalid characters and add backticks around each column name
  const sanitizedColumns = columns.map(col => `\`${col.replace(/\W+/g, '_')}\` TEXT`).join(', ');

  // SQL to create table
  const createTableSQL = `CREATE TABLE ${tableName} (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ${sanitizedColumns},
    userID VARCHAR(255) NOT NULL,
    FOREIGN KEY (userID) REFERENCES Users(userID)
  );`;

  // Create the table
  con.query(createTableSQL, (err, result) => {
    if (err) {
      console.error('Error creating table:', err);
      return;
    }

    // Insert rows into the table
    dataRows.forEach((row) => {
      const values = [...row, userID];
      const placeholders = values.map(() => '?').join(', ');
      const insertRowSQL = `INSERT INTO ${tableName} (${columns.map(col => `\`${col.replace(/\W+/g, '_')}\``).join(', ')}, userID) VALUES (${placeholders})`;
      con.query(insertRowSQL, values, (err) => {
        if (err) {
          console.error('Error inserting row:', err);
        }
      });
    });

    console.log(`Table ${tableName} created and data inserted.`);
  });
}
