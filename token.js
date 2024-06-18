import jwt from "jsonwebtoken";
import dotenv from "dotenv";
dotenv.config();

const data = {
    userID: 'user123',
    email: 'user@example.com',
    mobileNo: '1234567890',
    role: 'admin'
  };

  const token = jwt.sign(data, process.env.JWT_SECRET, { expiresIn: '1h' });
  console.log(token);

  const decrypt = jwt.verify(token, process.env.JWT_SECRET);
  console.log(decrypt);

