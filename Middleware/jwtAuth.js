import jwt from "jsonwebtoken";

export const authenticateJWT = (req, res, next) => {
    const token = req.header('Authorization')?.split(' ')[1]; // Bearer <token>
    console.log(token);
    
    if (!token) {
      return res.status(401).send('Access Denied');
    }

  
    try {
      const verified = jwt.verify(token, process.env.JWT_SECRET);
      req.user = verified; // Add the verified user to the request object
      next();
    } catch (err) {
      res.status(400).send('Invalid Token');
    }
  };

  