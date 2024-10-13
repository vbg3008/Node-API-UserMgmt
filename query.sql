create database UserDetails;
use UserDetails;
show tables;



CREATE TABLE Users (
    ID INT AUTO_INCREMENT PRIMARY KEY,
    userID VARCHAR(50) UNIQUE NOT NULL,
    emailId VARCHAR(100) UNIQUE NOT NULL,
    mobileNo VARCHAR(15) NOT NULL,
    password VARCHAR(255) NOT NULL,
    schoolName VARCHAR(100),
    favHobby VARCHAR(100)
); 

INSERT INTO Users (userID, emailid, mobileNo, password, SchoolName, FavHobby) VALUES
('user001', 'user001@example.com', '1234567890', 'password1', 'Greenwood High', 'Reading'),
('user002', 'user002@example.com', '0987654321', 'password2', 'Springfield High', 'Cycling'),
('user003', 'user003@example.com', '5551234567', 'password3', 'Riverdale High', 'Swimming'),
('user004', 'user004@example.com', '4447654321', 'password4', 'Sunnydale High', 'Painting'),
('user005', 'user005@example.com', '6669876543', 'password5', 'Hill Valley High', 'Gaming');

select * from Users;

INSERT INTO Users (userID, emailid, mobileNo, password, SchoolName, FavHobby) VALUES
('user7', 'vbg3008@example.com', '12345670', 'password1', 'Greenwood High', 'Reading');

ALTER TABLE Users ADD COLUMN otp VARCHAR(6) DEFAULT NULL;

CREATE TABLE UserUploadFiles (
  id INT AUTO_INCREMENT PRIMARY KEY,
  userID VARCHAR(255) NOT NULL,
  fileName VARCHAR(255) NOT NULL,
  uploadTimeStamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  year INT NOT NULL,
  month INT NOT NULL,
  type VARCHAR(50) NOT NULL,
  FOREIGN KEY (userID) REFERENCES Users(userID)
);

select * from UserUploadFiles;


