CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL
);

CREATE TABLE grades (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    subject VARCHAR(50),
    grade CHAR(1),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

INSERT INTO grades (user_id, subject, grade) VALUES 
(1, 'Mathematics', 'A'), 
(1, 'Physics', 'A'), 
(1, 'Chemistry', 'A'), 
(1, 'Biology', 'A');

select* from users;
select* from grades;
