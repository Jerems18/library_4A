# Library Management API

This project is a simple Library Management API built using PHP and the Slim framework. It provides endpoints for user registration, authentication, and managing authors and books. The API uses JWT (JSON Web Tokens) for authentication and token management.

## Features

- User Management (Register, Authenticate, Show, Update, Delete)
- Author Management (Register, Show, Update, Delete)
- Book Management (Register, Show, Update, Delete)
- Books Authors Management (Register, Show, Update, Delete)
- Token Management (Generate, Validate, Mark as Used)

## Prerequisites

- PHP 7.4 or higher
- Composer
- MySQL
- Slim
- Firebase
- Git
- Node.js
- XAMPP

## Installation

1. Clone the repository:

  ```bash
  git clone https://github.com/ELDRagados/Library.git
  cd library-management-api
  ```

2. Install dependencies:

  ```bash
  composer require slim/slim:3.*
  composer require firebase/php-jwt
  ```

3. Set up the database:

  - Create a MySQL database named `library`.

  - Run the following SQL scripts to create the necessary tables:

  ```sql
  CREATE TABLE users (
    userid INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL
  );

  CREATE TABLE authors (
    authorid INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL
  );

  CREATE TABLE books (
    bookid INT AUTO_INCREMENT PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    authorid INT NOT NULL,
    FOREIGN KEY (authorid) REFERENCES authors(authorid)
  );

  CREATE TABLE book_authors (
    collectionid INT AUTO_INCREMENT PRIMARY KEY,
    bookid INT NOT NULL,
    authorid INT NOT NULL,
    FOREIGN KEY (bookid) REFERENCES books(bookid),
    FOREIGN KEY (authorid) REFERENCES authors(authorid)
  );

  CREATE TABLE tokens (
    id INT AUTO_INCREMENT PRIMARY KEY,
    token VARCHAR(255) NOT NULL,
    userid INT NOT NULL,
    status ENUM('active', 'revoked', 'expired') DEFAULT 'active',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    used_at TIMESTAMP NULL,
    FOREIGN KEY (userid) REFERENCES users(userid)
  );
  ```

4. Configure the database connection:

  Update the database connection details in `index.php`:

  ```php
  <?php
  $servername = "localhost";
  $username = "root";
  $password = "";
  $dbname = "library";
  ?>
  ```

## Usage

### User Management

#### Create Users

- **Endpoint:** `/user/register`
- **Method:** `POST`
- **Payload:**

  ```json
  {
    "username": "your_username",
    "password": "your_password"
  }
  ```

#### Authenticate Users

- **Endpoint:** `/user/auth`
- **Method:** `POST`
- **Payload:**

  ```json
  {
    "username": "your_username",
    "password": "your_password"
  }
  ```

#### Show Users

- **Endpoint:** `/user/show`
- **Method:** `GET`
- **Header:**

  ```json
  {
    "Authorization": "Bearer your_token"
  }
  ```

#### Update Users

- **Endpoint:** `/user/update`
- **Method:** `PUT`
- **Header:**

  ```json
  {
    "token": "your_token",
    "userid": "your_userid",
    "username": "your_new_username",
    "password": "your_new_password"
  }
  ```

#### Delete Users

- **Endpoint:** `/user/delete`
- **Method:** `DELETE`
- **Header:**

  ```json
  {
    "token": "your_token",
    "userid": "your_userid"
  }
  ```

### Author Management

#### Author Registration

- **Endpoint:** `/author/register`
- **Method:** `POST`
- **Payload:**

  ```json
  {
    "token": "your_token",
    "name": "author_name"
  }
  ```

#### Show Authors

- **Endpoint:** `/author/show`
- **Method:** `GET`
- **Header:**

  ```json
  {
    "Authorization": "Bearer your_token"
  }
  ```

#### Update Authors

- **Endpoint:** `/author/update`
- **Method:** `PUT`
- **Header:**

  ```json
  {
    "token": "your_token",
    "authorid": "author_id",
    "name": "author_name"
  }
  ```

#### Delete Authors

- **Endpoint:** `/author/delete`
- **Method:** `DELETE`
- **Header:**

  ```json
  {
    "token": "your_token",
    "authorid": "author_id"
  }
  ```

### Book Management

#### Register Book

- **Endpoint:** `/book/register`
- **Method:** `POST`
- **Payload:**

  ```json
  {
    "token": "your_jwt_token",
    "title": "book_title",
    "authorid": 1
  }
  ```

#### Show Books

- **Endpoint:** `/book/show`
- **Method:** `GET`
- **Header:**

  ```json
  {
    "Authorization": "Bearer your_token"
  }
  ```

#### Update Book

- **Endpoint:** `/book/update`
- **Method:** `PUT`
- **Payload:**

  ```json
  {
    "token": "your_jwt_token",
    "bookid": 1,
    "title": "new_book_title",
    "authorid": 1
  }
  ```

#### Delete Book

- **Endpoint:** `/book/delete`
- **Method:** `DELETE`
- **Payload:**

  ```json
  {
    "token": "your_jwt_token",
    "bookid": 1
  }
  ```

### Book Authors Management

#### Register Book Authors

- **Endpoint:** `/book_author/register`
- **Method:** `POST`
- **Payload:**

  ```json
  {
    "token": "your_jwt_token",
    "bookid": 1,
    "authorid": 1
  }
  ```

#### Show Books Authors

- **Endpoint:** `/book_author/show`
- **Method:** `GET`
- **Header:**

  ```json
  {
    "Authorization": "Bearer your_token"
  }
  ```

#### Update Book Authors

- **Endpoint:** `/book_author/update`
- **Method:** `PUT`
- **Payload:**

  ```json
  {
    "token": "your_jwt_token",
    "collectionid": 1,
    "bookid": 1,
    "authorid": 1
  }
  ```

#### Delete Book Authors

- **Endpoint:** `/book_author/delete`
- **Method:** `DELETE`
- **Payload:**

  ```json
  {
    "token": "your_jwt_token",
    "collectionid": 1
  }
  ```

### Token Management

- **Generate Token:** Tokens are generated during user authentication and stored in the `tokens` table with a status of 'active'.

- **Validate Token:** Tokens are validated using the `validateToken` function, which checks the token's status and decodes it to retrieve the user ID.

- **Mark Token as Used:** Tokens are marked as used by updating their status to 'revoked' and setting the `used_at` timestamp.

## Error Responses

### Access Denied

- **Status Code:** 403
- **Error Message:**

  ```json
  {
    "status": "fail",
    "data": {
    "Message": "Access denied, only admins can add authors."
    }
  }
  ```

### Invalid or Expired Token

- **Status Code:** 401
- **Error Message:**

  ```json
  {
    "status": "fail",
    "data": {
    "Message": "Invalid or Outdated Token."
    }
  }
  ```

### Database Error

- **Status Code:** 500
- **Error Message:**

  ```json
  {
    "status": "fail",
    "data": {
    "Message": "Database error message here."
    }
  }
  ```

## Code Excerpt

Here is an excerpt from `index.php` that shows how tokens are managed:

```php
<?php
$password = "";
try {
  $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
  $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

  $sql = "INSERT INTO tokens (token, userid, status) VALUES (:token, :userid, 'active')";
  $stmt = $conn->prepare($sql);
  $stmt->bindParam(':token', $token);
  $stmt->bindParam(':userid', $userid);
  $stmt->execute();
} catch (PDOException $e) {
  // Handle exception
}

return $token;
}

function validateToken($token) {
  global $key;
  $servername = "localhost";
  $username = "root";
  $password = "";
  $dbname = "library";

  try {
  $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
  $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

  $sql = "SELECT * FROM tokens WHERE token = :token AND status = 'active'";
  $stmt = $conn->prepare($sql);
  $stmt->bindParam(':token', $token);
  $stmt->execute();
  $data = $stmt->fetch(PDO::FETCH_ASSOC);

  if ($data) {
    // Decode the token to get the payload
    $decoded = JWT::decode($token, new Key($key, 'HS256'));
    return $decoded->data->userid;
  } else {
    return false;
  }
  } catch (PDOException $e) {
  // Handle exception
  return false;
  }
}
```
## Author

This project was created and maintained by [ELDRagados](https://github.com/ELDRagados).

If you have any questions, suggestions, or feedback, feel free to reach out:

- GitHub: [ELDRagados](https://github.com/ELDRagados)
- Email: [Edward Lee Ragados](eragados09122@student.dmmmsu.edu.ph)

Contributions, issues, and feature requests are welcome! Feel free to check the [issues page](https://github.com/ELDRagados/Library/issues) if you want to contribute.

Thank you for using the Library Management API!
