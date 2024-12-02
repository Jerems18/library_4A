<?php

use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Slim\Factory\AppFactory;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

require '../src/vendor/autoload.php';
$app = new \Slim\App;


    $app->post('/register', function (Request $request, Response $response, array $args){

        $data = json_decode($request->getBody());
        $usr = $data->username;
        $pass = $data->password;
    
        $servername = "localhost";
        $username = "root";
        $password = "";
        $dbname = "library";

        try {
            $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
            // set the PDO error mode to exception
            $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            $sql = "INSERT INTO users(username,password)
            VALUES ('".$usr."','".hash('SHA256',$pass)."')";
            // use exec() because no results are returned
            $conn->exec($sql);
            $response->getBody()->write(json_encode(array("status"=>"success","data"=>null)));
        } catch(PDOException $e) {
            $response->getBody()->write(json_encode(array("status"=>"fail","data"=>array("title"=>$e->getMessage()))));
        }
          
          $conn = null;

        return $response;
    });

// User authentication and token generation
$app->post('/authenticate', function (Request $request, Response $response, array $args) {
    $data = json_decode($request->getBody());
    $usr = $data->username;
    $pass = $data->password;

    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Use a parameterized query to prevent SQL injection
        $sql = "SELECT * FROM users WHERE username = :username AND password = :password";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':username', $usr);
        $hashedPassword = hash('SHA256', $pass);
        $stmt->bindParam(':password', $hashedPassword);
        $stmt->execute();

        $data = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($data) {
            // Generate a simple token (this could be a random string, for example)
            $token = bin2hex(random_bytes(16));
            // Save the token to the database or memory associated with the user
            // Here, I assume you have a `tokens` table to store tokens for users
            $sql = "INSERT INTO tokens (username, token) VALUES (:username, :token)";
            $stmt = $conn->prepare($sql);
            $stmt->bindParam(':username', $usr);
            $stmt->bindParam(':token', $token);
            $stmt->execute();

            $response->getBody()->write(json_encode(array("status" => "success", "token" => $token)));
        } else {
            $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => "Authentication Failed"))));
        }
    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
    }

    return $response;
});

// Middleware to validate the token
function validateToken(Request $request, Response $response, $next) {
    // First, check for the token in the Authorization header
    $authHeader = $request->getHeader('Authorization');
    
    // Check if the token is present in the header
    if (!empty($authHeader)) {
        $token = str_replace('Bearer ', '', $authHeader[0]);
    } else {
        // Check if the token is present in the query parameters
        $queryParams = $request->getQueryParams();
        if (isset($queryParams['token'])) {
            $token = $queryParams['token'];
        } else {
            return $response->withStatus(401)->write(json_encode(array("status" => "fail", "message" => "No token provided")));
        }
    }

    // Check if the token is valid in your tokens table
    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $sql = "SELECT * FROM tokens WHERE token = :token";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':token', $token);
        $stmt->execute();
        
        if ($stmt->rowCount() > 0) {
            // Token is valid, proceed to the next middleware/route
            return $next($request, $response);
        } else {
            return $response->withStatus(401)->write(json_encode(array("status" => "fail", "message" => "Unauthorized")));
        }
    } catch (PDOException $e) {
        return $response->withStatus(500)->write(json_encode(array("status" => "fail", "message" => $e->getMessage())));
    }
}


// Adding a new book with token validation
$app->post('/books/add', function (Request $request, Response $response, array $args) {
    $data = json_decode($request->getBody());
    $title = $data->title;

    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $sql = "INSERT INTO books (title) VALUES (:title)";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':title', $title);
        $stmt->execute();

        $response->getBody()->write(json_encode(array("status" => "success", "message" => "Book added successfully")));
    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(array("status" => "fail", "message" => $e->getMessage())));
    }

    return $response;
})->add('validateToken'); // Add the token validation middleware



// Updating a book
$app->put('/books/update/{id}', function (Request $request, Response $response, array $args) {
    $bookId = $args['id'];
    $data = json_decode($request->getBody());
    $title = $data->title;

    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $sql = "UPDATE books SET title = :title WHERE bookid = :id";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':title', $title);
        $stmt->bindParam(':id', $bookId);
        $stmt->execute();

        $response->getBody()->write(json_encode(array("status" => "success", "message" => "Book updated successfully")));
    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(array("status" => "fail", "message" => $e->getMessage())));
    }

    return $response;
})->add('validateToken'); // Add the token validation middleware

// Adding a new author
$app->post('/authors/add', function (Request $request, Response $response, array $args) {
    $data = json_decode($request->getBody());
    $name = $data->name;

    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $sql = "INSERT INTO authors (name) VALUES (:name)";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':name', $name);
        $stmt->execute();

        $response->getBody()->write(json_encode(array("status" => "success", "message" => "Author added successfully")));
    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(array("status" => "fail", "message" => $e->getMessage())));
    }

    return $response;
})->add('validateToken'); // Ensure token is valid

// Updating an author
$app->put('/authors/update/{id}', function (Request $request, Response $response, array $args) {
    $authorId = $args['id'];
    $data = json_decode($request->getBody());
    $name = $data->name;

    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $sql = "UPDATE authors SET name = :name WHERE authorid = :authorid";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':name', $name);
        $stmt->bindParam(':authorid', $authorId);
        $stmt->execute();

        $response->getBody()->write(json_encode(array("status" => "success", "message" => "Author updated successfully")));
    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(array("status" => "fail", "message" => $e->getMessage())));
    }

    return $response;
})->add('validateToken'); // Ensure token is valid
 
$app->post('/books_authors/add', function (Request $request, Response $response, array $args) { 
    $data = json_decode($request->getBody()); 
    $bookid = $data->bookid;
    $authorid = $data->authorid;

    $servername = "localhost";
    $username = "root"; 
    $password = ""; 
    $dbname = "library"; 

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // 1. Check if bookid exists
        $checkBookSql = "SELECT bookid FROM books WHERE bookid = :bookid";
        $checkBookStmt = $conn->prepare($checkBookSql);
        $checkBookStmt->bindParam(':bookid', $bookid);
        $checkBookStmt->execute();

        if ($checkBookStmt->rowCount() === 0) {
            return $response->withStatus(404)
                            ->getBody()
                            ->write(json_encode(array("status" => "fail", "message" => "Book ID not found")));
        }

        // 2. Check if authorid exists
        $checkAuthorSql = "SELECT authorid FROM authors WHERE authorid = :authorid";
        $checkAuthorStmt = $conn->prepare($checkAuthorSql);
        $checkAuthorStmt->bindParam(':authorid', $authorid);
        $checkAuthorStmt->execute();

        if ($checkAuthorStmt->rowCount() === 0) {
            return $response->withStatus(404)
                            ->getBody()
                            ->write(json_encode(array("status" => "fail", "message" => "Author ID not found")));
        }

        // 3. Insert into books_authors table if both bookid and authorid exist
        $sql = "INSERT INTO books_authors (bookid, authorid) VALUES (:bookid, :authorid)";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':bookid', $bookid); 
        $stmt->bindParam(':authorid', $authorid); 
        $stmt->execute(); 

        // 4. Get the last inserted collectionid
        $collectionid = $conn->lastInsertId();

        // 5. Display the collectionid in the response
        $response->getBody()->write(json_encode(array("status" => "success", "message" => "Book-Author entry added successfully", "collectionid" => $collectionid))); 
    } catch (PDOException $e) { 
        $response->getBody()->write(json_encode(array("status" => "fail", "message" => $e->getMessage())));  
    } 

    return $response;  
})->add('validateToken');

$app->delete('/books_authors/delete/{collectionid}', function (Request $request, Response $response, array $args) {
    $collectionid = $args['collectionid']; // Get the collectionid from the URL

    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        // Create a new PDO connection
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Check if the collectionid exists
        $checkSql = "SELECT collectionid FROM books_authors WHERE collectionid = :collectionid";
        $checkStmt = $conn->prepare($checkSql);
        $checkStmt->bindParam(':collectionid', $collectionid);
        $checkStmt->execute();

        if ($checkStmt->rowCount() === 0) {
            return $response->withStatus(404)
                            ->getBody()
                            ->write(json_encode(array("status" => "fail", "message" => "Collection ID not found")));
        }

        // Delete the entry from the books_authors table
        $sql = "DELETE FROM books_authors WHERE collectionid = :collectionid";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':collectionid', $collectionid);
        $stmt->execute();

        // Return a success message
        $response->getBody()->write(json_encode(array("status" => "success", "message" => "Book-Author entry deleted successfully")));
    } catch (PDOException $e) {
        // Return a failure message if something goes wrong
        $response->getBody()->write(json_encode(array("status" => "fail", "message" => $e->getMessage())));
    }

    return $response;
})->add('validateToken'); // Add token validation middleware



$app->run();
?>
