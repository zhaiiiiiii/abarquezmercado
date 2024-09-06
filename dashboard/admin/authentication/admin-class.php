<?php
    require_once __DIR__.'/../../../database/dbconnection.php';
    include_once __DIR__.'/../../../config/settings-configuration.php';

    class ADMIN
    {
        private $connection;
    

        public function __construct()
       
        
        {
            $database = new Database();
            $this->connection = $database->dbConnection();
        
        }
        public function addAdmin($csrf_token, $username, $email, $password)
        {
            $statement = $this->connection->prepare("SELECT * FROM user WHERE email = :email");
            $statement->execute(array(":email" => $email));

            if($statement->rowCount() > 0){
                echo "<script>alert('EMAIL ALREADY EXISTS!'); window.location.href = '../../../';</script>";
                exit;
            }

            if (!isset($csrf_token) || !hash_equals($_SESSION['csrf_token'], $csrf_token)){
                echo "<script>alert('INVALID CSRF TOKEN!'); window.location.href = '../../../';</script>";
                exit;
            }

            unset($_SESSION['csrf_token']);

            $hash_password = md5($password);

            $statement = $this->runQuery('INSERT INTO user (username, email, password) VALUES (:username, :email, :password)');
            $execute = $statement->execute(array(
                ":username" => $username,
                ":email" => $email,
                ":password" => $hash_password
            ));

                if($execute){
                    echo "<script>alert('ADMIN ADDED SUCCESSFULLY!'); window.location.href = '../../../';</script>";
                    exit;
                }else {
                    echo "<script>alert('ERROR ADDING ADMIN!'); window.location.href = '../../../';</script>";
                }

        }

        public function adminSignin($email, $password, $csrf_token)
        {
            try {
                if (!isset($csrf_token) || !hash_equals($_SESSION['csrf_token'], $csrf_token)){
                    echo "<script>alert('INVALID CSRF TOKEN!'); window.location.href = '../../../';</script>";
                    exit;
                }

                unset($_SESSION['csrf_token']);

                $statement = $this->connection->prepare("SELECT * FROM user WHERE email = :email");
                $statement->execute(array(":email" => $email));
                $userRow = $statement->fetch(PDO::FETCH_ASSOC);

                if($statement->rowCount() == 1 && $userRow['password'] == md5($password)){
                    $activity = "HAS SUCCESSFULLY SIGNED IN";
                    $user_id = $userRow['id'];
                    $this->logs($activity, $user_id);

                    $_SESSION['adminSession'] = $user_id;

                    echo "<script>alert('WELCOME!'); window.location.href = '../';</script>";
                    exit;
                }else {
                    echo "<script>alert('INVALID CREDENTIALS!'); window.location.href = '../../../';</script>";
                    exit;                    
                }

            }catch(PDOExeception $exception){
                echo $exception->getMessage();
            }
        }

        public function adminSignout()
        {
            unset($_SESSION['adminSession']);
            echo "<script>alert('SIGNED OUT SUCCESSFULLY!'); window.location.href = '../../../';</script>";
            exit;  
        }

        public function logs($activity, $user_id)
        {
            $statement = $this->connection->prepare("INSERT INTO logs (user_id, activity) VALUES (:user_id, :activity)");
            $statement->execute(array(":user_id" => $user_id, ":activity" => $activity));
        }

        public function  userLoggedIn()
        {
            if(isset($_SESSION['adminSession'])){
                return true;
            }
        }

        public function redirect()
        {
            echo "<script>alert('ADMIN MUST LOG IN FIRST!'); window.location.href = '../../../';</script>";
            exit;
        }

        public function runQuery($sql)
        {
            $statement = $this->connection->prepare($sql);
            return $statement;
        }

    }


    if(isset($_POST['btn-signup'])){
        $csrf_token = trim($_POST['csrf_token']);
        $username = trim($_POST['username']);
        $email = trim($_POST['email']);
        $password = trim($_POST['password']);

        $addAdmin = new ADMIN();
        $addAdmin->addAdmin($csrf_token, $username, $email, $password);
    }

    if(isset($_POST['btn-signin'])){
        $csrf_token = trim($_POST['csrf_token']);
        $email = trim($_POST['email']);
        $password = trim($_POST['password']);

        $adminSignin = new ADMIN();
        $adminSignin->adminSignin($email, $password, $csrf_token);
    }

    if(isset($_GET['admin_signout'])){
        $adminSignout = new ADMIN();
        $adminSignout->adminSignout();
    }

?>
