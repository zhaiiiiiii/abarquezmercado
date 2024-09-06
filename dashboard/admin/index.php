<?php
    require_once 'authentication/admin-class.php';

    $admin = new ADMIN();
    if(!$admin->userLoggedIn())
    {
        $admin->redirect('../../');
    }

    $statement = $admin->runQuery("SELECT * FROM user WHERE id = :id");
    $statement->execute(array(":id" => $_SESSION['adminSession']));
    $user_data = $statement->fetch(PDO::FETCH_ASSOC);
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ADMIN DASHBOARD</title>
</head>
<body>
    <h1> WELCOME! <?php echo $user_data ['email']?> </h1>
    <button><a href = "authentication/admin-class.php?admin_signout"> SIGN OUT </a></button>
</body>
</html>
