<?php
session_start();
include "./config.php";
if($_GET['page'] == "login"){
    try{
        $input = json_decode(file_get_contents('php://input'), true);
    }
    catch(Exception $e){
        exit("<script>alert(`wrong input`);history.go(-1);</script>");
    }
    $db = dbconnect();
    $filtered = array(
        'id' => mysqli_real_escape_string($db,$input['id']),
        'pw' => mysqli_real_escape_string($db,$input['pw'])
        );
    $query = "select id,pw from member where id='{$filtered['id']}'";
    $result = mysqli_fetch_array(mysqli_query($db,$query));
    
    $hash_pw = hash("sha256", $filtered['pw']);
    if($result['id']==='admin')
        $result['pw'] = mysqli_real_escape_string($db,hash("sha256", $result['pw']));
        
    if($result['id'] && $result['pw'] === $hash_pw){
        $_SESSION['id'] = $result['id'];
        exit("<script>alert(`login ok`);location.href=`/`;</script>");
    }
    else{ exit("<script>alert(`login fail`);history.go(-1);</script>"); }
}
if($_GET['page'] == "join"){
    try{
        $input = json_decode(file_get_contents('php://input'), true);
    }
    catch(Exception $e){
        exit("<script>alert(`wrong input`);history.go(-1);</script>");
    }
    $db = dbconnect();
    if(strlen($input['id']) > 256) exit("<script>alert(`userid too long`);history.go(-1);</script>");
    if(strlen($input['email']) > 120) exit("<script>alert(`email too long`);history.go(-1);</script>");
    if(!filter_var($input['email'],FILTER_VALIDATE_EMAIL)) exit("<script>alert(`wrong email`);history.go(-1);</script>");
    $filtered = array(
        'id' => mysqli_real_escape_string($db,$input['id']),
        'email' => mysqli_real_escape_string($db,$input['email']),
        'pw' => mysqli_real_escape_string($db,$input['pw'])
        );
    $query = "select id from member where id='{$filtered['id']}'";
    $result = mysqli_fetch_array(mysqli_query($db,$query));
    if(!$result['id']){
        $hash_pw = hash("sha256", $filtered['pw']);
        $query = "insert into member values('{$filtered['id']}','{$filtered['email']}','{$hash_pw}','user')";
        mysqli_query($db,$query);
        exit("<script>alert(`join ok`);location.href=`/`;</script>");
    }
    else{
        exit("<script>alert(`Userid already existed`);history.go(-1);</script>");
    }
}
if($_GET['page'] == "upload"){
    if(!$_SESSION['id']){
        exit("<script>alert(`login plz`);history.go(-1);</script>");
    }
    if($_FILES['fileToUpload']['size'] >= 1024 * 1024 * 1){ exit("<script>alert(`file is too big`);history.go(-1);</script>"); } // file size limit(1MB). do not remove it.
    $ext = explode(".",strtolower($_GET['file']));
    $cnt = count($ext)-1;
    if($ext[$cnt]===""){
        if(preg_match("/abc|php|txt|tst/",$ext)){
            exit("");
        }
    }
    define($File_Path,$_FILES['fileToUpload']['tmp_name']);
    define($home_path,"./upload");
    $extension = explode(".",$_FILES['fileToUpload']['name'])[1];
    if($extension == "txt" || $extension == "png"){
        system("cp {$_FILES['fileToUpload']['tmp_name']} ./upload/{$_FILES['fileToUpload']['name']}");
        //system("cp {$File_Path} {$home_path + $File_Path}");
        exit("<script>alert(`upload ok`);location.href=`/`;</script>");
    }
    else{
        exit("<script>alert(`txt or png only`);history.go(-1);</script>");
    }
}
if($_GET['page'] == "download"){
    $escape_file=str_replace("/","",$_GET['file']);
    $escape_file=str_replace('\\\\',' ',$_GET['file']);
    $ext = explode(".",strtolower($_GET['file']));
    $cnt = count($ext)-1;
    if($ext[$cnt]===""){
        if(preg_match("/exe|jsp|php|aspx|bat|vbs|dll|jspx|asp|java|pdb/",$ext)){
            exit("");
        }
    }
    $escape_file = basename($escape_file);
    $content = file_get_contents("./upload/{$escape_file}");
    if(!$content){
        exit("<script>alert(`not exists file`);history.go(-1);</script>");
    }
    else{
        header("Content-Disposition: attachment;");
        echo file_get_contents("./upload/{$escape_file}");
        exit;
    }
}
if($_GET['page'] == "admin"){
    $db = dbconnect();
    $result = mysqli_fetch_array(mysqli_query($db,"select id from member where id='{$_SESSION['id']}'"));
    if($result['id'] == "admin"){
        echo htmlspecialchars(file_get_contents("/flag")); // do not remove it.
    }
    else{
        exit("<script>alert(`admin only`);history.go(-1);</script>");
    }
}

/*  this is hint. you can remove it.
CREATE TABLE `member` (
    `id` varchar(120) NOT NULL,
    `email` varchar(120) NOT NULL,
    `pw` varchar(120) NOT NULL,
    `type` varchar(5) NOT NULL
  );
  
  INSERT INTO `member` (`id`, `email`, `pw`, `type`)
      VALUES ('admin', '**SECRET**', '**SECRET**', 'admin');
*/

?>