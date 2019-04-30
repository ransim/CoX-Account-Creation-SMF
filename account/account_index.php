<?php

global $ssi_guest_access;
global $smcFunc;
global $user_info;
$ssi_guest_access = false;
require_once('../SSI.php');

function adler32($data)
{
        $mod_adler = 65521;
        $a = 1;
        $b = 0;
        $len = strlen($data);
        for($index = 0; $index < $len; $index++)
        {
                $a = ($a + ord($data[$index])) % $mod_adler;
                $b = ($b + $a) % $mod_adler;
        }

        return ($b << 16) | $a;
}

function game_hash_password($authname, $password)
{
        $authname = strtolower($authname);
        $a32 = adler32($authname);
        $a32hex = sprintf('%08s', dechex($a32));
        $a32hex = substr($a32hex, 6, 2) . substr($a32hex, 4, 2) . substr($a32hex, 2, 2) . substr($a32hex, 0, 2);
        $digest = hash('sha512', $password . $a32hex, TRUE);
        return $digest;
}

$context['page_title_html_safe'] = 'Game Account';
template_html_above();
template_body_above();

echo '<table class="table_list"><tbody class="header" id="category_4"><tr><td><div class="cat_bar"><h3 class="catbg">';
echo 'Game Account</h3></div></td></tr></tbody></table><div style="margin: 50px 100px;">';

$forum_id = $user_info['id'];
$is_admin = allowedTo('admin_forum');

// Admins can use this page as any user by passing a different forum ID.
if ($is_admin and isset($_REQUEST['fid'])) $forum_id = intval($_REQUEST['fid']);

$validationerror = false;
$errormsg = '';

//Getting your Microsoft SQL Server ODBC Connected
$serverName = "Server Connection String"; 
$connectionInfo = array( 
	"Database"=>"DB NAME", 
	"UID"=>"DB USER", 
	"PWD"=>"DB PASSWORD", 
	);
$conn = sqlsrv_connect( $serverName, $connectionInfo );
if( $conn === false ) {
	die( print_r( sqlsrv_errors(), true));
}

//Make sure the logged in user has a forum_id, otherwise something is wrong.
if ($forum_id > 0)
{
	//Process form if submitted
	if (isset($_POST['authname']) && isset($_POST['password']))
	{
			// Validate the stuff and send it over.
			$authname = trim($_POST['authname']);
			$password = trim($_POST['password']); 
			if (!ctype_alnum($authname))
				{
						echo '<span style="color: yellow"><b>ERROR:</b> Your login name must contain only letters and numbers.</span><br><br>';
						$validationerror = true;
				}
				else if (strlen($authname) > 14)
				{
						echo '<span style="color: yellow"><b>ERROR:</b> Your login name is too long.</span><br><br>';
						$validationerror = true;
				}
				else if (strlen($password) < 8)
				{
						echo '<span style="color: yellow"><b>ERROR:</b> Your password is too short.</span><br><br>';
						$validationerror = true;
				}
				else if (strlen($password) > 16)
				{
						echo '<span style="color: yellow"><b>ERROR:</b> Your password is too long.</span><br><br>';
						$validationerror = true;
				} 
				if ($validationerror == false)
					{     
					$password = bin2hex(game_hash_password($authname, $password));

				   // First lets verify there isn't already an account
					$sql = "SELECT TOP 1 * from user_account where account = ? and forum_id =?";
					$params = array( $authname, $forum_id );
					$acctchk = sqlsrv_query( $conn, $sql, $params );
					if( $acctchk === false) {
						die( print_r( sqlsrv_errors(), true));
					} else {
					if( sqlsrv_has_rows($acctchk) === true) {
						//Ok, account exists so lets just reset/change the password
							$pwdsql = "UPDATE user_auth SET password=CONVERT(BINARY(128),?) WHERE account=?";
							$paramspwd = array($password, $authname);
							$updatepwd = sqlsrv_query($conn, $pwdsql, $paramspwd);
							if ($updatepwd === false){
							    die( "Password Update Failed. ".print_r( sqlsrv_errors(), true));
							} else {
								echo "<p><strong>Your password has been updated.</strong></p>";
							}
							sqlsrv_free_stmt( $updatepwd );
						}
						else
						{
							//Lets generate an account 
							//First, lets make sure its not a dupe username
							$authsql = "SELECT account FROM user_account WHERE account=?";
							$paramsauth = array($authname);
							$authchk = sqlsrv_query($conn, $authsql, $paramsauth);
							if( sqlsrv_has_rows($authchk) === true) {
								echo "<p style='color:red'><strong>The account name is already taken. Try Again.</strong></p>";
							} else {
								//Increment the Auth ID - for some reason the account is the PK >_>
								//Also UID isn't auto increment, lulz
								$authidsql = "SELECT MAX(uid)+1 as newID FROM user_account";
								$authidchk = sqlsrv_query($conn, $authidsql);
								if($authidchk < 1) {
									echo "Something is really broken, try again in a few minutes.";
								} else {
									$row = sqlsrv_fetch_array($authidchk);
									$authid = $row['newID'];
									//Insert Account details in SQL DB
									//Start Account Creation Transaction
									if ( sqlsrv_begin_transaction( $conn ) === false ) {
										die( "Connection Failed. ".print_r( sqlsrv_errors(), true));
									}
									
									// First lets insert the main user account record								
									$sql1 = "INSERT INTO user_account (account, uid, forum_id, pay_stat) VALUES (?, ?, ?, 1014);";
									$params1 = array( $authname, $authid ,$forum_id );
									$addacct = sqlsrv_query($conn, $sql1, $params1);
									
									//Alright now lets try to insert the hashed/salted password
									$sql2 = "INSERT INTO user_auth (account, password, salt, hash_type) VALUES ('?', CONVERT(BINARY(128),''), 0, 1);";
									$params2 = array( $authname, $password );
									$addauth = sqlsrv_query($conn, $sql2, $params2);
									
									//Insert user data now						
									$sql3 = "INSERT INTO user_data (uid, user_data) VALUES (?, 0x0080C2E000D00B0C000000000CB40058);";
									$params3 = array( $authid ); 
									$adddata = sqlsrv_query($conn, $sql3, $params3);
									
									//Last steps, insert a general server group value									
									$sql4 = "INSERT INTO user_server_group (uid, server_group_id) VALUES (?, 1);";
									$addgroup = sqlsrv_query($conn, $sql4, $params3); // same parameters no point redefining.
									
									//If all four queries were successful then lets commit, otherwise rollback and give an error.
									if( $addacct && $addauth && $adddata && $addgroup ) {
										sqlsrv_commit( $conn );
											echo "<p><strong>Account created successfully!.</strong><p>";
									} else {
										sqlsrv_rollback( $conn );
											echo "<p style='color:red'><strong>Account creation failed, error logged. Please report to admins.<br />";
									}
									/* Free statement and connection resources. */  
									sqlsrv_free_stmt( $addacct);  
									sqlsrv_free_stmt( $addauth);  
									sqlsrv_free_stmt( $adddata);  
									sqlsrv_free_stmt( $addgroup);  
								//}
								
							}
							sqlsrv_free_stmt( $authchk );
						}
						sqlsrv_free_stmt( $acctchk) ;
					}
				}                    
	}
		
		$acctlookupsql = "SELECT uid, account FROM user_account WHERE forum_id=?";
		$paramslookup = array( $forum_id );
		$authlookupchk = sqlsrv_query($conn, $acctlookupsql, $paramslookup);
			while ($row = sqlsrv_fetch_array($authlookupchk)) {
                $authid = $row['uid'];
                $authname = $row['account'];
			}

        if ($authid > 0)
        {
                // Has a game account. Prompt to change password.
                echo 'Your game login username is <b>' . $authname . '</b>. You can change your game account password by entering a new one below.<br><br>';
                echo '<form method="post" autocomplete="off"><span style="display: inline-block; width: 80px;">Login: </span><input type="text" name="authname" value="' . $authname . '" maxlength=14 readonly><br>';
                echo '<span style="display: inline-block; width: 80px;">Password: </span><input type="password" name="password" maxlength=16> <small>(between 8 and 16 characters)</small><br><br>';
                echo '<span style="display: inline-block; width: 80px;"><input type="hidden" name="fid" value="' . $forum_id . '"></span>';
                echo '<input style="display: inline-block; width: 160px;" type="submit" value="Change Game Password"></form>';
        }
        else
        {
                // No game account. Prompt to create one.
                echo 'Select a login name and password for your game account. You will be able to change the password from this page at any time.<br><br>';
                echo '<form method="post" autocomplete="off"><span style="display: inline-block; width: 80px;">Login: </span><input type="text" name="authname" maxlength=14> <small>(maximum 14 characters; only letters and numbers)</small><br>';
                echo '<span style="display: inline-block; width: 80px;">Password: </span><input type="password" name="password" maxlength=16> <small>(between 8 and 16 characters)</small><br><br>';
                echo '<span style="display: inline-block; width: 80px;"><input type="hidden" name="fid" value="' . $forum_id . '"></span>';
                echo '<input style="display: inline-block; width: 160px;" type="submit" value="Create Game Account"></form>';
        }
} 
else
{
        echo '<b>ERROR:</b> You are not logged in to the forums. This should never happen. Please report this error.</a>';
}
//Uncomment for error reporting
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

sqlsrv_close( $conn); 


echo '</div>';

template_body_below();
template_html_below();
?>

