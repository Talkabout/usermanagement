<?php
#==============================================================================
# LTB Self Service Password
#
# Copyright (C) 2009 Clement OUDOT
# Copyright (C) 2009 LTB-project.org
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# GPL License: http://www.gnu.org/licenses/gpl.txt
#
#==============================================================================

# This page is called to change password

#==============================================================================
# POST parameters
#==============================================================================
# Initiate vars
$result = "";
$login = "";
$password = "";
$ldap = "";
$userdn = "";
if (!isset($pwd_forbidden_chars)) { $pwd_forbidden_chars=""; }
$mail = "";

if (!isset($_SESSION['lastLoginAttempt']) || (time() - $_SESSION['lastLoginAttempt'] >= 300)) {
    $_SESSION['loginCounter'] = 0;
}

if (isset($_POST["password"]) and $_POST["password"]) { $password = strval($_POST["password"]); }
 else { $result = "passwordrequired"; }
if (isset($_REQUEST["login"]) and $_REQUEST["login"]) { $login = strval($_REQUEST["login"]); }
 else { $result = "loginrequired"; }

# Check the entered username for characters that our installation doesn't support
if ( $result === "" ) {
    $result = check_username_validity($login,$login_forbidden_chars);
}

#==============================================================================
# Check reCAPTCHA
#==============================================================================
if ( $result === "" && $use_recaptcha ) {
    $result = check_recaptcha($recaptcha_privatekey, $recaptcha_request_method, $_POST['g-recaptcha-response'], $login);
}

#==============================================================================
# Check password
#==============================================================================
if ( $result === "" ) {

    # Connect to LDAP
    $ldap = ldap_connect($ldap_url);
    ldap_set_option($ldap, LDAP_OPT_PROTOCOL_VERSION, 3);
    ldap_set_option($ldap, LDAP_OPT_REFERRALS, 0);
    if ( $ldap_starttls && !ldap_start_tls($ldap) ) {
        $result = "ldaperror";
        error_log("LDAP - Unable to use StartTLS");
    } else {

    # Bind
    if ( isset($ldap_binddn) && isset($ldap_bindpw) ) {
        $bind = ldap_bind($ldap, $ldap_binddn, $ldap_bindpw);
    } else {
        $bind = ldap_bind($ldap);
    }

    if ( !$bind ) {
        $result = "ldaperror";
        $errno = ldap_errno($ldap);
        if ( $errno ) {
	    error_log("LDAP - Bind error $errno  (".ldap_error($ldap).")");
        }
    } else {

    # Search for user
    $ldap_filter = str_replace("{login}", $login, $ldap_filter);
    $search = ldap_search($ldap, $ldap_base, $ldap_filter, array('objectclass', 'memberof', 'dn', 'thumbnailphoto'));
    $entries = ldap_get_entries($ldap, $search);

    $errno = ldap_errno($ldap);
    if ( $errno ) {
        $result = "ldaperror";
        error_log("LDAP - Search error $errno  (".ldap_error($ldap).")");
    } else {

    # Get user DN
    $entry = ldap_first_entry($ldap, $search);
    $userdn = ldap_get_dn($ldap, $entry);

    if( !$userdn ) {
        $result = "badcredentials";
        error_log("LDAP - User $login not found");
    } else {

    # Check objectClass to allow samba and shadow updates
    $ocValues = ldap_get_values($ldap, $entry, 'objectClass');
    if ( !in_array( 'sambaSamAccount', $ocValues ) and !in_array( 'sambaSAMAccount', $ocValues ) ) {
        $samba_mode = false;
    }
    if ( !in_array( 'shadowAccount', $ocValues ) ) {
        $shadow_options['update_shadowLastChange'] = false;
        $shadow_options['update_shadowExpire'] = false;
    }

    # Bind with password
    $bind = ldap_bind($ldap, $userdn, $password);
    if ( !$bind ) {
        $result = "badcredentials";
        $errno = ldap_errno($ldap);
        if ( $errno ) {
            error_log("LDAP - Bind user error $errno  (".ldap_error($ldap).")");
        }
        if ( ($errno == 49) && $ad_mode ) {
            if ( ldap_get_option($ldap, 0x0032, $extended_error) ) {
                error_log("LDAP - Bind user extended_error $extended_error  (".ldap_error($ldap).")");
                $extended_error = explode(', ', $extended_error);
                if ( strpos($extended_error[2], '773') or strpos($extended_error[0], 'NT_STATUS_PASSWORD_MUST_CHANGE') ) {
                    error_log("LDAP - Bind user password needs to be changed");
                    $result = "";
                }
                if ( ( strpos($extended_error[2], '532') or strpos($extended_error[0], 'NT_STATUS_ACCOUNT_EXPIRED') ) and $ad_options['change_expired_password'] ) {
                    error_log("LDAP - Bind user password is expired");
                    $result = "";
                }
                unset($extended_error);
            }
        }
    }
    if ( $result === "" )  {

        # Rebind as Manager if needed
        if ( $who_change_password == "manager" ) {
            $bind = ldap_bind($ldap, $ldap_binddn, $ldap_bindpw);
        }

	$result = 'loggedin';
    }}}}}

    if ($result !== 'loggedin') {
        sleep($_SESSION['loginCounter']);
    }

    $_SESSION['lastLoginAttempt'] = time();

    if ($_SESSION['loginCounter'] < 5) {
        $_SESSION['loginCounter']++;
    }

}

#==============================================================================
# HTML
#==============================================================================
if ( in_array($result, $obscure_failure_messages) ) {
    $result = "badcredentials";
}
?>

<?php if (sizeof($_POST)) { ?>

<div class="result alert alert-<?php echo get_criticity($result) ?>">
<p><i class="fa fa-fw <?php echo get_fa_class($result) ?>" aria-hidden="true"></i> <?php echo $messages[$result]; ?></p>
</div>

<?php } ?>

<?php if ( $display_posthook_error and $posthook_return > 0 ) { ?>

<div class="result alert alert-warning">
<p><i class="fa fa-fw fa-exclamation-triangle" aria-hidden="true"></i> <?php echo $posthook_output[0]; ?></p>
</div>

<?php } ?>

<?php if ( $result !== "loggedin" ) { ?>

<?php
if ($pwd_show_policy_pos === 'above') {
    show_policy($messages, $pwd_policy_config, $result);
}
?>

<div class="alert alert-info">
<form action="#" method="post" class="form-horizontal">
    <div class="form-group">
        <label for="login" class="col-sm-4 control-label"><?php echo $messages["login"]; ?></label>
        <div class="col-sm-8">
            <div class="input-group">
                <span class="input-group-addon"><i class="fa fa-fw fa-user"></i></span>
                <input type="text" name="login" id="login" value="<?php echo htmlentities($login) ?>" class="form-control" placeholder="<?php echo $messages["login"]; ?>" />
            </div>
        </div>
    </div>
    <div class="form-group">
        <label for="password" class="col-sm-4 control-label"><?php echo $messages["password"]; ?></label>
        <div class="col-sm-8">
            <div class="input-group">
                <span class="input-group-addon"><i class="fa fa-fw fa-lock"></i></span>
                <input type="password" name="password" id="password" class="form-control" placeholder="<?php echo $messages["password"]; ?>" />
            </div>
        </div>
    </div>
<?php if ($use_recaptcha) { ?>
    <div class="form-group">
        <div class="col-sm-offset-4 col-sm-8">
            <div class="g-recaptcha" data-sitekey="<?php echo $recaptcha_publickey; ?>" data-theme="<?php echo $recaptcha_theme; ?>" data-type="<?php echo $recaptcha_type; ?>" data-size="<?php echo $recaptcha_size; ?>"></div>
            <script type="text/javascript" src="https://www.google.com/recaptcha/api.js?hl=<?php echo $lang; ?>"></script>
        </div>
    </div>
<?php } ?>
    <div class="form-group">
        <div class="col-sm-offset-4 col-sm-8">
            <button type="submit" class="btn btn-success">
                <i class="fa fa-fw fa-check-square-o"></i> <?php echo $messages['submit']; ?>
            </button>
        </div>
    </div>
</form>
</div>

<?php
if ($pwd_show_policy_pos === 'below') {
    show_policy($messages, $pwd_policy_config, $result);
}
?>

<?php } else {

	$_SESSION['authenticated']  = true;
	$_SESSION['login']          = $login;
	$_SESSION['password']       = $password;
	$_SESSION['objectclass']    = $entries[0]['objectclass'];
	$_SESSION['memberof']       = $entries[0]['memberof'];
	$_SESSION['dn']             = $entries[0]['dn'];
	$_SESSION['thumbnailphoto'] = $entries[0]['thumbnailphoto'] ?? '';
  $_SESSION['loginCounter']  = 0;

  if (is_array($_SESSION['memberof']) && count($_SESSION['memberof'])) {
      $_SESSION['administrator'] = !(array_search(strtolower($ldap_administration_dn), array_map('strtolower', $_SESSION['memberof'])) === false);
  }

	header('Location: index.php');

}
?>

