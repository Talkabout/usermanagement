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

# This page is called to send a reset token by mail

#==============================================================================
# POST parameters
#==============================================================================
# Initiate vars
$result = "";
$login = "";
$mail = "";
$ldap = "";
$userdn = "";
$token = "";

if (!$mail_address_use_ldap) {
    if (isset($_POST["mail"]) and $_POST["mail"]) { $mail = $_POST["mail"]; }
     else { $result = "mailrequired"; }
}
if (isset($_REQUEST["login"]) and $_REQUEST["login"]) { $login = $_REQUEST["login"]; }
 else { $result = "loginrequired"; }
if (! isset($_POST["mail"]) and ! isset($_REQUEST["login"]))
 { $result = "emptysendtokenform"; }

# Strip slashes added by PHP
$login = stripslashes_if_gpc_magic_quotes($login);
$mail = stripslashes_if_gpc_magic_quotes($mail);

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
# Check mail
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

    $errno = ldap_errno($ldap);
    if ( $errno ) {
        $result = "ldaperror";
        error_log("LDAP - Bind error $errno (".ldap_error($ldap).")");
    } else {

    # Search for user
    $ldap_filter = str_replace("{login}", $login, $ldap_filter);
    $search = ldap_search($ldap, $ldap_base, $ldap_filter);

    $errno = ldap_errno($ldap);
    if ( $errno ) {
        $result = "ldaperror";
        error_log("LDAP - Search error $errno (".ldap_error($ldap).")");
    } else {

    # Get user DN
    $entry = ldap_first_entry($ldap, $search);
    $userdn = ldap_get_dn($ldap, $entry);

    if( !$userdn ) {
        $result = "badcredentials";
        error_log("LDAP - User $login not found");
    } else {

    # Compare mail values
    $mailValues = ldap_get_values($ldap, $entry, $mail_attribute);
    unset($mailValues["count"]);
    $match = 0;

    if (!$mail_address_use_ldap) {
        # Match with user submitted values
        foreach ($mailValues as $mailValue) {
            if (strcasecmp($mail_attribute, "proxyAddresses") == 0) {
                $mailValue = str_ireplace("smtp:", "", $mailValue);
            }
            if (strcasecmp($mail, $mailValue) == 0) {
                $match = 1;
            }
        }
    } else {
        # Use first available mail adress in ldap
        if(count($mailValues) > 0) {
            $mailValue = $mailValues[0];
            if (strcasecmp($mail_attribute, "proxyAddresses") == 0) {
                $mailValue = str_ireplace("smtp:", "", $mailValue);
            }
            $mail = $mailValue;
            $match = true;
        }
    }

    if (!$match) {
        if (!$mail_address_use_ldap) {
            $result = "mailnomatch";
            error_log("Mail $mail does not match for user $login");
        } else {
            $result = "mailnomatch";
            error_log("Mail not found for user $login");
        }
    }

}}}}}

#==============================================================================
# Build and store token
#==============================================================================
if ( $result === "" ) {

    # Use PHP session to register token
    # We do not generate cookie
    ini_set("session.use_cookies",0);
    ini_set("session.use_only_cookies",1);

    session_name("token");
    session_start();
    $_SESSION['login'] = $login;
    $_SESSION['time']  = time();

    if ( $crypt_tokens ) {
        $token = encrypt(session_id(), $keyphrase);
    } else {
        $token = session_id();
    }

}

#==============================================================================
# Send token by mail
#==============================================================================
if ( $result === "" ) {

    if ( empty($reset_url) ) {

        # Build reset by token URL
        $method = "http";
        if ( !empty($_SERVER['HTTPS']) ) { $method .= "s"; }
        $server_name = $_SERVER['SERVER_NAME'];
        $server_port = $_SERVER['SERVER_PORT'];
        $script_name = $_SERVER['SCRIPT_NAME'];

        # Force server port if non standard port
        if (   ( $method === "http"  and $server_port != "80"  )
            or ( $method === "https" and $server_port != "443" )
        ) {
            $server_name .= ":".$server_port;
        }

        $reset_url = $method."://".$server_name.$script_name;
    }

    $reset_url .= "?action=resetbytoken&token=".urlencode($token);

    if ( !empty($reset_request_log) ) {
        error_log("Send reset URL $reset_url \n\n", 3, $reset_request_log);
    } else {
        error_log("Send reset URL $reset_url");
    }

    $data = array( "login" => $login, "mail" => $mail, "url" => $reset_url ) ;

    # Send message
    if ( send_mail($mailer, $mail, $mail_from, $mail_from_name, $messages["resetsubject"], $messages["resetmessage"].$mail_signature, $data) ) {
        $result = "tokensent";
    } else {
        $result = "tokennotsent";
        error_log("Error while sending token to $mail (user $login)");
    }
}


# Render associated template
echo $twig->render('sendtoken.twig', array(
    'result' => $result,
    'show_help' => $show_help,
    'login' => $login,
    'mail_address_use_ldap' => $mail_address_use_ldap,
    'recaptcha_publickey' => $recaptcha_publickey,
    'recaptcha_theme' => $recaptcha_theme,
    'recaptcha_type' => $recaptcha_type,
    'recaptcha_size' => $recaptcha_size,
    'lang' => $lang,


    'background_image' => $background_image,
    'show_menu' => $show_menu,
    'logo' => $logo,
    'dependency_check_results' => $dependency_check_results,

    'use_questions' => $use_questions,
    'use_tokens' => $use_tokens,
    'use_sms' => $use_sms,
    'change_sshkey' => $change_sshkey,
    'action' => $action,
    'source' => $source,
));
