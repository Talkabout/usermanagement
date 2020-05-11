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
$login = $_SESSION['login'];
$password = $_SESSION['password'];
$ldap = "";
$userdn = "";
$username = "";

if(isset($_POST["username"]) && $_POST['username']) { $username = $_POST['username']; }
else { $result = "emptydeleteform"; }

#==============================================================================
# Get mail
#==============================================================================

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
$search = ldap_search($ldap, $ldap_base, $ldap_filter);

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

$ldapResult = ldap_search($ldap, "cn=Users,dc=home,dc=intern", "objectclass=user", array('dn', 'cn'));
$entries    = ldap_get_entries($ldap, $ldapResult);
$users      = array();

foreach ($entries as $key => $value) {
    if (is_numeric($key)) {
        $users[$value[dn]] = $value['cn'][0];
    }
}

asort($users, SORT_NATURAL | SORT_FLAG_CASE);

}}}}

#==============================================================================
# delete user
#==============================================================================
if (!empty($username)) { 
    $result = delete_user($ldap, $username);
}

#==============================================================================
# HTML
#==============================================================================
if ( in_array($result, $obscure_failure_messages) ) { $result = "badcredentials"; }
?>

<div class="result alert alert-<?php echo get_criticity($result) ?>">
<p><i class="fa fa-fw <?php echo get_fa_class($result) ?>" aria-hidden="true"></i> <?php echo $messages[$result]; ?></p>
</div>

<?php if ( $display_posthook_error and $posthook_return > 0 ) { ?>

<div class="result alert alert-warning">
<p><i class="fa fa-fw fa-exclamation-triangle" aria-hidden="true"></i> <?php echo $posthook_output[0]; ?></p>
</div>

<?php } ?>

<?php if ( $result !== "userdeleted" ) { ?>

<div class="alert alert-info">
<form action="#" method="post" class="form-horizontal">
    <div class="form-group">
        <label for="username" class="col-sm-4 control-label"><?php echo $messages['username']; ?></label>
        <div class="col-sm-8">
            <div class="input-group">
                <span class="input-group-addon"><i class="fa fa-fw fa-user"></i></span>
		<select class="form-control" name="username" id="username">
		    <option value=""></option>
<?php foreach ($users as $dn => $name) { ?>
		    <option value="<?php echo $name; ?>" <?php if ($_POST['username'] == $name) echo 'selected="selected"'; ?>><?php echo $name; ?></option>
<?php } ?>
		</select>
            </div>
        </div>
  </div>
    <div class="form-group">
        <div class="col-sm-offset-4 col-sm-8">
            <button type="submit" class="btn btn-success">
                <i class="fa fa-fw fa-check-square-o"></i> <?php echo $messages['submit']; ?>
            </button>
        </div>
    </div>
</form>
</div>

<?php } ?>
