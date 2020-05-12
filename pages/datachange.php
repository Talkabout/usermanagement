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
$administrator = $_SESSION['administrator'];
$currentlogin = $_POST['login'] ?? $_GET['login'] ?? $_SESSION['currentlogin'] ?? $_SESSION['login'];
$additionalResult = '';

if (!$administrator) {
  $currentlogin = $_SESSION['login'];
}

$_SESSION['currentlogin'] = $currentlogin;

$password = $_SESSION['password'];
$ldap = "";
$userdn = "";
$data= null;

$attributeMapping = array(
    'displayname' => array(
        'icon' => 'user',
        'tab' => $messages['tabgeneral']
    ),
    'givenname' => array(
        'icon' => 'user',
        'tab' => $messages['tabgeneral']
    ),
    'sn' => array(
        'icon' => 'user',
        'tab' => $messages['tabgeneral']
    ),
    'initials' => array(
        'icon' => 'user',
        'tab' => $messages['tabgeneral']
    ),
    'memberof' => array(
        'icon' => 'unlock',
        'tab' => $messages['tabgroups'],
        'admin' => true,
        'values' => array()
    ),
    'objectclass' => array(
        'icon' => 'tag',
        'tab' => $messages['tabobjectclasses'],
        'admin' => true,
        'values' => array()
    ),
    'mail' => array(
        'icon' => 'envelope',
        'tab' => $messages['tabgeneral']
    ),
    'othermailbox' => array(
        'icon' => 'envelope',
        'tab' => $messages['tabgeneral'],
        'dependency' => 'mail'
    ),
    'streetaddress' => array(
        'icon' => 'map-marker',
        'tab' => $messages['tabaddress']
    ),
    'l' => array(
        'icon' => 'map-marker',
        'tab' => $messages['tabaddress']
    ),
    'postalcode' => array(
        'icon' => 'map-marker',
        'tab' => $messages['tabaddress']
    ),
    'st' => array(
        'icon' => 'map-marker',
        'tab' => $messages['tabaddress']
    ),
    'c' => array(
        'icon' => 'map-marker',
        'tab' => $messages['tabaddress'],
        'values' => get_country_codes($lang)
    ),
    'homephone' => array(
        'icon' => 'phone',
        'tab' => $messages['tabcontact']
    ),
    'otherhomephone' => array(
        'icon' => 'phone',
        'tab' => $messages['tabcontact'],
        'dependency' => 'homephone'
    ),
    'mobile' => array(
        'icon' => 'mobile',
        'tab' => $messages['tabcontact']
    ),
    'othermobile' => array(
        'icon' => 'mobile',
        'tab' => $messages['tabcontact'],
        'dependency' => 'mobile'
    ),
    'telephonenumber' => array(
        'icon' => 'phone',
        'tab' => $messages['tabcontact']
    ),
    'othertelephone' => array(
        'icon' => 'phone',
        'tab' => $messages['tabcontact'],
        'dependency' => 'telephonenumber'
    ),
    'facsimiletelephonenumber' => array(
        'icon' => 'fax',
        'tab' => $messages['tabcontact']
    ),
    'otherfacsimiletelephonenumber' => array(
        'icon' => 'fax',
        'tab' => $messages['tabcontact'],
        'dependency' => 'facsimiletelephonenumber'
    ),
    'wwwhomepage' => array(
        'icon' => 'globe',
        'tab' => $messages['tabcontact']
    ),
    'url' => array(
        'icon' => 'globe',
        'tab' => $messages['tabcontact'],
        'dependency' => 'wwwhomepage'
    ),
    'title' => array(
        'icon' => 'user',
        'tab' => $messages['taborganization']
    ),
    'department' => array(
        'icon' => 'user',
        'tab' => $messages['taborganization']
    ),
    'company' => array(
        'icon' => 'user',
        'tab' => $messages['taborganization']
    ),
    'manager' => array(
        'icon' => 'user',
        'tab' => $messages['taborganization'],
        'values' => array('' => '')
    ),
    'directreports' => array(
        'icon' => 'user',
        'tab' => $messages['taborganization'],
        'readonly' => true,
        'values' => array()
    ),
    'thumbnailphoto' => array(
        'icon' => 'photo',
        'tab' => $messages['tabgeneral']
    )
);

if (isset($ldap_additional_attributes) && is_array($ldap_additional_attributes)) {
    $attributeMapping = array_replace_recursive($attributeMapping, $ldap_additional_attributes);
}

$files['thumbnailphoto'] = true;

if (isset($_POST) && sizeof($_POST)) {
    $data = array();

    foreach ($_POST as $key => $value) {
        if (preg_match('/^data_(.+)$/', $key, $matches)) {
            $data[$matches[1]] = $value;
        }
    }

    if (isset($data['mail'])) {
        foreach ($data['mail'] as $mail) {
            if (!filter_var($mail, FILTER_VALIDATE_EMAIL)) {
                $result = "emailinvalid";
                $data = null;
                break;
            }
        }
    }
    else {
        $result = "emailinvalid";
        $data = null;
    }

    if (count($_FILES)) {
        echo ob_get_clean();

        foreach ($_FILES as $key => $file) {
            if ($file['error'] === UPLOAD_ERR_NO_FILE) {
                continue;
            }
            if ($file['error'] === UPLOAD_ERR_OK && preg_match('/^data_(.+)$/', $key, $matches)) {
                $file = file_get_contents($file['tmp_name']);
                if ($image = imagecreatefromstring($file)) {
                    ob_start();
                    imagejpeg($image);
                    $data['photo'] = array(ob_get_clean());
                    $image = imagescale($image, 500);
                    $height = imagesy($image);
                    $image = imagecrop($image, array('x' => 0, 'y' => ($height > 500 ? round(($height - 500)/2) : 0), 'width' => 500, 'height' => 500));
                    ob_start();
                    imagejpeg($image);
                    $data[$matches[1]] = array(ob_get_clean());
                    $data['jpegphoto'] = $data[$matches[1]];
                }
                else {
                    $result = 'imageinvalid';
                    $data = null;
                }
            }
        }
    }

    foreach (array('wwwhomepage', 'url') as $name) {
        if (isset($data[$name])) {
            foreach ($data[$name] as $homepage) {
                if ($homepage && !filter_var($homepage, FILTER_VALIDATE_URL)) {
                    $result = "homepageinvalid";
                    $data = null;
                    break;
                }
            }
        }
    }
    if (isset($data['postalcode']) && $data['postalcode']) {
        foreach ($data['postalcode'] as $postalcode) {
            if ($postalcode && !preg_match('/^[0-9\-]+$/', $postalcode)) {
                $result = "postalcodeinvalid";
                $data = null;
                break;
            }
        }
    }
    if (isset($data['c'])) {
        foreach ($data['c'] as $country) {
            if ($country && !preg_match('/^[A-Z]{2}$/', $country)) {
                $result = "countryinvalid";
                $data = null;
                break;
            }
        }
    }
}
else if(isset($_POST["mail"])) { $result = "mailrequired"; }
else { $result = "emptydatachangeform"; }

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

                if ($administrator) {
                    if (!isset($_SESSION['allgroups'])) {
                        $ldapResult = ldap_search($ldap, "cn=Users," . $ldap_base, "objectclass=group", array('dn', 'cn'));
                        $entries = ldap_get_entries($ldap, $ldapResult);

                        foreach ($entries as $key => $value) {
                            if (is_numeric($key)) {
                               $attributeMapping['memberof']['values'][$value[dn]] = $value['cn'][0];
                            }
                        }

                        asort($attributeMapping['memberof']['values'], SORT_NATURAL | SORT_FLAG_CASE);

                        $_SESSION['allgroups'] = $attributeMapping['memberof']['values'];
                    }
                    else {
                        $attributeMapping['memberof']['values'] = $_SESSION['allgroups'];
                    }

                    if (!isset($_SESSION['allobjectclasses'])) {
                        $ldapResult = ldap_search($ldap, "cn=Schema,cn=Configuration," . $ldap_base, "objectclass=classSchema", array('dn', 'cn', 'ldapdisplayname'));
                        $entries = ldap_get_entries($ldap, $ldapResult);

                        foreach ($entries as $key => $value) {
                            if (is_numeric($key)) {
                                $attributeMapping['objectclass']['values'][$value['ldapdisplayname'][0]] = $value['ldapdisplayname'][0];
                            }
                        }

                        asort($attributeMapping['objectclass']['values'], SORT_NATURAL | SORT_FLAG_CASE);

                        $_SESSION['allobjectclasses'] = $attributeMapping['objectclass']['values'];
                    }
                    else {
                        $attributeMapping['objectclass']['values'] = $_SESSION['allobjectclasses'];
                    }

                    if (!isset($_SESSION['allusers'])) {
                        $ldapResult = ldap_search($ldap, "cn=Users," . $ldap_base, "objectclass=user", array('dn', 'cn', 'givenName', 'sn'));
                        $entries    = ldap_get_entries($ldap, $ldapResult);
                        $users      = array();

                        foreach ($entries as $key => $value) {
                            if (is_numeric($key)) {
                                $fullname = $value['sn'][0] . ', ' . $value['givenname'][0];
                                if (!trim($fullname, ' ,')) {
                                    $fullname = $value['cn'][0];
                                }
                                else {
                                    $fullname .= ' (' . $value['cn'][0] . ')';
                                }
                                $users[$value[dn]] = $fullname;
                            }
                        }

                        asort($users, SORT_NATURAL | SORT_FLAG_CASE);

                        $_SESSION['allusers'] = $users;
                    }
                    else {
                        $users = $_SESSION['allusers'];
                    }

                    $attributeMapping['manager']['values'] = array_merge(array('' => ''), $users);
                    $attributeMapping['directreports']['values'] = array_merge(array('' => ''), $users);
                }

                $ldapResult = ldap_search($ldap, "cn=Schema,cn=Configuration," . $ldap_base, '(|(ldapdisplayname=' . implode(')(ldapdisplayname=', array_keys($attributeMapping)) . '))', array('dn', 'cn', 'isSingleValued', 'ldapdisplayname'));
                $entries = ldap_get_entries($ldap, $ldapResult);

                $attributes = array();
                foreach ($entries as $index => $entry) {
                    $attributes[strtolower($entries[$index]['ldapdisplayname'][0])] = array('cn' => $entry['cn'][0], 'multiple' => $entry['issinglevalued'][0] == "FALSE");
                }

                $ldapResult = ldap_search($ldap, "cn=Users," . $ldap_base, "cn=$currentlogin", array_keys($attributeMapping));
                $ldapData   = ldap_get_entries($ldap, $ldapResult);
                $userdn     = $ldapData[0]['dn'];

                if ($data === null) {
                    $data = $ldapData;

                    if ($currentlogin == $_SESSION['login']) {
                        $_SESSION['objectclass'] = $data[0]['objectclass'];
                        $_SESSION['memberof'] = $data[0]['memberof'];
                    }
                }

                $ldapResult = ldap_search($ldap, "cn=Schema,cn=Configuration," . $ldap_base, '(|(ldapdisplayname=' . implode(')(ldapdisplayname=', $data[0]['objectclass']) . '))', array('dn', 'cn', 'maycontain', 'systemmaycontain', 'ldapdisplayname'));
                $entries = ldap_get_entries($ldap, $ldapResult);

                $availableAttributes = array();
                foreach ($entries as $index => $entry) {
                    if (isset($entry['maycontain'])) {
                        $availableAttributes = array_merge($availableAttributes, array_filter(
                            $entry['maycontain'],
                            function ($value, $key) {
                                return is_numeric($key);
                            },
                            ARRAY_FILTER_USE_BOTH
                        ));
                    }
                    if (isset($entry['systemmaycontain'])) {
                        $availableAttributes = array_merge($availableAttributes, array_filter(
                            $entry['systemmaycontain'],
                            function ($value, $key) {
                                return is_numeric($key);
                            },
                            ARRAY_FILTER_USE_BOTH
                        ));
                    }
                }

                $availableAttributes[] = 'objectclass';

                $attributeMapping = array_intersect_key($attributeMapping, array_flip(array_map('strtolower', $availableAttributes)));
            }
        }
    }
}

#==============================================================================
# Set mail
#==============================================================================
if (isset($_POST) and sizeof($_POST) && !preg_match('/.+invalid$/', $result)) { 
    $result = change_data($ldap, $userdn, $data);
    preg_match('/([^\[]+)(\[([^\]]+)\])?/', $result, $matches);
    $result = $matches[1];
    $additionalResult = ($matches[3] ?? '');
}

#==============================================================================
# HTML
#==============================================================================
if ( in_array($result, $obscure_failure_messages) ) { $result = "badcredentials"; }
?>

<div style="position: relative;" class="result alert alert-<?php echo get_criticity($result) ?>">
<p><i class="fa fa-fw <?php echo get_fa_class($result) ?>" aria-hidden="true"></i> <?php echo $messages[$result] . (!empty($additionalResult) ? ' (' . $additionalResult . ')' : ''); ?></p>
<?php if ($_SESSION['login'] != $currentlogin && isset($data[0]['thumbnailphoto'])) { ?>
<div style="float: right;">
<div
   class="profile-image"
   style="background-image:url('data:image/png;base64,<?php echo base64_encode($data[0]['thumbnailphoto'][0]); ?>');"
   data-toggle="popover"
   data-content="<div class='profile-image large' style=&quot;background-image:url('data:image/png;base64,<?php echo base64_encode($data[0]['thumbnailphoto'][0]); ?>');&quot;></div>"
   data-html="true"
>
</div>
</div>
<?php } ?>
</div>

<?php if ( $display_posthook_error and $posthook_return > 0 ) { ?>

<div class="result alert alert-warning">
    <p><i class="fa fa-fw fa-exclamation-triangle" aria-hidden="true"></i> <?php echo $posthook_output[0]; ?></p>
</div>

<?php } ?>

<?php if ( $result !== "datachanged" ) { ?>

<?php
if ($pwd_show_policy_pos === 'above') {
    show_policy($messages, $pwd_policy_config, $result);
}
?>

<div class="alert alert-info">
<form action="#" method="post" class="form-horizontal" enctype="multipart/form-data">

<?php if ($administrator) { ?>
  <div class="group-container user">
    <div class="form-group">
        <label for="login" class="col-sm-4 control-label"><?php echo $messages['login']; ?></label>
        <div class="col-sm-8">
            <div class="input-group">
                <span class="input-group-addon"><i class="fa fa-fw fa-user"></i></span>
		<select class="form-control" name="login" id="login" onchange="location.href = '?login=' + this[this.selectedIndex].value">
<?php foreach ($users as $dn => $name) {
    preg_match('/^cn=([^,]+)/i', $dn, $matches);
    $cn = $matches[1];
?>
		    <option value="<?php echo $cn ; ?>" <?php if ($userdn == $dn) echo 'selected="selected"'; ?>><?php echo $name; ?></option>
<?php } ?>
		</select>
            </div>
        </div>
    </div>
  </div>
<?php } ?>
<?php
    foreach ($attributeMapping as $name => $details) {
        if (isset($details['admin']) && $details['admin'] && !$administrator) {
            continue;
        }
?>
<?php ob_start(); ?>
<?php $values = ($_POST['data_' . $name] ?? ($data[0][$name] ?? array(''))); ?>
<div id="container_<?php echo $name; ?>" class="group-container <?php echo (!count(array_filter($values)) && isset($attributeMapping[$name]['dependency']) ? 'hidden' : ''); ?>">
<div id="<?php echo $name; ?>">
<?php foreach ($values as $key => $value) { ?>
<?php if (is_numeric($key)) { ?>
<?php if (isset($attributeMapping[$name]['readonly']) && $attributeMapping[$name]['readonly'] && empty($value)) continue; ?>
    <div class="form-group <?php echo ($attributes[$name]['multiple'] ? 'multiple' : '') . ' ' . $name; ?>">
        <label for="<?php echo $name; ?>" class="col-sm-4 control-label"><?php echo ($attributes[$name]['multiple'] ? ($key + 1) . '. ' : '') . ($messages[$name] ?? $name); ?></label>
        <div class="col-sm-8">
            <div class="input-group">
                <span class="input-group-addon"><i class="fa fa-fw fa-<?php echo $attributeMapping[$name]['icon']; ?>"></i></span>
<?php if (isset($attributeMapping[$name]['values'])) { ?>
<?php if (isset($attributeMapping[$name]['readonly']) && $attributeMapping[$name]['readonly']) { ?>
    <input type="text" value="<?php echo htmlentities($attributeMapping[$name]['values'][$value]); ?>" class="form-control" readonly="readonly" />
<?php } else { ?>
		<select class="form-control" name="data_<?php echo $name; ?>[]" id="<?php echo $name; ?>">
<?php foreach ($attributeMapping[$name]['values'] as $availableKey => $availableValue) { ?>
		    <option value="<?php echo $availableKey; ?>" <?php if (strtolower($availableKey) == strtolower($value) || strtolower($availableValue) == strtolower($value)) echo 'selected="selected"'; ?>><?php echo $availableValue; ?></option>
<?php } ?>
		</select>
<?php } ?>
<?php } elseif (isset($files[$name])) { ?>
                <input type="text" name="filename_<?php echo $name; ?>" id="filename_<?php echo $name; ?>" value="" class="form-control" placeholder="" readonly="readonly" />
	        <label class="btn btn-default input-group-addon">
                    <input type="file" name="data_<?php echo $name; ?>" id="data_<?php echo $name; ?>" style="display: none;" /><?php echo $messages['selectfile']; ?>
	        </label>
		<script type="text/javascript">
		     $(document).ready(function () {
		         $('#<?php echo 'data_' . $name; ?>').on('change', function(event) {
			     $('#<?php echo "filename_" . $name; ?>').val(this.files[0].name);
		         });
                     });
		</script>
<?php } else { ?>
<?php if (isset($attributeMapping[$name]['readonly']) && $attributeMapping[$name]['readonly']) { ?>
                <input type="text" value="<?php echo htmlentities($value) ?>" class="form-control" />
<?php } else { ?>
                <input type="text" name="data_<?php echo $name; ?>[]" id="<?php echo $name; ?>" value="<?php echo htmlentities($value) ?>" class="form-control" placeholder="<?php echo $messages[$name . 'placeholder']; ?>" />
<?php } ?>
<?php } ?>
<?php if ($attributes[$name]['multiple'] && (!isset($attributeMapping[$name]['readonly']) || !$attributeMapping[$name]['readonly'])) { ?>
                <span class="input-group-addon btn btn-default delete" style="cursor: pointer;" onclick="delete_parent_form_group(this);"><i style="color: red;" class="fa fa-fw fa-times"></i></span>
                <span class="input-group-addon btn btn-default add" style="cursor: pointer;" onclick="clone_parent_form_group(this);"><i class="fa fa-fw fa-plus"></i></span>
<?php } ?>
<?php if (($dependencyKey = reset(array_keys(array_filter($attributeMapping, function ($mapping) use ($name) { return $mapping['dependency'] == $name; })))) && !$data[0][$dependencyKey]['count']) { ?>
                <label class="btn btn-default input-group-addon" onclick="$('#container_<?php echo $dependencyKey; ?>').removeClass('hidden');$(this).hide();">
                    <?php echo $messages['additional']; ?>
                </label>
<?php } ?>
            </div>
        </div>
    </div>
<?php } ?>
<?php } ?>
</div>
</div>
<?php $tabs[$messages[$attributeMapping[$name]['tab']] ?? $attributeMapping[$name]['tab']] .= ob_get_clean(); ?>
<?php } ?>
<ul class="nav nav-tabs" id="tabs" role="tablist">
<?php foreach (array_keys($tabs) as $name) { ?>
  <li class="nav-item <?php echo (reset(array_keys($tabs)) == $name ? 'active' : ''); ?>">
    <a class="nav-link <?php echo (reset(array_keys($tabs)) == $name ? 'active' : ''); ?>" data-toggle="tab" href="#<?php echo md5($name); ?>" role="tab" aria-controls="<?php echo md5($name); ?>" aria-selected="<?php echo (reset(array_keys($tabs)) == $name ? 'true' : 'false'); ?>"><?php echo $name; ?></a>
  </li>
<?php } ?>
</ul>
<div class="tab-content" id="tabContent">
<?php foreach ($tabs as $name => $content) { ?>
  <div class="tab-pane fade <?php echo (reset(array_keys($tabs)) == $name ? 'in active' : ''); ?>" id="<?php echo md5($name); ?>" role="tabpanel" aria-labelledby="<?php echo md5($name); ?>-tab"><?php echo $tabs[$name]; ?></div>
<?php } ?>
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
