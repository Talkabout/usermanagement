    <div class="navbar-wrapper">
        <div class="navbar navbar-default navbar-static-top" role="navigation">
          <div class="container-fluid">
            <div class="navbar-header">
              <button type="button" class="navbar-toggle" data-toggle="collapse" data-target=".navbar-collapse">
                <span class="sr-only">Toggle navigation</span>
                <span class="icon-bar"></span>
                <span class="icon-bar"></span>
                <span class="icon-bar"></span>
              </button>
		<?php if ($_SESSION['authenticated']) { ?>
              <a class="navbar-brand <?php if ( $action === "datachange" ) { echo "active"; } ?>" href="?action=datachange"
                  ><i class="fa fa-fw fa-home"></i> <?php echo $messages["datachange"]; ?></a>
		<?php } ?>
            </div>
            <div class="navbar-collapse collapse">
              <ul class="nav navbar-nav">
		<?php if ($_SESSION['authenticated']) { ?>
		<li class="<?php if ( $action === "change" ) { echo "active"; } ?>">
                  <a href="?action=change"
                     data-toggle="menu-popover"
                     data-content="<?php echo htmlentities(strip_tags($messages["passwordchange"])); ?>"
                  ><i class="fa fa-fw fa-lock"></i> <?php echo $messages["passwordchange"]; ?></a>
                </li>
                <?php if ( $use_questions ) { ?>
                <li class="<?php if ( $action === "resetbyquestions" or $action === "setquestions" ) { echo "active"; } ?>">
                  <a href="?action=resetbyquestions"
                     data-toggle="menu-popover"
                     data-content="<?php echo htmlentities(strip_tags($messages["changehelpquestions"])); ?>"
                  ><i class="fa fa-fw fa-question-circle"></i> <?php echo $messages["menuquestions"]; ?></a>
                </li>
                <?php } ?>
                <?php if ( $use_sms ) { ?>
                <li class="<?php if ( ( $action === "resetbytoken" and $source === "sms" ) or $action === "sendsms" ) { echo "active"; } ?>">
                  <a href="?action=sendsms"
                     data-toggle="menu-popover"
                     data-content="<?php echo htmlentities(strip_tags($messages["changehelpsms"])); ?>"
                  ><i class="fa fa-fw fa-mobile"></i> <?php echo $messages["menusms"]; ?></a>
                </li>
                <?php } ?>
                <?php if ( $_SESSION['administrator']) { ?>
		<li class="<?php if ( $action === "create" ) { echo "active"; } ?>">
                  <a href="?action=create"
                     data-toggle="menu-popover"
                     data-content="<?php echo htmlentities(strip_tags($messages["create"])); ?>"
                  ><i class="fa fa-fw fa-user-plus"></i> <?php echo $messages["menucreate"]; ?></a>
                </li>
                <li class="<?php if ( $action === "delete" ) { echo "active"; } ?>">
                  <a href="?action=delete"
                     data-toggle="menu-popover"
                     data-content="<?php echo htmlentities(strip_tags($messages["delete"])); ?>"
                  ><i class="fa fa-fw fa-user-times"></i> <?php echo $messages["menudelete"]; ?></a>
                </li>
                <?php } ?>
		<?php if ( $_SESSION['authenticated'] ) { ?>
                
                <?php } ?>
                <?php } else { ?>
                <li class="<?php if ( $action === $default_action ) { echo "active"; } ?>">
                  <a href="?"
                     data-toggle="menu-popover"
                     data-content="<?php echo htmlentities(strip_tags($messages["login"])); ?>"
                  ><i class="fa fa-fw fa-sign-in"></i> <?php echo $messages["login"]; ?></a>
                </li>
		<?php if ( $use_tokens ) { ?>
                <li class="<?php if ( ( $action === "resetbytoken" and $source !== "sms" ) or $action === "sendtoken" ) { echo "active"; } ?>">
                  <a href="?action=sendtoken"
                     data-toggle="menu-popover"
                     data-content="<?php echo htmlentities(strip_tags($messages["changehelptoken"])); ?>"
                  ><i class="fa fa-fw fa-envelope"></i> <?php echo $messages["menutoken"]; ?></a>
                </li>
                <?php } ?>
                <?php } ?>
              </ul>
              <ul style="float: right;" class="nav navbar-nav">
<?php if ($_SESSION['authenticated']) { ?>
		<li>
                  <a href="?login=<?php echo $_SESSION['login']; ?>"
                     data-toggle="menu-popover"
                     data-content="<?php echo htmlentities(strip_tags($_SESSION['login'])); ?>"
                  ><i class="fa fa-fw fa-user"></i> <?php echo $_SESSION['login']; ?></a>
                </li>
		<li>
                  <a href="?action=logout"
                     data-toggle="menu-popover"
                     data-content="<?php echo htmlentities(strip_tags($messages["logout"])); ?>"
		     style="padding: 15px 5px;"
                  ><i class="fa fa-fw fa-sign-out"></i>&nbsp;</a>
                </li>
<?php } ?>
              </ul>
            </div>
          </div>
        </div>

    </div>
