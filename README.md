# LDAP Usermanagement

## Presentation

Usermangement is a PHP application based on "Self Service Password" that allows users to manage their data in an LDAP directory.

The application can be used on standard LDAPv3 directories (OpenLDAP, OpenDS, ApacheDS, Sun Oracle DSEE, Novell, etc.) and also on Active Directory. Currently I am only able to test it on a Samba Active Directory environmnet. Thanks to everybody who can check if it works with other LDAP services also!

## Screenshots

![1 - login](https://user-images.githubusercontent.com/10157917/81551946-f0034880-9382-11ea-9865-00d217ea7bab.jpg)
![2 - reset](https://user-images.githubusercontent.com/10157917/81551952-f2fe3900-9382-11ea-8788-ec3259c513e4.jpg)
![3 - user management - general](https://user-images.githubusercontent.com/10157917/81551959-f5f92980-9382-11ea-95a4-c7d72d86c910.jpg)
![4 - user management - general - user selection](https://user-images.githubusercontent.com/10157917/81551966-f8f41a00-9382-11ea-9500-a2f101cd5593.jpg)
![5 - user management - groups](https://user-images.githubusercontent.com/10157917/81551979-fb567400-9382-11ea-8be9-f55c7898f996.jpg)
![6 - user management - object classes](https://user-images.githubusercontent.com/10157917/81551985-fdb8ce00-9382-11ea-8c77-4dfa6d2653d9.jpg)
![7 - user management - address](https://user-images.githubusercontent.com/10157917/81551991-00b3be80-9383-11ea-88fc-eda01a998e97.jpg)
![8 - user management - contact](https://user-images.githubusercontent.com/10157917/81551999-03aeaf00-9383-11ea-8641-0af2eaf80d54.jpg)
![9 - password management](https://user-images.githubusercontent.com/10157917/81552011-06110900-9383-11ea-92f0-8b9c711350a1.jpg)
![10 - add user](https://user-images.githubusercontent.com/10157917/81552018-090bf980-9383-11ea-8516-bea4a1796680.jpg)
![11 - delete user](https://user-images.githubusercontent.com/10157917/81552028-0d381700-9383-11ea-806f-de85ef9de5e5.jpg)

## Features

It has the following features:
* Samba mode to change Samba passwords
* Active directory mode
* Local password policy:
  * Minimum/maximum length
  * Forbidden characters
  * Upper, Lower, Digit or Special characters counters
  * Reuse old password check
  * Password same as login
  * Complexity (different class of characters)
* Help messages
* Reset by questions
* Reset by mail challenge (token sent by mail)
* Reset by SMS (trough external Email 2 SMS service or SMS API)
* Change SSH Key in LDAP directory
* reCAPTCHA (Google API)
* Mail notification after password change
* Hook script after password change
* editing of general user settings in ldap
* upload profile images to ldap (full size image stored in 'photo' attribute, scaled down images (500x500) stored in 'thumbnailPhoto' and 'jpegPhoto')
* administration mode (based on configurable user group) to
  * change other users settings
  * assign groups/object classes
  * create users
  * delete users

## Prerequisite

* PHP extensions required:
  * php-openssl (token crypt, probably built-in)
  * php-mbstring (reset mail)
  * php-curl (haveibeenpwned api)
  * php-ldap
  * php-filter
  * php-intl
* strong cryptography functions available (for random_compat, php 7 or libsodium or /dev/urandom readable or php-mcrypt extension installed)
* valid PHP mail server configuration (reset mail)
* valid PHP session
