<?php

session_start();

$binary = $_SESSION['thumbnailphoto'][0];

if ($binary && ($image = imagecreatefromstring($binary))) {
    header('Content-type: image/jpeg');
    imagejpeg($image);
    imagedestroy($image);
}
