<?php
/**
 * English language file for passpolicy plugin
 *
 * @author Andreas Gohr <andi@splitbrain.org>
 */

$lang['badpasspolicy']         = 'You must use a stronger password.';
$lang['length']     = 'Your password needs to be at least %d characters long.';
$lang['pools']      = 'Your password needs to use characters from at least %d of the following types: %s.';
$lang['user1']      = 'Your password may not contain your username.';
$lang['user2']      = 'Your password may only use %d or less consecutive characters that appear in your username.';
$lang['oldpass']    = 'Your password may not be equal to the last %d password(s).';

$lang['js']['strength0']  = 'very weak';
$lang['js']['strength1']  = 'weak';
$lang['js']['strength2']  = 'decent';
$lang['js']['strength3']  = 'strong';

$lang['expirewarn'] = 'Your password is going to be expired at %s. You can change your password here: %s. Or <a href="#" id="passpolicy_msg_hide">hide</a> it for today';
$lang['expired']    = 'Your password is expired since %s, you have to change your password! If you forgot your password, logout/login and use the reset password link.';

//Setup VIM: ex: et ts=4 :
