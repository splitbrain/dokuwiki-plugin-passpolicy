<?php
/**
 * english language file for passpolicy plugin
 *
 * @author Andreas Gohr <andi@splitbrain.org>
 */

$lang['minlen']   = 'Mimimal length for user passwords';
$lang['pools']    = 'Character types to use in passwords';
$lang['minpools'] = 'Minimal number of different character types that have to be used in passwords. May not be higher than the number of selected types above';
$lang['user']     = 'Check if password matches against the user\'s name. 0 to disable. 1 for exact matches. Any other number for the number of consecutive characters that may be contained in both password and username';

$lang['autotype'] = 'How to generate passwords?';
$lang['autobits'] = 'Minimal number of bits of information to generate passwords. The higher, the more secure but harder to remember. Minimum: 24.';

$lang['autotype_o_random'] = 'random password';
$lang['autotype_o_pronouncable'] = 'pronouncable password';
$lang['autotype_o_phrase'] = 'multi word pass phrase';

$lang['pools_lower']   = 'lower case letters';
$lang['pools_upper']   = 'upper case letters';
$lang['pools_numeric'] = 'numbers';
$lang['pools_special'] = 'special chars (eg. !, $, #, %)';

$lang['oldpass']     = 'Number of old passwords, which will be checked. 0 to disable checking of old passwords.';
$lang['expire']      = 'Number in days of password interval. 0 to disable expiring passwords';
$lang['expirewarn']  = 'Number in days the user will be informed before the password expires.';
$lang['date_start']  = 'Set the beginning day when passwords will first expire after plugin installation, so that user are forced to change their password according to the passpolicy. This date is used to give the user a transition time to change their password after plugin installation. Setting the date to far future will disable expiring passwords. (Format YYYY-MM-DD)';

//Setup VIM: ex: et ts=4 :
