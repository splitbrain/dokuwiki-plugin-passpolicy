<?php
/**
 * english language file for passpolicy plugin
 *
 * @author Andreas Gohr <andi@splitbrain.org>
 */

$lang['minlen'] = 'Mimimal length for user passwords';
$lang['pools'] = 'Character types to use in passwords';
$lang['minpools'] = 'Minimal number of different character types that have to be used in passwords. May not be higher than the number of selected types above';
$lang['user'] = 'Check if password matches against the user\'s name. 0 to disable. 1 for exact matches. Any other number for the number of consecutive characters that may be contained in both password and username';
$lang['nocommon'] = 'Check password against a list of the 10,000 most common passwords.';
$lang['noleaked'] = 'Check password against the haveibeenpwned.com passwords API (using k-anonymity) to avoid passwords that have been leaked before.';

$lang['autotype'] = 'How to generate passwords?';
$lang['autobits'] = 'Minimal number of bits of information to generate passwords. The higher, the more secure but harder to remember. Minimum: 24.';

$lang['supressuserhints'] = 'The reset password mechanism usually tells if the given user account exists or not. This supresses all hints on that.';

$lang['autotype_o_random'] = 'random password';
$lang['autotype_o_pronouncable'] = 'pronouncable password';
$lang['autotype_o_phrase'] = 'multi word pass phrase';

$lang['pools_lower'] = 'lower case letters';
$lang['pools_upper'] = 'upper case letters';
$lang['pools_numeric'] = 'numbers';
$lang['pools_special'] = 'special chars (eg. !, $, #, %)';
