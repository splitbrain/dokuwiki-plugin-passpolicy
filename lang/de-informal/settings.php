<?php

/**
 * @license    GPL 2 (http://www.gnu.org/licenses/gpl.html)
 *
 * @author Hella <hella.breitkopf@gmail.com>
 * @author Felix Müller-Donath <j.felix@mueller-donath.de>
 */
$lang['minlen']                = 'Mindestlänge für Benutzerpasswörter';
$lang['pools']                 = 'Für Passwörter geeignete Schriftzeichen';
$lang['minpools']              = 'Minimale Anzahl der unterschiedlichen Schriftzeichen, die in einem Passwort verwendet werden muss. Darf nicht größer als die Anzahl der oben ausgewählten Zeichen sein.';
$lang['user']                  = 'Überprüfen, ob das Passwort mit dem Benutzernamen übereinstimmt. 0 schaltet die Prüfung ab, 1 entspricht der exakten Übereinstimmung. Jede andere Zahl entspricht der Anzahl der zusammenhängenden Zeichen, die sowohl im Benutzernamen als auch im Passwort vorkommen dürfen.';
$lang['nocommon']              = 'Vergleiche Passwort mit einer Liste der 10.000 beliebtesten Passwörter.';
$lang['noleaked']              = 'Vergleiche Passwort mit der haveibeenpwned.com passwords API (unter Verwendung von k-anonymity), um Passwörter zu vermeiden, die schon einmal geleakt wurden.';
$lang['autotype']              = 'Wie sollen Passwörter generiert werden?';
$lang['autobits']              = 'Minimale Anzahl an Informationsbits zur Generierung eines Passwortes. Je höher die Zahl ist, desto sicherer ist das Passwort aber auch um so schwerer zu merken. Minimum: 24';
$lang['supressuserhints']      = 'Der Mechanismus zum Zurücksetzen des Passworts zeigt normalerweise, ob das angegebene Benutzerkonto existiert oder nicht. Dies unterdrückt alle Hinweise darauf.';
$lang['autotype_o_random']     = 'Zufallspasswort';
$lang['autotype_o_pronouncable'] = 'Aussprechbares Passwort';
$lang['autotype_o_phrase']     = 'Passwortsatz aus mehreren Wörtern';
$lang['pools_lower']           = 'Kleinbuchstaben';
$lang['pools_upper']           = 'Großbuchstaben';
$lang['pools_numeric']         = 'Zahlen';
$lang['pools_special']         = 'Sonderzeichen (z.B. !, $, #, %)';
