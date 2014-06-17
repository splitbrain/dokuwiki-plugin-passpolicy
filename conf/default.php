<?php
/**
 * Default settings for the passpolicy plugin
 *
 * @author Andreas Gohr <andi@splitbrain.org>
 */

$conf['minlen']   = 8;
$conf['pools']    = 'lower,numeric,special';
$conf['minpools'] = 2;
$conf['user']     = 1;

$conf['autotype'] = 'random';
$conf['autobits'] = 44;


$conf['oldpass']     = 5;
$conf['expire']      = 30;
$conf['expirewarn']  = 2;
$conf['date_start']  = '2014-06-18';
