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
$conf['nocommon'] = 1;

$conf['autotype'] = 'random';
$conf['autobits'] = 44;
