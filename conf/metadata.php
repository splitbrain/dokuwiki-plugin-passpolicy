<?php

/**
 * Options for the passpolicy plugin
 *
 * @author Andreas Gohr <andi@splitbrain.org>
 */

$meta['minlen'] = array('numeric', '_min' => 0);
$meta['pools'] = array('multicheckbox', '_choices' => array('lower', 'upper', 'numeric', 'special'));
$meta['minpools'] = array('numeric', '_min' => 0, '_max' => 4);
$meta['user'] = array('numeric', '_min' => 0);
$meta['nocommon'] = array('onoff');
$meta['noleaked'] = array('onoff');

$meta['autotype'] = array('multichoice', '_choices' => array('random', 'phrase', 'pronouncable'));
$meta['autobits'] = array('numeric', '_min' => 24);

$meta['supressuserhints'] = array('onoff');
