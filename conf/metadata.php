<?php
/**
 * Options for the passpolicy plugin
 *
 * @author Andreas Gohr <andi@splitbrain.org>
 */

$meta['minlen']   = array('numeric', '_min' => 0);
$meta['pools']    = array('multicheckbox', '_choices' => array('lower','upper','numeric','special'));
$meta['minpools'] = array('numeric', '_min' => 0, '_max' => 4);
$meta['user']     = array('numeric', '_min' => 0);

$meta['autotype'] = array('multichoice', '_choices' => array('random', 'phrase', 'pronouncable'));
$meta['autobits'] = array('numeric', '_min' => 24);

$meta['oldpass']     = array('numeric', '_min' => 0);
$meta['expire']      = array('numeric', '_min' => 0); //days
$meta['expirewarn']  = array('numeric', '_min' => 0); //days before expire
$meta['date_start']  = array('string', '_pattern' => '/20\d{2}-\d{2}-\d{2}/');


