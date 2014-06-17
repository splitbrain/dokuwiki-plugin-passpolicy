<?php
/**
 * DokuWiki Plugin passpolicy (Action Component)
 *
 * @license GPL 2 http://www.gnu.org/licenses/gpl-2.0.html
 * @author  Andreas Gohr <andi@splitbrain.org>
 */

// must be run within Dokuwiki
if(!defined('DOKU_INC')) die();

class action_plugin_passpolicy extends DokuWiki_Action_Plugin {

    /**
     * Registers a callback function for a given event
     *
     * @param Doku_Event_Handler $controller DokuWiki's event controller object
     * @return void
     */
    public function register(Doku_Event_Handler &$controller) {

        $controller->register_hook('HTML_REGISTERFORM_OUTPUT', 'BEFORE', $this, 'handle_forms');
        $controller->register_hook('HTML_UPDATEPROFILEFORM_OUTPUT', 'BEFORE', $this, 'handle_forms');
        $controller->register_hook('HTML_RESENDPWDFORM_OUTPUT', 'BEFORE', $this, 'handle_forms');

        $controller->register_hook('AUTH_USER_CHANGE', 'BEFORE', $this, 'handle_passchange');
        $controller->register_hook('AUTH_USER_CHANGE', 'BEFORE', $this, 'save_pass');

        $controller->register_hook('AUTH_PASSWORD_GENERATE', 'BEFORE', $this, 'handle_passgen');
                
        $controller->register_hook('AJAX_CALL_UNKNOWN', 'BEFORE',  $this, '_ajax_call');
        
        $controller->register_hook('ACTION_ACT_PREPROCESS', 'BEFORE',  $this, 'check_act');
        
        
    }
    
    /**
     * Handles the warn message and redirects user to the profile page in case of password expired
     * 
     * @param Doku_Event $event
     * @param unknown $param
     */
    function check_act(Doku_Event &$event,$param) {
    	if(!$_SERVER['REMOTE_USER']) return;
    
    	if(in_array($event->data,array('login','logout','profile')))  return;
    	
    	/* @var $passpolicy helper_plugin_passpolicy */
    	$passpolicy = $this->loadHelper('passpolicy');
    	 
    	if($expireDate = $passpolicy->checkPasswordExpired()) { //password is expired
    		msg(sprintf($this->getLang('expired'), date('Y-m-d',$expireDate)));
    		$event->data = 'profile';
    	} else if($expireDate = $passpolicy->checkPasswordExpireWarn()) { //show warn message
    		if(!isset($_COOKIE['passpolicy_msg_hide'])) {
    			msg(sprintf($this->getLang('expirewarn'), date('Y-m-d',$expireDate),tpl_action('profile',1,false,true)));
    		}
    		
    	}
   
    }
    
    /**
     * Save the password to the pass history
     * 
     * @param Doku_Event $event
     * @param unknown $param
     */
    function save_pass(Doku_Event &$event,$param) {
    	if($event->data['type'] == 'create') {
            $user = $event->data['params'][0];
            $pass = $event->data['params'][1];
        } elseif($event->data['type'] == 'modify') {
            $user = $event->data['params'][0];
            if(!isset($event->data['params'][1]['pass'])) {
                return; //password is not changed, nothing to do
            }
            $pass = $event->data['params'][1]['pass'];
        } else {
            return;
        }

        /* @var $passpolicy helper_plugin_passpolicy */
        $passpolicy = $this->loadHelper('passpolicy');
       
        $passpolicy->savePassword2PassHistory($user,$pass);
    }

    /**
     * Check for password policy
     * 
     * @param Doku_Event $event
     * @param unknown $param
     */
    function _ajax_call(Doku_Event &$event,$param) {
    	if ($event->data !== 'plugin_passpolicy') {
    		return;
    	}
    	//no other ajax call handlers needed
    	$event->stopPropagation();
    	$event->preventDefault();
    
    	if(!$_SERVER['REMOTE_USER']) return;
    	
    	/* @var $INPUT \Input */
    	global $INPUT;
    	$user = $INPUT->post->str('user',$_SERVER['REMOTE_USER']);
    	$pass = $INPUT->post->str('pass');
    	
    	
    	
    	$passpolicy = $this->loadHelper('passpolicy');
    	if(!$passpolicy->checkPolicy($pass, $user)) {
    		// passpolicy not matched, throw error
    		echo '0';
    	} else {
    		echo '1';
    	}
    	
    }

    /**
     * Print the password policy in forms that allow setting passwords
     *
     * @param Doku_Event $event  event object by reference
     * @param mixed      $param  [the parameters passed as fifth argument to register_hook() when this
     *                           handler was registered]
     * @return void
     */
    public function handle_forms(Doku_Event &$event, $param) {
        $pos = $event->data->findElementByAttribute('name', 'passchk');
        if(!$pos) return; // no password repeat field found

        /** @var $passpolicy helper_plugin_passpolicy */
        $passpolicy = plugin_load('helper', 'passpolicy');
        $html       = '<p class="passpolicy_hint">'.$passpolicy->explainPolicy().'</p>';
        $event->data->insertElement(++$pos, $html);
        
    }

    /**
     * Check if a new password matches the set password policy
     *
     * @param Doku_Event $event  event object by reference
     * @param mixed      $param  [the parameters passed as fifth argument to register_hook() when this
     *                           handler was registered]
     * @return void
     */
    public function handle_passchange(Doku_Event &$event, $param) {
        if($event->data['type'] == 'create') {
            $user = $event->data['params'][0];
            $pass = $event->data['params'][1];
        } elseif($event->data['type'] == 'modify') {
            $user = $event->data['params'][0];
            if(!isset($event->data['params'][1]['pass'])) {
                return; //password is not changed, nothing to do
            }
            $pass = $event->data['params'][1]['pass'];
        } else {
            return;
        }

        /** @var $passpolicy helper_plugin_passpolicy */
        $passpolicy = plugin_load('helper', 'passpolicy');
        if(!$passpolicy->checkPolicy($pass, $user)) {
            // passpolicy not matched, throw error and stop modification
            msg($this->getLang('badpasspolicy'), -1);
            $event->preventDefault();
            $event->stopPropagation();
        }
    }

    /**
     * Replace default password generator by policy aware one
     *
     * @param Doku_Event $event  event object by reference
     * @param mixed      $param  [the parameters passed as fifth argument to register_hook() when this
     *                           handler was registered]
     * @return void
     */
    public function handle_passgen(Doku_Event &$event, $param) {
        /** @var $passpolicy helper_plugin_passpolicy */
        $passpolicy = plugin_load('helper', 'passpolicy');

        $event->data['password'] = $passpolicy->generatePassword($event->data['foruser']);
        $event->preventDefault();
    }
}
// vim:ts=4:sw=4:et:
