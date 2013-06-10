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

        $controller->register_hook('AUTH_PASSWORD_GENERATE', 'BEFORE', $this, 'handle_passgen');
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
        } elseif($event->data['type'] == 'create') {
            $user = $event->data['params'][0];
            if(!isset($event->data['params'][1]['password'])) {
                return; //password is not changed, nothing to do
            }
            $pass = $event->data['params'][1]['password'];
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
