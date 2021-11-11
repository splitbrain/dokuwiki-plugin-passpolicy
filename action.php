<?php

/**
 * DokuWiki Plugin passpolicy (Action Component)
 *
 * @license GPL 2 http://www.gnu.org/licenses/gpl-2.0.html
 * @author  Andreas Gohr <andi@splitbrain.org>
 */
class action_plugin_passpolicy extends DokuWiki_Action_Plugin
{

    /**
     * Registers a callback function for a given event
     *
     * @param Doku_Event_Handler $controller DokuWiki's event controller object
     * @return void
     */
    public function register(Doku_Event_Handler $controller)
    {
        $controller->register_hook('FORM_REGISTER_OUTPUT', 'BEFORE', $this, 'handleForms');
        $controller->register_hook('FORM_UPDATEPROFILE_OUTPUT', 'BEFORE', $this, 'handleForms');
        $controller->register_hook('FORM_RESENDPWD_OUTPUT', 'BEFORE', $this, 'handleForms');

        $controller->register_hook('HTML_REGISTERFORM_OUTPUT', 'BEFORE', $this, 'handleForms');
        $controller->register_hook('HTML_UPDATEPROFILEFORM_OUTPUT', 'BEFORE', $this, 'handleForms');
        $controller->register_hook('HTML_RESENDPWDFORM_OUTPUT', 'BEFORE', $this, 'handleForms');

        $controller->register_hook('AUTH_USER_CHANGE', 'BEFORE', $this, 'handlePasschange');

        $controller->register_hook('AUTH_PASSWORD_GENERATE', 'BEFORE', $this, 'handlePassgen');

        $controller->register_hook('AJAX_CALL_UNKNOWN', 'BEFORE', $this, 'handleAjax');
    }

    /**
     * Handle Ajax for the Password strength check
     *
     * @param Doku_Event $event
     * @param $param
     */
    public function handleAjax(Doku_Event $event, $param)
    {
        if ($event->data !== 'plugin_passpolicy') {
            return;
        }
        //no other ajax call handlers needed
        $event->stopPropagation();
        $event->preventDefault();

        /* @var $INPUT \Input */
        global $INPUT;
        $pass = $INPUT->post->str('pass');
        $user = $INPUT->post->str('user', $_SERVER['REMOTE_USER']);

        /** @var helper_plugin_passpolicy $passpolicy */
        $passpolicy = $this->loadHelper('passpolicy');
        if (!$passpolicy->checkPolicy($pass, $user)) {
            // passpolicy not matched, throw error
            echo '0';
        } else {
            echo '1';
        }
    }

    /**
     * Print the password policy in forms that allow setting passwords
     *
     * @param Doku_Event $event event object
     * @param mixed $param
     */
    public function handleForms(Doku_Event $event, $param)
    {
        if (substr($event->name, 0, 4) === 'FORM') {
            // applicable to development snapshot 2020-10-13 or later
            $pos = $event->data->findPositionByAttribute('name', 'passchk');
        } else {
            // applicable to 2020-07-29 "Hogfather" and older
            $pos = $event->data->findElementByAttribute('name', 'passchk');
        }
        if (!$pos) return; // no password repeat field found

        /** @var $passpolicy helper_plugin_passpolicy */
        $passpolicy = plugin_load('helper', 'passpolicy');
        $html = '<p class="passpolicy_hint">' . $passpolicy->explainPolicy() . '</p>';
        if (substr($event->name, 0, 4) === 'FORM') {
            $event->data->addHTML($html, ++$pos);
        } else {
            $event->data->insertElement(++$pos, $html);
        }
    }

    /**
     * Check if a new password matches the set password policy
     *
     * @param Doku_Event $event event object
     * @param mixed $param
     */
    public function handlePasschange(Doku_Event $event, $param)
    {
        if ($event->data['type'] == 'create') {
            $user = $event->data['params'][0];
            $pass = $event->data['params'][1];
        } elseif ($event->data['type'] == 'modify') {
            $user = $event->data['params'][0];
            if (!isset($event->data['params'][1]['pass'])) {
                return; //password is not changed, nothing to do
            }
            $pass = $event->data['params'][1]['pass'];
        } else {
            return;
        }

        /** @var $passpolicy helper_plugin_passpolicy */
        $passpolicy = plugin_load('helper', 'passpolicy');
        if (!$passpolicy->checkPolicy($pass, $user)) {
            // passpolicy not matched, throw error and stop modification
            msg($this->getLang('badpasspolicy'), -1);
            $event->preventDefault();
            $event->stopPropagation();
        }
    }

    /**
     * Replace default password generator by policy aware one
     *
     * @param Doku_Event $event event object
     * @param mixed $param
     * @throws Exception
     */
    public function handlePassgen(Doku_Event $event, $param)
    {
        /** @var $passpolicy helper_plugin_passpolicy */
        $passpolicy = plugin_load('helper', 'passpolicy');

        $event->data['password'] = $passpolicy->generatePassword($event->data['foruser']);
        $event->preventDefault();
    }
}
