<?php

use dokuwiki\Extension\ActionPlugin;
use dokuwiki\Extension\EventHandler;
use dokuwiki\Extension\Event;
use dokuwiki\Form\Form;
use dokuwiki\Action\Exception\ActionException;
use dokuwiki\Action\Resendpwd;

/**
 * DokuWiki Plugin passpolicy (Action Component)
 *
 * @license GPL 2 http://www.gnu.org/licenses/gpl-2.0.html
 * @author  Andreas Gohr <andi@splitbrain.org>
 */
class action_plugin_passpolicy extends ActionPlugin
{
    /**
     * Registers a callback function for a given event
     *
     * @param EventHandler $controller DokuWiki's event controller object
     * @return void
     */
    public function register(EventHandler $controller)
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

        if ($this->getConf('supressuserhints')) {
            $controller->register_hook('ACTION_ACT_PREPROCESS', 'BEFORE', $this, 'handleResendPwd');
            $controller->register_hook('TPL_ACT_UNKNOWN', 'BEFORE', $this, 'handleResendPwdUI');
        }
    }

    /**
     * Handle Ajax for the Password strength check
     *
     * @param Event $event
     * @param $param
     */
    public function handleAjax(Event $event, $param)
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
     * @param Event $event event object
     * @param mixed $param
     */
    public function handleForms(Event $event, $param)
    {
        if (is_a($event->data, Form::class)) {
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
        if (is_a($event->data, Form::class)) {
            $event->data->addHTML($html, ++$pos);
        } else {
            $event->data->insertElement(++$pos, $html);
        }
    }

    /**
     * Check if a new password matches the set password policy
     *
     * @param Event $event event object
     * @param mixed $param
     */
    public function handlePasschange(Event $event, $param)
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
     * @param Event $event event object
     * @param mixed $param
     * @throws Exception
     */
    public function handlePassgen(Event $event, $param)
    {
        /** @var $passpolicy helper_plugin_passpolicy */
        $passpolicy = plugin_load('helper', 'passpolicy');

        $event->data['password'] = $passpolicy->generatePassword($event->data['foruser']);
        $event->preventDefault();
    }

    /**
     * Intercept the resendpwd action
     *
     * This supresses all hints on if a user exists or not
     *
     * @param Event $event
     * @param $param
     */
    public function handleResendPwd(Event $event, $param)
    {
        $act = act_clean($event->data);
        if ($act != 'resendpwd') return;

        $event->preventDefault();

        $action = new Resendpwd();
        try {
            $action->checkPreconditions();
        } catch (ActionException $ignored) {
            $event->data = 'show';
            return;
        }

        try {
            $action->preProcess();
        } catch (ActionException $ignored) {
        }

        $this->fixResendMessages();
    }

    /**
     * Reuse the standard action UI for ResendPwd
     *
     * @param Event $event
     * @param $param
     */
    public function handleResendPwdUI(Event $event, $param)
    {
        $act = act_clean($event->data);
        if ($act != 'resendpwd') return;
        $event->preventDefault();
        (new Resendpwd())->tplContent();
    }

    /**
     * Replaces the resendPwd messages with neutral ones
     *
     * @return void
     */
    protected function fixResendMessages()
    {
        global $MSG;
        global $lang;

        foreach ((array)$MSG as $key => $info) {
            if (
                $info['msg'] == $lang['resendpwdnouser'] || $info['msg'] == $lang['resendpwdconfirm']
            ) {
                unset($MSG[$key]);
                msg($this->getLang('resendpwd'), 1);
            }
        }
    }
}
