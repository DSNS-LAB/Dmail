<?php
/**
 * Copyright 2005-2015 Horde LLC (http://www.horde.org/)
 *
 * See the enclosed file COPYING for license information (GPL). If you
 * did not receive this file, see http://www.horde.org/licenses/gpl.
 *
 * @category  Horde
 * @copyright 2005-2015 Horde LLC
 * @license   http://www.horde.org/licenses/gpl GPL
 * @package   IMP
 */

/**
 * Compose code common to various dynamic views.
 *
 * @author    Michael Slusarz <slusarz@horde.org>
 * @category  Horde
 * @copyright 2005-2015 Horde LLC
 * @license   http://www.horde.org/licenses/gpl GPL
 * @package   IMP
 */
class IMP_Dynamic_Compose_Common
{
    /**
     * Create content needed to output the compose page.
     *
     * @param IMP_Dynamic_Base $base  Base dynamic view object.
     * @param array $args             Configuration parameters:
     *   - redirect: (boolean) Display the redirect interface? If true,
     *               display only redirect. If false, don't add redirect
     *               interface to page.
     *   - resume: (boolean) Are we resuming a saved draft?
     *   - show_editor: (boolean) Show the HTML editor?
     *   - template: (string) Display the edit template interface?
     *
     * @return string  The compose HTML text.
     */
    public function compose(IMP_Dynamic_Base $base, array $args = array())
    {
        global $injector, $page_output, $prefs;

        $page_output->addScriptPackage('Horde_Core_Script_Package_Keynavlist');
        $page_output->addScriptPackage('IMP_Script_Package_ComposeBase');
        $page_output->addScriptFile('compose-dimp.js');
        $page_output->addScriptFile('draghandler.js');
        $page_output->addScriptFile('editor.js');
        $page_output->addScriptFile('imp.js');

        if (!$prefs->isLocked('default_encrypt') &&
            ($prefs->getValue('use_pgp') || $prefs->getValue('use_smime'))) {
            $page_output->addScriptPackage('Horde_Core_Script_Package_Dialog');
            $page_output->addScriptFile('passphrase.js');
        }

        $this->_addComposeVars($base);

        $view = $base->getEmptyView();
        $view->addHelper('Tag');
        $view->addHelper('FormTag');

        $view->compose_enable = IMP_Compose::canCompose();

        /* Attach spellchecker & auto completer. */
        $imp_ui = $injector->getInstance('IMP_Compose_Ui');

        if (!empty($args['redirect'])) {
            $base->js_conf['redirect'] = 1;
            $imp_ui->attachAutoCompleter(array('redirect_to'));
            return $view->render('redirect');
        }

        $ac = array('to', 'cc', 'bcc');
        if (!isset($args['redirect'])) {
            $ac[] = 'redirect_to';
        }

        $imp_ui->attachAutoCompleter($ac);
        $view->spellcheck = $imp_ui->attachSpellChecker();

        $this->_compose($base, $view, $args);
        return $view->render('compose') . (isset($args['redirect']) ? '' : $view->render('redirect'));
    }

    /**
     */
    protected function _compose($base, $view, $args)
    {
        global $injector, $registry, $page_output, $prefs, $session;

        $view->title = $args['title'];

        /* Load Identity. */
        $identity = $injector->getInstance('IMP_Identity');
        $selected_identity = intval($identity->getDefault());

        /* Generate identities list. */
        $injector->getInstance('IMP_Compose_Ui')->addIdentityJs();

        if ($session->get('imp', 'rteavail')) {
            $view->compose_html = !empty($args['show_editor']);
            $view->rte = true;

            $page_output->addScriptPackage('IMP_Script_Package_Editor');
            $page_output->addScriptFile('external/base64.js');
        }

        /* Create list for sent-mail selection. */
        $imp_imap = $injector->getInstance('IMP_Factory_Imap')->create();
        if ($imp_imap->access(IMP_Imap::ACCESS_FOLDERS) &&
            !$prefs->isLocked('save_sent_mail')) {
            $view->save_sent_mail = true;
            $view->save_sent_mail_select = !$prefs->isLocked(IMP_Mailbox::MBOX_SENT);
        }

        $view->drafts = ($imp_imap->access(IMP_Imap::ACCESS_DRAFTS) &&
            ($draft = IMP_Mailbox::getPref(IMP_Mailbox::MBOX_DRAFTS)) &&
            !$draft->readonly);

        $view->compose_link = $registry->getServiceLink('ajax', 'imp')->url . 'addAttachment';
        $view->resume = !empty($args['resume']);
        $view->is_template = !empty($args['template']);
        $view->read_receipt_set = (strcasecmp($prefs->getValue('request_mdn'), 'always') === 0);
        $view->user = $registry->getAuth();

        if (IMP_Compose::canUploadAttachment()) {
            $view->attach = true;
            $view->max_size = $session->get('imp', 'file_upload');
            $view->save_attach_set = (strcasecmp($prefs->getValue('save_attachments'), 'always') === 0);
        } else {
            $view->attach = false;
        }

        if ($prefs->getValue('use_pgp') &&
            $prefs->getValue('pgp_public_key')) {
            $view->pgp_pubkey = $prefs->getValue('pgp_attach_pubkey');
        }

        if ($registry->hasMethod('contacts/ownVCard')) {
            $view->vcard_attach = true;
        }

        $view->priority = $prefs->getValue('set_priority');
        if (!$prefs->isLocked('default_encrypt') &&
            ($prefs->getValue('use_pgp') || $prefs->getValue('use_smime'))) {
            $view->encrypt = $prefs->getValue('default_encrypt');
        }

        $from_list = array();
        foreach ($identity->getSelectList() as $id => $from) {
            $from_list[] = array(
                'label' => $from,
                'sel' => ($id == $selected_identity),
                'val' => $id
            );
        }
        $view->from_list = $from_list;

        $view->signature = $identity->hasSignature(true);
        $view->sigExpanded = $prefs->getValue('signature_expanded');
    }

    /**
     * Add compose javascript variables to the page.
     */
    protected function _addComposeVars($base)
    {
        global $browser, $injector, $prefs, $registry;

        /* Context menu definitions. */
        $base->js_context['ctx_other'] = new stdClass;
        if (!$prefs->isLocked('request_mdn')) {
            $base->js_context['ctx_other']->rr = _("Read Receipt");
        }

        $base->js_context['ctx_atc'] = new stdClass;

        if (IMP_Compose::canUploadAttachment()) {
            if (!$prefs->isLocked('save_attachments') &&
                (!$prefs->isLocked('save_sent_mail') ||
                 $prefs->getValue('save_sent_mail'))) {
                $base->js_context['ctx_atc']->save = _("Save Attachments in Sent Mailbox");
            }

            $atcfile = new stdClass;
            $atcfile->delete = _("Delete");
            $base->js_context['ctx_atcfile'] = $atcfile;
        }

        if ($prefs->getValue('use_pgp') &&
            $prefs->getValue('pgp_public_key')) {
            $base->js_context['ctx_atc']->pgppubkey = _("Attach Personal PGP Public Key");
        }

        if ($registry->hasMethod('contacts/ownVCard')) {
            $base->js_context['ctx_atc']->vcard = _("Attach contact information");
        }

        /* Variables used in compose page. */
        $compose_cursor = $prefs->getValue('compose_cursor');
        $templates_mbox = IMP_Mailbox::getPref(IMP_Mailbox::MBOX_TEMPLATES);

        $base->js_conf += array_filter(array(
            'compose_cursor' => ($compose_cursor ? $compose_cursor : 'top'),
            'rte_avail' => intval($browser->hasFeature('rte')),
            'spellcheck' => intval($prefs->getValue('compose_spellcheck')),
            'templates_mbox' => $templates_mbox ? $templates_mbox->form_to : null
        ));

        if ($injector->getInstance('IMP_Factory_Imap')->create()->access(IMP_Imap::ACCESS_DRAFTS) &&
            ($drafts_mbox = IMP_Mailbox::getPref(IMP_Mailbox::MBOX_DRAFTS)) &&
            !$drafts_mbox->readonly) {
            $base->js_conf += array_filter(array(
                'auto_save_interval_val' => intval($prefs->getValue('auto_save_drafts')),
                'close_draft' => intval($prefs->getValue('close_draft')),
                'drafts_mbox' => $drafts_mbox->form_to
            ));
        }

        if ($registry->hasMethod('contacts/search')) {
            $base->js_conf['URI_ABOOK'] = strval(IMP_Basic_Contacts::url()->setRaw(true));
        }

        if ($prefs->getValue('set_priority')) {
            $base->js_conf['priority'] = array(
                array(
                    'l' => _("High"),
                    'v' => 'high'
                ),
                array(
                    'l' => _("Normal"),
                    's' => true,
                    'v' => 'normal'
                ),
                array(
                    'l' => _("Low"),
                    'v' => 'low'
                )
            );
        }

        if (!$prefs->isLocked('default_encrypt')) {
            $encrypt = array();
            foreach ($injector->getInstance('IMP_Compose_Ui')->encryptList(null, true) as $key => $val) {
                $encrypt[] = array(
                    'l' => htmlspecialchars($val),
                    'v' => $key
                );
            }

            if (!empty($encrypt)) {
                $base->js_conf['encrypt'] = $encrypt;
            }
        }

        /* Gettext strings used in compose page. */
        $base->js_text += array(
            'change_identity' => _("You have edited your signature. Change the identity and lose your changes?"),
            'compose_cancel' => _("Cancelling this message will permanently discard its contents and will delete auto-saved drafts.\nAre you sure you want to do this?"),
            'compose_close' => _("Compose action completed. You may now safely close this window."),
            'dragdropimg_error' => _("Could not add %d file(s) to message: only images are supported."),
            'multiple_atc' => _("%d Attachments"),
            'nosubject' => _("The message does not have a subject entered.") . "\n" . _("Send message without a subject?"),
            'paste_error' => _("Could not paste image as the clipboard data is invalid."),
            'replyall' => _("%d recipients"),
            'spell_noerror' => _("No spelling errors found."),
            'toggle_html' => _("Discard all text formatting information (by converting from HTML to plain text)? This conversion cannot be reversed."),
            'uploading' => _("Uploading..."),
        );
    }

}
