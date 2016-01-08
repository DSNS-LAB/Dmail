<?php
/**
 * Copyright 2004-2015 Horde LLC (http://www.horde.org/)
 *
 * See the enclosed file COPYING for license information (GPL). If you
 * did not receive this file, see http://www.horde.org/licenses/gpl.
 *
 * @category  Horde
 * @copyright 2004-2015 Horde LLC
 * @license   http://www.horde.org/licenses/gpl GPL
 * @package   IMP
 */

/**
 * Message thread display.
 * Usable in both basic and dynamic views.
 *
 * @author    Michael Slusarz <slusarz@horde.org>
 * @category  Horde
 * @copyright 2004-2015 Horde LLC
 * @license   http://www.horde.org/licenses/gpl GPL
 * @package   IMP
 */
class IMP_Basic_Thread extends IMP_Basic_Base
{
    /**
     */
    protected function _init()
    {
        global $injector, $notification, $page_output, $registry, $session;

        $imp_mailbox = $this->indices->mailbox->list_ob;

        switch ($mode = $this->vars->get('mode', 'thread')) {
        case 'thread':
            /* THREAD MODE: Make sure we have a valid index. */
            list($m, $u) = $this->indices->getSingle();
            $imp_indices = $imp_mailbox->getFullThread($u, $m);
            break;

        default:
            /* MSGVIEW MODE: Make sure we have a valid list of messages. */
            $imp_indices = $this->indices;
            break;
        }

        if (!count($imp_indices)) {
            $notification->push(_("Could not load message."), 'horde.error');
            $this->indices->mailbox->url('mailbox')->redirect();
        }

        /* Run through action handlers. */
        switch ($this->vars->actionID) {
        case 'add_address':
            try {
                $contact_link = $injector->getInstance('IMP_Contacts')->addAddress($this->vars->address, $this->vars->name);
                $notification->push(sprintf(_("Entry \"%s\" was successfully added to the address book"), $contact_link), 'horde.success', array('content.raw'));
            } catch (Horde_Exception $e) {
                $notification->push($e);
            }
            break;
        }

        $msgs = $tree = array();
        $subject = '';
        $page_label = $this->indices->mailbox->label;

        $imp_ui = $injector->getInstance('IMP_Message_Ui');

        $query = new Horde_Imap_Client_Fetch_Query();
        $query->envelope();

        /* Force images to show in HTML data. */
        $injector->getInstance('IMP_Images')->alwaysShow = true;

        $multiple = (count($imp_indices) > 1);

        foreach ($imp_indices as $ob) {
            $imp_imap = $ob->mbox->imp_imap;
            $fetch_res = $imp_imap->fetch($ob->mbox, $query, array(
                'ids' => $imp_imap->getIdsOb($ob->uids)
            ));

            foreach ($ob->uids as $idx) {
                $envelope = $fetch_res[$idx]->getEnvelope();

                /* Get the body of the message. */
                $curr_msg = $curr_tree = array();
                $contents = $injector->getInstance('IMP_Factory_Contents')->create($ob->mbox->getIndicesOb($idx));
                $mime_id = $contents->findBody();
                if ($contents->canDisplay($mime_id, IMP_Contents::RENDER_INLINE)) {
                    $ret = $contents->renderMIMEPart($mime_id, IMP_Contents::RENDER_INLINE);
                    $ret = reset($ret);
                    $curr_msg['body'] = $ret['data'];

                    if (!empty($ret['js'])) {
                        $page_output->addInlineScript($ret['js'], true);
                    }
                } else {
                    $curr_msg['body'] = '<em>' . _("There is no text that can be displayed inline.") . '</em>';
                }
                $curr_msg['idx'] = $idx;

                /* Get headers for the message. */
                $curr_msg['date'] = $imp_ui->getLocalTime($envelope->date);

                if ($this->indices->mailbox->special_outgoing) {
                    $curr_msg['addr_to'] = true;
                    $curr_msg['addr'] = _("To:") . ' ' . $imp_ui->buildAddressLinks($envelope->to, Horde::selfUrlParams());
                    $addr = _("To:") . ' ' . htmlspecialchars($envelope->to[0]->label, ENT_COMPAT, 'UTF-8');
                } else {
                    $from = $envelope->from;
                    $curr_msg['addr_to'] = false;
                    $curr_msg['addr'] = $imp_ui->buildAddressLinks($from, Horde::selfUrlParams());
                    $addr = htmlspecialchars($from[0]->label, ENT_COMPAT, 'UTF-8');
                }

                $subject_header = htmlspecialchars($envelope->subject, ENT_COMPAT, 'UTF-8');

                switch ($mode) {
                case 'thread':
                    if (empty($subject)) {
                        $subject = preg_replace('/^re:\s*/i', '', $subject_header);
                    }
                    $curr_msg['link'] = $multiple
                        ? Horde::widget(array('url' => '#display', 'title' => _("Thread List"), 'nocheck' => true))
                        : '';
                    $curr_tree['subject'] = $imp_mailbox->getThreadOb($imp_mailbox->getArrayIndex($fetch_res[$idx]->getUid(), $ob->mbox) + 1)->img;
                    break;

                default:
                    $curr_msg['link'] = Horde::widget(array('url' => '#display', 'title' => _("Back to Multiple Message View Index"), 'nocheck' => true));
                    $curr_tree['subject'] = '';
                    break;
                }

                switch ($registry->getView()) {
                case $registry::VIEW_BASIC:
                    $curr_msg['link'] .= ' | ' . Horde::widget(array('url' => $this->indices->mailbox->url('message', $idx), 'title' => _("Go to Message"), 'nocheck' => true)) .
                        ' | ' . Horde::widget(array('url' => $this->indices->mailbox->url('mailbox')->add(array('start' => $imp_mailbox->getArrayIndex($idx))), 'title' => sprintf(_("Bac_k to %s"), $page_label)));
                    break;
                }

                $curr_tree['subject'] .= Horde::link('#i' . $idx) . Horde_String::truncate($subject_header, 60) . '</a> (' . $addr . ')';

                $msgs[] = $curr_msg;
                $tree[] = $curr_tree;
            }
        }

        /* Flag messages as seen. */
        $injector->getInstance('IMP_Message')->flag(array(
            'add' => array(Horde_Imap_Client::FLAG_SEEN)
        ), $imp_indices);

        $view = new Horde_View(array(
            'templatePath' => IMP_TEMPLATES . '/thread'
        ));

        if ($mode == 'thread') {
            $view->subject = $subject;
            $view->thread = true;

            switch ($registry->getView()) {
            case $registry::VIEW_BASIC:
                $uid_list = $imp_indices[strval($this->indices->mailbox)];
                $delete_link = $this->indices->mailbox->url('mailbox')->add(array(
                    'actionID' => 'delete_messages',
                    'indices' => strval($imp_indices),
                    'token' => $session->getToken(),
                    'start' => $imp_mailbox->getArrayIndex(end($uid_list))
                ));
                $view->delete = Horde::link($delete_link, _("Delete Thread"), null, null, null, null, null, array('id' => 'threaddelete'));
                $page_output->addInlineScript(array(
                    '$("threaddelete").observe("click", function(e) { if (!window.confirm(' . json_encode(_("Are you sure you want to delete all messages in this thread?")) . ')) { e.stop(); } })'
                ), true);
                break;
            }
        } else {
            $view->subject = sprintf(_("%d Messages"), count($msgs));
        }
        $view->messages = $msgs;
        $view->tree = $tree;

        $page_output->addScriptFile('stripe.js', 'horde');
        $page_output->addScriptFile('toggle_quotes.js', 'horde');
        $page_output->noDnsPrefetch();

        $this->output = $view->render('thread');

        switch ($registry->getView()) {
        case $registry::VIEW_DYNAMIC:
            $page_output->topbar = $page_output->sidebar = false;
            $this->header_params = array(
                'html_id' => 'htmlAllowScroll'
            );
            break;
        }

        $this->title = ($mode == 'thread')
            ? _("Thread View")
            : _("Multiple Message View");
    }

    /**
     */
    public function status()
    {
        global $registry;

        return ($registry->getView() == $registry::VIEW_DYNAMIC)
            ? ''
            : parent::status();
    }

    /**
     */
    static public function url(array $opts = array())
    {
        return Horde::url('basic.php')
            ->add('page', 'thread')
            ->unique()
            ->setRaw(!empty($opts['full']));
    }

}
