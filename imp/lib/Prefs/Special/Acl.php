<?php
/**
 * Copyright 2012-2015 Horde LLC (http://www.horde.org/)
 *
 * See the enclosed file COPYING for license information (GPL). If you
 * did not receive this file, see http://www.horde.org/licenses/gpl.
 *
 * @category  Horde
 * @copyright 2012-2015 Horde LLC
 * @license   http://www.horde.org/licenses/gpl GPL
 * @package   IMP
 */

/**
 * Special prefs handling for the 'aclmanagement' preference.
 *
 * @author    Michael Slusarz <slusarz@horde.org>
 * @category  Horde
 * @copyright 2012-2015 Horde LLC
 * @license   http://www.horde.org/licenses/gpl GPL
 * @package   IMP
 */
class IMP_Prefs_Special_Acl implements Horde_Core_Prefs_Ui_Special
{
    /**
     */
    public function init(Horde_Core_Prefs_Ui $ui)
    {
    }

    /**
     */
    public function display(Horde_Core_Prefs_Ui $ui)
    {
        global $injector, $notification, $page_output;

        $page_output->addScriptFile('acl.js');

        $acl = $injector->getInstance('IMP_Imap_Acl');

        $mbox = isset($ui->vars->mbox)
            ? IMP_Mailbox::formFrom($ui->vars->mbox)
            : IMP_Mailbox::get('INBOX');

        try {
            $curr_acl = $acl->getACL($mbox);
            if (!($canEdit = $acl->canEdit($mbox))) {
                $notification->push(_("You do not have permission to change access to this mailbox."), 'horde.warning');
            }
        } catch (IMP_Exception $e) {
            $notification->push($e);
            $canEdit = false;
            $curr_acl = array();
        }

        $rightslist = $acl->getRights();

        $iterator = new IMP_Ftree_IteratorFilter(
            $injector->getInstance('IMP_Ftree')
        );
        $iterator->add($iterator::NONIMAP);

        $view = new Horde_View(array(
            'templatePath' => IMP_TEMPLATES . '/prefs'
        ));
        $view->addHelper('FormTag');
        $view->addHelper('Tag');
        $view->addHelper('Text');

        $view->canedit = $canEdit;
        $view->current = sprintf(_("Current access to %s"), $mbox->display_html);
        $view->hasacl = count($curr_acl);
        $view->mbox = $mbox->form_to;
        $view->options = new IMP_Ftree_Select(array(
            'basename' => true,
            'iterator' => $iterator,
            'selected' => $mbox
        ));

        if ($view->hasacl) {
            $cval = array();

            foreach ($curr_acl as $index => $rule) {
                $entry = array(
                    'index' => $index,
                    'rule' => array()
                );

                if ($rule instanceof Horde_Imap_Client_Data_AclNegative) {
                    $entry['negative'] = substr($index, 1);
                }

                /* Create table of each ACL option for each user granted
                 * permissions; enabled indicates the right has been given to
                 * the user. */
                $rightsmbox = $acl->getRightsMbox($mbox, $index);
                foreach (array_keys($rightslist) as $val) {
                    $entry['rule'][] = array(
                        'disable' => !$canEdit || !$rightsmbox[$val],
                        'on' => $rule[$val],
                        'val' => $val
                    );
                }
                $cval[] = $entry;
            }

            $view->curr_acl = $cval;
        }

        $current_users = array_keys($curr_acl);
        $new_user = array();

        try {
            $auth_imap = $injector->getInstance('IMP_AuthImap');
            foreach ((array('anyone') + $auth_imap->listUsers()) as $user) {
                if (!in_array($user, $current_users)) {
                    $new_user[] = htmlspecialchars($user);
                }
            }

            $view->new_user = $new_user;
        } catch (IMP_Exception $e) {
            /* Ignore - admin user is not available. */
        } catch (Horde_Exception $e) {
            $notification->push('Could not authenticate as admin user to obtain ACLs. Perhaps your admin configuration is incorrect in config/backends.local.php?', 'horde.warning');
        }

        $rights = array();
        foreach ($rightslist as $key => $val) {
            $val['val'] = $key;
            $rights[] = $val;
        }
        $view->rights = $rights;

        $view->width = round(100 / (count($rights) + 2)) . '%';

        return $view->render('acl');
    }

    /**
     */
    public function update(Horde_Core_Prefs_Ui $ui)
    {
        global $injector, $notification;

        if ($ui->vars->change_acl_mbox) {
            return false;
        }

        $acl = $injector->getInstance('IMP_Imap_Acl');
        $mbox = IMP_Mailbox::formFrom($ui->vars->mbox);

        try {
            $curr_acl = $acl->getACL($mbox);
        } catch (IMP_Exception $e) {
            $notification->push($e);
            return;
        }

        if (!($acl_list = $ui->vars->acl)) {
            $acl_list = array();
        }
        $new_user = $ui->vars->new_user;

        if (strlen($new_user) && $ui->vars->new_acl) {
            if (isset($acl_list[$new_user])) {
                $acl_list[$new_user] = $ui->vars->new_acl;
            } else {
                try {
                    $acl->addRights($mbox, $new_user, implode('', $ui->vars->new_acl));
                    $notification->push(sprintf(_("ACL for \"%s\" successfully created for the mailbox \"%s\"."), $new_user, $mbox->label), 'horde.success');
                } catch (IMP_Exception $e) {
                    $notification->push($e);
                }
            }
        }

        foreach ($curr_acl as $index => $rule) {
            if (isset($acl_list[$index])) {
                /* Check to see if ACL changed, but only compare rights we
                 * understand. */
                $acldiff = $rule->diff(implode('', $acl_list[$index]));
                $update = false;

                try {
                    if ($acldiff['added']) {
                        $acl->addRights($mbox, $index, $acldiff['added']);
                        $update = true;
                    }
                    if ($acldiff['removed']) {
                        $acl->removeRights($mbox, $index, $acldiff['removed']);
                        $update = true;
                    }

                    if ($update) {
                        $notification->push(sprintf(_("ACL rights for \"%s\" updated for the mailbox \"%s\"."), $index, $mbox->label), 'horde.success');
                    }
                } catch (IMP_Exception $e) {
                    $notification->push($e);
                }
            } else {
                /* If we dont see ANY form params, the user deleted all
                 * rights. */
                try {
                    $acl->removeRights($mbox, $index, null);
                    $notification->push(sprintf(_("All rights on mailbox \"%s\" successfully removed for \"%s\"."), $mbox->label, $index), 'horde.success');
                } catch (IMP_Exception $e) {
                    $notification->push($e);
                }
            }
        }

        return false;
    }

}
