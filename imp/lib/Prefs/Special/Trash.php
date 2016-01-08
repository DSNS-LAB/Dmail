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
 * Special prefs handling for the 'trashselect' preference.
 *
 * @author    Michael Slusarz <slusarz@horde.org>
 * @category  Horde
 * @copyright 2012-2015 Horde LLC
 * @license   http://www.horde.org/licenses/gpl GPL
 * @package   IMP
 */
class IMP_Prefs_Special_Trash extends IMP_Prefs_Special_SpecialMboxes implements Horde_Core_Prefs_Ui_Special
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
        global $injector, $page_output, $prefs;

        $page_output->addScriptFile('folderprefs.js');
        $page_output->addInlineJsVars(array(
            'ImpFolderPrefs.mboxes.trash' => _("Enter the name for your new trash mailbox.")
        ));

        $imp_search = $injector->getInstance('IMP_Search');
        $trash = IMP_Mailbox::getPref(IMP_Mailbox::MBOX_TRASH);

        $view = new Horde_View(array(
            'templatePath' => IMP_TEMPLATES . '/prefs'
        ));
        $view->addHelper('FormTag');
        $view->addHelper('Horde_Core_View_Helper_Label');
        $view->addHelper('Tag');

        $iterator = new IMP_Ftree_IteratorFilter(
            $injector->getInstance('IMP_Ftree')
        );
        $iterator->add(array(
            $iterator::NONIMAP,
            $iterator::REMOTE
        ));
        $iterator->mboxes = array('INBOX');

        $view->flist = new IMP_Ftree_Select(array(
            'basename' => true,
            'iterator' => $iterator,
            'new_mbox' => true,
            'selected' => $trash
        ));
        $view->nombox = IMP_Mailbox::formTo(self::PREF_NO_MBOX);
        $view->special_use = $this->_getSpecialUse(Horde_Imap_Client::SPECIALUSE_TRASH);

        if (!$prefs->isLocked('vfolder') || $imp_search['vtrash']->enabled) {
            $view->vtrash = IMP_Mailbox::formTo($imp_search->createSearchId('vtrash'));
            $view->vtrash_select = $trash->vtrash;
        }

        return $view->render('trash');
    }

    /**
     */
    public function update(Horde_Core_Prefs_Ui $ui)
    {
        global $injector, $prefs;

        $imp_search = $injector->getInstance('IMP_Search');
        $curr_vtrash = IMP_Mailbox::getPref(IMP_Mailbox::MBOX_TRASH)->vtrash;
        $trash = IMP_Mailbox::formFrom($ui->vars->trash);

        if (!$prefs->isLocked('vfolder')) {
            $vtrash = $imp_search['vtrash'];
            $vtrash->enabled = $trash->vtrash;
            $imp_search['vtrash'] = $vtrash;
        }

        if (!$this->_updateSpecialMboxes(IMP_Mailbox::MBOX_TRASH, $trash, $ui->vars->trash_new, Horde_Imap_Client::SPECIALUSE_TRASH, $ui)) {
            return false;
        }

        $injector->getInstance('IMP_Factory_Imap')->create()->updateFetchIgnore();

        /* Switching to/from Virtual Trash requires us to expire all currently
         * cached mailbox lists (hide deleted status may have changed). */
        if ($curr_vtrash || $trash->vtrash) {
            $injector->getInstance('IMP_Factory_MailboxList')->expireAll();
        }

        return true;
    }

}
