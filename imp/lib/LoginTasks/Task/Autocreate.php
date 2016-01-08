<?php
/**
 * Copyright 2011-2015 Horde LLC (http://www.horde.org/)
 *
 * See the enclosed file COPYING for license information (GPL). If you
 * did not receive this file, see http://www.horde.org/licenses/gpl.
 *
 * @category  Horde
 * @copyright 2011-2015 Horde LLC
 * @license   http://www.horde.org/licenses/gpl GPL
 * @package   IMP
 */

/**
 * Autocreate special mailboxes on login.
 *
 * @author    Michael Slusarz <slusarz@horde.org>
 * @category  Horde
 * @copyright 2011-2015 Horde LLC
 * @license   http://www.horde.org/licenses/gpl GPL
 * @package   IMP
 */
class IMP_LoginTasks_Task_Autocreate extends Horde_LoginTasks_Task
{
    /**
     * The interval at which to run the task.
     *
     * @var integer
     */
    public $interval = Horde_LoginTasks::EVERY;

    /**
     * Display type.
     *
     * @var integer
     */
    public $display = Horde_LoginTasks::DISPLAY_NONE;

    /**
     * Constructor.
     */
    public function __construct()
    {
        $this->active = $GLOBALS['injector']->getInstance('IMP_Factory_Imap')->create()->config->autocreate_special;
    }

    /**
     * Autocreate special mailboxes on login.
     */
    public function execute()
    {
        foreach (IMP_Mailbox::getSpecialMailboxes() as $key => $val) {
            if (is_null($val)) {
                continue;
            }

            switch ($key) {
            case IMP_Mailbox::SPECIAL_COMPOSETEMPLATES:
                $val->create();
                break;

            case IMP_Mailbox::SPECIAL_DRAFTS:
                $val->create(array(
                    'special_use' => array(Horde_Imap_Client::SPECIALUSE_DRAFTS)
                ));
                break;

            case IMP_Mailbox::SPECIAL_SENT:
                foreach ($val as $mbox) {
                    $mbox->create(array(
                        'special_use' => array(Horde_Imap_Client::SPECIALUSE_SENT)
                    ));
                }
                break;

            case IMP_Mailbox::SPECIAL_SPAM:
                $val->create(array(
                    'special_use' => array(Horde_Imap_Client::SPECIALUSE_JUNK)
                ));
                break;

            case IMP_Mailbox::SPECIAL_TRASH:
                $val->create(array(
                    'special_use' => array(Horde_Imap_Client::SPECIALUSE_TRASH)
                ));
                break;
            }
        }
    }

}
