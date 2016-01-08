<?php
/**
 * Copyright 2013-2015 Horde LLC (http://www.horde.org/)
 *
 * See the enclosed file COPYING for license information (GPL). If you
 * did not receive this file, see http://www.horde.org/licenses/gpl.
 *
 * @category  Horde
 * @copyright 2013-2015 Horde LLC
 * @license   http://www.horde.org/licenses/gpl GPL
 * @package   IMP
 */

/**
 * Extends base Indices object by incorporating base mailbox information.
 *
 * @author    Michael Slusarz <slusarz@horde.org>
 * @category  Horde
 * @copyright 2013-2015 Horde LLC
 * @license   http://www.horde.org/licenses/gpl GPL
 * @package   IMP
 */
class IMP_Indices_Mailbox extends IMP_Indices
{
    /**
     * The BUIDs list.
     *
     * @var IMP_Indices
     */
    public $buids;

    /**
     * Base mailbox name.
     *
     * @var IMP_Mailbox
     */
    public $mailbox;

    /**
     * Constructor.
     *
     * @param mixed  Two possible inputs:
     *   - 1 argument: Horde_Variables object. These GET/POST parameters are
     *     reserved in IMP:
     *     - buid: (string) BUID [Browser UID].
     *     - mailbox: (string) Base64url encoded mailbox.
     *     - muid: (string) MUID [Mailbox + UID].
     *     - uid: (string) UID [Actual mail UID].
     *   - 2 arguments: IMP_Mailbox object, IMP_Indices argument
     */
    public function __construct()
    {
        $args = func_get_args();

        switch (func_num_args()) {
        case 1:
            if ($args[0] instanceof Horde_Variables) {
                if (isset($args[0]->mailbox) && strlen($args[0]->mailbox)) {
                    $this->mailbox = IMP_Mailbox::formFrom($args[0]->mailbox);

                    if (isset($args[0]->buid)) {
                        /* BUIDs are always integers. Do conversion here since
                         * POP3 won't work otherwise. */
                        $tmp = new Horde_Imap_Client_Ids($args[0]->buid);
                        $this->buids = new IMP_Indices($this->mailbox, $tmp->ids);
                        parent::__construct($this->mailbox->fromBuids($this->buids));
                    } elseif (isset($args[0]->uid)) {
                        parent::__construct($this->mailbox, $args[0]->uid);
                    }
                }

                if (isset($args[0]->muid)) {
                    parent::__construct($args[0]->muid);
                }
            }
            break;

        case 2:
            if (($args[0] instanceof IMP_Mailbox) &&
                ($args[1] instanceof IMP_Indices)) {
                $this->mailbox = $args[0];
                $this->buids = $args[0]->toBuids($args[1]);
                parent::__construct($args[1]);
            }
            break;
        }

        if (!isset($this->buids)) {
            $this->buids = new IMP_Indices();
        }

        if (!isset($this->mailbox)) {
            $this->mailbox = IMP_Mailbox::get('INBOX');
        }
    }

}
