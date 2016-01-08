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
 * Implementation of the account object for a remote server.
 *
 * @author    Michael Slusarz <slusarz@horde.org>
 * @category  Horde
 * @copyright 2013-2015 Horde LLC
 * @license   http://www.horde.org/licenses/gpl GPL
 * @package   IMP
 */
class IMP_Ftree_Account_Remote extends IMP_Ftree_Account_Imap
{
    /* Remote account key. */
    const REMOTE_KEY = "remote\0";

    /**
     */
    public function __construct($id = null)
    {
        if (is_null($id)) {
            throw new InvalidArgumentException('Constructor requires an account ID.');
        }

        parent::__construct($id);
    }

    /**
     */
    public function getList($query = array(), $mask = 0)
    {
        global $injector;

        $out = array();

        $init = $this->imp_imap->init;

        $remote = $injector->getInstance('IMP_Remote');
        $raccount = $remote[strval($this)];

        $query = array_filter(
            array_map(array($remote, 'getMailboxById'), $query)
        );
        if (empty($query)) {
            $mask |= self::INIT;
        }

        if ($mask & self::INIT) {
            $out[] = array(
                'a' => IMP_Ftree::ELT_REMOTE | IMP_Ftree::ELT_NOSELECT | IMP_Ftree::ELT_NONIMAP,
                'v' => self::REMOTE_KEY
            );

            $out[] = array(
                'a' => ($init ? IMP_Ftree::ELT_REMOTE_AUTH : 0) | IMP_Ftree::ELT_REMOTE | IMP_Ftree::ELT_IS_SUBSCRIBED | IMP_Ftree::ELT_NONIMAP,
                'p' => self::REMOTE_KEY,
                'v' => strval($this)
            );
        }

        if ($init) {
            foreach (parent::getList($query, $mask) as $val) {
                $out[] = array_filter(array(
                    'a' => $val['a'] | IMP_Ftree::ELT_REMOTE_MBOX,
                    'p' => isset($val['p']) ? $raccount->mailbox($val['p']) : strval($raccount),
                    'v' => $raccount->mailbox($val['v'])
                ));
            }
        }

        return $out;
    }

    /**
     */
    public function delete(IMP_Ftree_Element $elt)
    {
        if ($elt->remote_auth) {
            return self::DELETE_ELEMENT_QUICK | self::DELETE_RECURSIVE;
        }

        return $elt->remote
            ? self::DELETE_ELEMENT_QUICK
            : self::DELETE_ELEMENT;
    }

}
