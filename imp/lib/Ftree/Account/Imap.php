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
 * Implementation of the account object for an IMAP server.
 *
 * @author    Michael Slusarz <slusarz@horde.org>
 * @category  Horde
 * @copyright 2013-2015 Horde LLC
 * @license   http://www.horde.org/licenses/gpl GPL
 * @package   IMP
 *
 * @property-read IMP_Imap $imp_imap  IMP IMAP object.
 */
class IMP_Ftree_Account_Imap extends IMP_Ftree_Account
{
    /* Defines used with namespace display. */
    const OTHER_KEY = "other\0";
    const SHARED_KEY = "shared\0";

    /**
     */
    public function __get($name)
    {
        switch ($name) {
        case 'imp_imap':
            return $GLOBALS['injector']->getInstance('IMP_Factory_Imap')->create($this->_id == IMP_Ftree::BASE_ELT ? null : $this->_id);
        }
    }

    /**
     */
    public function getList($query = array(), $mask = 0)
    {
        global $prefs;

        $imp_imap = $this->imp_imap;
        $ns = $imp_imap->getNamespaces();
        $out = array();

        if ($mask & self::INIT) {
            /* Add namespace elements. */
            if ($prefs->getValue('tree_view')) {
                foreach ($ns as $val) {
                    $type = null;

                    switch ($val->type) {
                    case $val::NS_OTHER:
                        $attr = IMP_Ftree::ELT_NAMESPACE_OTHER;
                        $type = self::OTHER_KEY;
                        break;

                    case $val::NS_SHARED:
                        $attr = IMP_Ftree::ELT_NAMESPACE_SHARED;
                        $type = self::SHARED_KEY;
                        break;
                    }

                    if (!is_null($type)) {
                        $out[$type] = array(
                            'a' => $attr | IMP_Ftree::ELT_NOSELECT | IMP_Ftree::ELT_NONIMAP,
                            'v' => $type
                        );
                    }
                }
            }

            $query = array('INBOX');
            foreach ($ns as $val) {
                $query[] = $val . '*';
            }

            $lmquery = ($mask & self::UNSUB)
                ? Horde_Imap_Client::MBOX_ALL_SUBSCRIBED
                : Horde_Imap_Client::MBOX_SUBSCRIBED_EXISTS;
        } elseif ($mask & self::UNSUB) {
            $lmquery = Horde_Imap_Client::MBOX_UNSUBSCRIBED;
            $query = array();
            foreach ($ns as $val) {
                $query[] = $val . '*';
            }
        } elseif (empty($query)) {
            return $out;
        } else {
            $lmquery = Horde_Imap_Client::MBOX_ALL_SUBSCRIBED;
        }

        $res = $imp_imap->listMailboxes($query, $lmquery, array(
            'attributes' => true,
            'delimiter' => true,
            'sort' => true
        ));

        foreach ($res as $val) {
            if (in_array('\nonexistent', $val['attributes'])) {
                continue;
            }

            $mbox = strval($val['mailbox']);
            $ns_info = $imp_imap->getNamespace($mbox);
            $parent = null;

            /* Break apart the name via the delimiter and go step by
             * step through the name to make sure all subfolders exist
             * in the tree. */
            if ($ns_info && strlen($ns_info->delimiter)) {
                /* Strip personal namespace (if non-empty). */
                if ($ns_info->type === $ns_info::NS_PERSONAL) {
                    $stripped = $ns_info->stripNamespace($mbox);
                    $parts = explode($ns_info->delimiter, $stripped);
                    if ($stripped != $mbox) {
                        $parts[0] = $ns_info->name . $parts[0];
                    }
                } else {
                    $parts = explode($ns_info->delimiter, $mbox);
                }

                if ($prefs->getValue('tree_view')) {
                    switch ($ns_info->type) {
                    case $ns_info::NS_OTHER:
                        $parent = self::OTHER_KEY;
                        break;

                    case $ns_info::NS_SHARED:
                        $parent = self::SHARED_KEY;
                        break;
                    }
                }
            } else {
                $parts = array($mbox);
            }

            for ($i = 1, $p_count = count($parts); $i <= $p_count; ++$i) {
                $part = implode($val['delimiter'], array_slice($parts, 0, $i));

                if (!isset($out[$part])) {
                    if ($p_count == $i) {
                        $attr = 0;

                        if (in_array('\subscribed', $val['attributes'])) {
                            $attr |= IMP_Ftree::ELT_IS_SUBSCRIBED;
                        }

                        if (in_array('\noselect', $val['attributes'])) {
                            $attr |= IMP_Ftree::ELT_NOSELECT;
                        }

                        if (in_array('\noinferiors', $val['attributes'])) {
                            $attr |= IMP_Ftree::ELT_NOINFERIORS;
                        }
                    } else {
                        $attr = IMP_Ftree::ELT_NOSELECT;
                    }

                    $out[$part] = array(
                        'a' => $attr,
                        'v' => $part
                    );
                    if (!is_null($parent)) {
                        $out[$part]['p'] = $parent;
                    }
                }

                $parent = $part;
            }
        }

        return $out;
    }

    /**
     */
    public function delete(IMP_Ftree_Element $elt)
    {
        return ($elt->inbox || $elt->namespace)
            ? 0
            : self::DELETE_ELEMENT;
    }

}
