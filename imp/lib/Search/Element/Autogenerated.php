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
 * Handle "automatically generated" message search query.
 *
 * RFC 3834 defines a method to indicate whether a message was automatically
 * generated without explicit user direction. This search object queries
 * the message headers for this information.
 *
 * @author    Michael Slusarz <slusarz@horde.org>
 * @category  Horde
 * @copyright 2011-2015 Horde LLC
 * @license   http://www.horde.org/licenses/gpl GPL
 * @package   IMP
 */
class IMP_Search_Element_Autogenerated extends IMP_Search_Element
{
    /**
     * Constructor.
     *
     * @param boolean $not  If true, do a 'NOT' search of $text.
     */
    public function __construct($not = false)
    {
        /* Data element: (integer) Do a NOT search? */
        $this->_data = intval(!empty($not));
    }

    /**
     */
    public function createQuery($mbox, $queryob)
    {
        $search_ob = new Horde_Imap_Client_Search_Query();

        $ob1 = clone $search_ob;
        $ob1->headerText('auto-submitted', 'auto-generated', $this->_data);

        $ob2 = clone $search_ob;
        $ob2->headerText('auto-submitted', 'auto-replied', $this->_data);

        $queryob->orSearch(array($ob1, $ob2));

        return $queryob;
    }

    /**
     */
    public function queryText()
    {
        return ($this->_data ? _("not") . ' ' : '') . _("Automatically Generated Messages");
    }

}