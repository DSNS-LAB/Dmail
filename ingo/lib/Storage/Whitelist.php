<?php
/**
 * Copyright 2012-2015 Horde LLC (http://www.horde.org/)
 *
 * See the enclosed file LICENSE for license information (ASL).  If you
 * did not receive this file, see http://www.horde.org/licenses/apache.
 *
 * @author   Michael Slusarz <slusarz@horde.org>
 * @category Horde
 * @license  http://www.horde.org/licenses/apache ASL
 * @package  Ingo
 */

/**
 * Ingo_Storage_Whitelist is the object used to hold whitelist rule
 * information.
 *
 * @author   Michael Slusarz <slusarz@horde.org>
 * @category Horde
 * @license  http://www.horde.org/licenses/apache ASL
 * @package  Ingo
 */
class Ingo_Storage_Whitelist extends Ingo_Storage_Rule
{
    /**
     */
    protected $_addr = array();

    /**
     */
    protected $_obtype = Ingo_Storage::ACTION_WHITELIST;

    /**
     * Sets the list of whitelisted addresses.
     *
     * @param mixed $data  The list of addresses (array or string).
     *
     * @throws Ingo_Exception
     */
    public function setWhitelist($data)
    {
        global $injector;

        $addr = $this->_addressList($data);
        $max = $injector->getInstance('Horde_Core_Perms')->hasAppPermission(Ingo_Perms::getPerm('max_whitelist'));

        if (($max !== true) && !empty($max)) {
            $addr_count = count($addr);
            if ($addr_count > $max) {
                throw new Ingo_Exception(sprintf(_("Maximum number of whitelisted addresses exceeded (Total addresses: %s, Maximum addresses: %s).  Could not add new addresses to whitelist."), $addr_count, $max));
            }
        }

        $this->_addr = $addr;
    }

    /**
     */
    public function getWhitelist()
    {
        return $this->_addr;
    }

}
