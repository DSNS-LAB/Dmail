<?php
/**
 * Copyright 2010-2015 Horde LLC (http://www.horde.org/)
 *
 * See the enclosed file COPYING for license information (GPL). If you
 * did not receive this file, see http://www.horde.org/licenses/gpl.
 *
 * @category  Horde
 * @copyright 2010-2015 Horde LLC
 * @license   http://www.horde.org/licenses/gpl GPL
 * @package   IMP
 */

/**
 * The abstract class that all quota drivers inherit from.
 *
 * @author    Michael Slusarz <slusarz@horde.org>
 * @category  Horde
 * @copyright 2010-2015 Horde LLC
 * @license   http://www.horde.org/licenses/gpl GPL
 * @package   IMP
 */
abstract class IMP_Quota
{
    /**
     * Driver parameters.
     *
     * @var array
     */
    protected $_params = array(
        'hide_when_unlimited' => false,
        'unit' => 'MB'
    );

    /**
     * Constructor.
     *
     * @param array $params  Parameters:
     *   - unit: (string) What storage unit the quota messages should be
     *           displayed in. Either 'GB', 'MB', or 'KB'.
     *   - username: (string) The username to query.
     */
    public function __construct(array $params = array())
    {
        $this->_params = array_merge(
            $this->_params,
            array(
                'format' => array(
                    'nolimit_short' => _("%.0f %s"),
                    'short' => _("%.0f%% of %.0f %s")
                )
            ),
            $params
        );
    }

    /**
     * Get quota information (used/allocated), in bytes.
     *
     * @param string $mailbox  Mailbox to check.
     *
     * @return array  An array with the following keys:
     *   - limit: Maximum quota allowed
     *   - usage: Currently used portion of quota (in bytes)
     *
     * @throws IMP_Exception
     */
    abstract public function getQuota($mailbox = null);

    /**
     * Should quota be displayed if no limit is configured?
     *
     * @return boolean  Whether to hide the quota.
     */
    public function isHiddenWhenUnlimited()
    {
        return $this->_params['hide_when_unlimited'];
    }

    /**
     * Returns the quota messages variants, including sprintf placeholders.
     *
     * @return array  An array with quota message templates.
     */
    public function getMessages()
    {
        return $this->_params['format'];
    }

    /**
     * Determine the units of storage to display in the quota message.
     *
     * @return array  An array of size and unit type.
     */
    public function getUnit()
    {
        $unit = $this->_params['unit'];

        switch ($unit) {
        case 'GB':
            $calc = 1024 * 1024 * 1024.0;
            break;

        case 'KB':
            $calc = 1024.0;
            break;

        case 'MB':
        default:
            $calc = 1024 * 1024.0;
            $unit = 'MB';
            break;
        }

        return array($calc, $unit);
    }

}
