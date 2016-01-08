<?php
/**
 * Copyright 2002-2015 Horde LLC (http://www.horde.org/)
 *
 * See the enclosed file COPYING for license information (GPL). If you
 * did not receive this file, see http://www.horde.org/licenses/gpl.
 *
 * @category  Horde
 * @copyright 2002-2015 Horde LLC
 * @license   http://www.horde.org/licenses/gpl GPL
 * @package   IMP
 */

/**
 * Quota driver for IMAP servers.
 *
 * @author    Mike Cochrane <mike@graftonhall.co.nz>
 * @category  Horde
 * @copyright 2002-2015 Horde LLC
 * @license   http://www.horde.org/licenses/gpl GPL
 * @package   IMP
 */
class IMP_Quota_Imap extends IMP_Quota
{
    /**
     * Constructor.
     *
     * @param array $params  Parameters:
     *   - imap_ob: (Horde_Imap_Client_Base) IMAP client object [REQUIRED].
     */
    public function __construct(array $params = array())
    {
        if (!isset($params['imap_ob'])) {
            throw new InvalidArgumentException('Missing imap_ob parameter');
        }

        parent::__construct($params);
    }

    /**
     */
    public function getQuota($mailbox = null)
    {
        try {
            $quota = $this->_params['imap_ob']->getQuotaRoot(is_null($mailbox) ? 'INBOX' : $mailbox);
        } catch (IMP_Imap_Exception $e) {
            throw new IMP_Exception(_("Unable to retrieve quota"));
        }

        $quota_val = reset($quota);

        return isset($quota_val['storage'])
            ? array(
                  'limit' => $quota_val['storage']['limit'] * 1024,
                  'usage' => $quota_val['storage']['usage'] * 1024
              )
            : array(
                'limit' => 0,
                'usage' => 0
              );
    }

}
