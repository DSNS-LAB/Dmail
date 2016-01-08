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
 * Add IMAP alert notifications to the stack.
 *
 * @author    Michael Slusarz <slusarz@horde.org>
 * @category  Horde
 * @copyright 2010-2015 Horde LLC
 * @license   http://www.horde.org/licenses/gpl GPL
 * @package   IMP
 */
class IMP_Notification_Handler_Decorator_ImapAlerts
extends Horde_Core_Notification_Handler_Decorator_Base
{
    /**
     */
    protected $_app = 'imp';

    /**
     */
    protected function _notify(
        Horde_Notification_Handler $handler,
        Horde_Notification_Listener $listener
    )
    {
        if (($listener instanceof Horde_Notification_Listener_Status) &&
            ($ob = $GLOBALS['injector']->getInstance('IMP_Factory_Imap'))) {
            /* Display IMAP alerts. */
            foreach ($ob->alerts() as $alert) {
                $handler->push($alert, 'horde.warning');
            }
        }
    }

}
