<?php
/**
 * Copyright 2006-2015 Horde LLC (http://www.horde.org/)
 *
 * See the enclosed file COPYING for license information (GPL). If you
 * did not receive this file, see http://www.horde.org/licenses/gpl.
 *
 * @category  Horde
 * @copyright 2006-2015 Horde LLC
 * @license   http://www.horde.org/licenses/gpl GPL
 * @package   IMP
 */

/**
 * Common UI code for IMP's various mailbox views.
 *
 * @author    Michael Slusarz <slusarz@horde.org>
 * @category  Horde
 * @copyright 2006-2015 Horde LLC
 * @license   http://www.horde.org/licenses/gpl GPL
 * @package   IMP
 */
class IMP_Mailbox_Ui
{
     const DATE_FORCE = 1;
     const DATE_FULL = 2;

    /**
     * The current mailbox.
     *
     * @var IMP_Mailbox
     */
    private $_mailbox;

    /**
     * Cached data.
     *
     * @var array
     */
    private $_cache = array();

    /**
     * Constructor.
     *
     * @param IMP_Mailbox $mailbox  The current mailbox.
     */
    public function __construct($mailbox = null)
    {
        $this->_mailbox = $mailbox;
    }

    /**
     * Get From address information for display on mailbox page.
     *
     * @param Horde_Imap_Client_Data_Envelope $ob  An envelope object.
     *
     * @return array  An array of information:
     *   - from: (string) The label(s) of the From address (personal part;
     *           fallback to address).
     *   - from_addr: (string) The bare address(es) of the From address.
     *   - from_list: (Horde_Mail_Rfc822_List) From address list.
     *   - to: (boolean) True if this is who the message was sent to.
     */
    public function getFrom($ob)
    {
        $ret = array(
            'from' => '',
            'from_addr' => '',
            'to' => false
        );

        if (!isset($this->_cache['drafts_sm_folder'])) {
            $this->_cache['drafts_sm_folder'] = $this->_mailbox->special_outgoing;
        }

        if ($GLOBALS['injector']->getInstance('IMP_Identity')->hasAddress($ob->from)) {
            if (!$this->_cache['drafts_sm_folder']) {
                $ret['from'] = _("To:") . ' ';
            }
            $ret['to'] = true;
            $addrs = $ob->to;

            if (!count($addrs)) {
                $ret['from'] .= _("Undisclosed Recipients");
                $ret['from_list'] = new Horde_Mail_Rfc822_List();
                return $ret;
            }
        } else {
            $addrs = $ob->from;
            if ($this->_cache['drafts_sm_folder']) {
                $ret['from'] = _("From:") . ' ';
            }

            if (!count($addrs)) {
                $ret['from'] = _("Invalid Address");
                $ret['from_list'] = new Horde_Mail_Rfc822_List();
                return $ret;
            }
        }

        $bare = $parts = array();

        $addrs->unique();
        foreach ($addrs->base_addresses as $val) {
            $bare[] = $val->bare_address;
            $parts[] = $val->label;
        }

        $ret['from'] .= implode(', ', $parts);
        $ret['from_addr'] = implode(', ', $bare);
        $ret['from_list'] = $addrs;

        return $ret;
    }

    /**
     * Formats the date header.
     *
     * @param mixed $date      The date object. Either a DateTime object or a
     *                         date string.
     * @param integer $format  Mask of formatting options:
     *   - IMP_Mailbox_Ui::DATE_FORCE - Force use of date formatting, instead
     *                                  of time formatting, for all dates.
     *   - IMP_Mailbox_Ui::DATE_FULL - Use full representation of date,
     *                                 including time information.
     *
     * @return string  The formatted date header.
     */
    public function getDate($date, $format = 0)
    {
        if (!is_object($date)) {
            if (is_null($date)) {
                return _("Unknown Date");
            }

            $date = new Horde_Imap_Client_DateTime($date);
        }

        if (!($format & self::DATE_FORCE) &&
            !isset($this->_cache['today_start'])) {
            $this->_cache['today_start'] = new DateTime('today');
            $this->_cache['today_end'] = new DateTime('today + 1 day');
        }

        $udate = null;
        if (!$date->error()) {
            try {
                $udate = $date->format('U');
            } catch (Exception $e) {}
        }

        if (is_null($udate)) {
            return _("Unknown Date");
        }

        if (($format & self::DATE_FORCE) ||
            ($udate < $this->_cache['today_start']->format('U')) ||
            ($udate > $this->_cache['today_end']->format('U'))) {
            /* Not today, use the date. */
            if ($format & self::DATE_FULL) {
                return strftime($GLOBALS['prefs']->getValue('date_format'), $udate) .
                    ' [' . strftime($GLOBALS['prefs']->getValue('time_format') . ' %Z', $udate) . ']';
            }

            return strftime($GLOBALS['prefs']->getValue('date_format_mini'), $udate);
        }

        /* Else, it's today, use the time. */
        return strftime($GLOBALS['prefs']->getValue('time_format'), $udate);
    }

    /**
     * Formats the subject header.
     *
     * @param string $subject     The subject header.
     * @param string $htmlspaces  HTML-ize spaces?
     *
     * @return string  The formatted subject header.
     */
    public function getSubject($subject, $htmlspaces = false)
    {
        if (!strlen($subject)) {
            return _("[No Subject]");
        }

        $new_subject = $subject = IMP::filterText(preg_replace("/\s+/", ' ', $subject));

        if ($htmlspaces) {
            $new_subject = $GLOBALS['injector']->getInstance('Horde_Core_Factory_TextFilter')->filter($subject, 'space2html', array('encode' => true));
            if (empty($new_subject)) {
                $new_subject = htmlspecialchars($subject);
            }
        }

        return empty($new_subject) ? $subject : $new_subject;
    }

}
