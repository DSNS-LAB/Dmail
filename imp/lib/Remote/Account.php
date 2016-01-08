<?php
/**
 * Copyright 2013-2015 Horde LLC (http://www.horde.org/)
 *
 * See the enclosed file COPYING for license information (GPL). If you
 * did not receive this file, see http://www.horde.org/licenses/gpl.
 *
 * @category  Horde
 * @copyright 2013-2015 Horde LLC
 * @license   http://www.fsf.org/copyleft/gpl.html GPL
 * @package   IMP
 */

/**
 * Object representation of a remote mail account.
 *
 * @author    Michael Slusarz <slusarz@horde.org>
 * @category  Horde
 * @copyright 2013-2015 Horde LLC
 * @license   http://www.horde.org/licenses/gpl GPL
 * @package   IMP
 *
 * @property string $hostspec  Remote host.
 * @property-read string $id  Remote account storage ID.
 * @property-read IMP_Imap_Remote $imp_imap  IMP IMAP object.
 * @property string $label  Remote account label.
 * @property integer $port  Remote server port.
 * @property mixed $secure  See backends.php ('secure' parameter).
 * @property integer $type  The connection type (self::IMAP or self::POP3).
 * @property string $username  Remote username.
 */
class IMP_Remote_Account implements Serializable
{
    /* Constants used for the 'type' property. */
    const IMAP = 1;
    const POP3 = 2;

    /**
     * Configuration.
     *
     * @var array
     */
    protected $_config = array();

    /**
     */
    public function __construct()
    {
        $this->_config['id'] = strval(new Horde_Support_Randomid());
    }

    /**
     * String representation of object.
     *
     * @return string  The identifier (mailbox) ID.
     */
    public function __toString()
    {
        return IMP_Remote::MBOX_PREFIX . $this->_config['id'];
    }

    /**
     */
    public function __get($name)
    {
        if (isset($this->_config[$name])) {
            return $this->_config[$name];
        }

        switch ($name) {
        case 'hostspec':
            return 'localhost';

        case 'imp_imap':
            return $GLOBALS['injector']->getInstance('IMP_Factory_Imap')->create(strval($this));

        case 'label':
            return $this->hostspec;

        case 'port':
            return ($this->type == self::POP3) ? 110 : 143;

        case 'secure':
            return null;

        case 'type':
            return self::IMAP;

        case 'username':
            return '';
        }
    }

    /**
     */
    public function __set($name, $value)
    {
        switch ($name) {
        case 'hostspec':
        case 'label':
        case 'username':
            $this->_config[$name] = strval($value);
            break;

        case 'port':
        case 'type':
            $this->_config[$name] = intval($value);
            break;

        case 'secure':
            $this->_config[$name] = $value;
            break;
        }
    }

    /**
     * Create the IMAP object in the session.
     *
     * @param string $password  Password.
     *
     * @throws IMP_Imap_Exception
     */
    public function createImapObject($password)
    {
        $this->imp_imap->createImapObject(array(
            'hostspec' => $this->hostspec,
            'password' => new IMP_Imap_Password($password),
            'port' => $this->port,
            'secure' => $this->secure,
            'username' => $this->username,
        ), $this->type == self::IMAP, strval($this));
    }

    /**
     * Return mailbox name.
     *
     * @param string $id  Base IMAP name.
     *
     * @return string  IMP mailbox name.
     */
    public function mailbox($id)
    {
        return strval($this) . "\0" . $id;
    }

    /* Serializable methods. */

    /**
     */
    public function serialize()
    {
        return json_encode($this->_config);
    }

    /**
     */
    public function unserialize($data)
    {
        $this->_config = json_decode($data, true);
    }

}
