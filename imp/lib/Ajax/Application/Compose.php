<?php
/**
 * Copyright 2012-2015 Horde LLC (http://www.horde.org/)
 *
 * See the enclosed file COPYING for license information (GPL). If you
 * did not receive this file, see http://www.horde.org/licenses/gpl.
 *
 * @category  Horde
 * @copyright 2012-2015 Horde LLC
 * @license   http://www.horde.org/licenses/gpl GPL
 * @package   IMP
 */

/**
 * Compose view utilities for AJAX data.
 *
 * @author    Michael Slusarz <slusarz@horde.org>
 * @category  Horde
 * @copyright 2012-2015 Horde LLC
 * @license   http://www.horde.org/licenses/gpl GPL
 * @package   IMP
 */
class IMP_Ajax_Application_Compose
{
    /**
     * Forward mapping of id -> compose object constants.
     *
     * @var array
     */
    public $forward_map = array(
        'editasnew' => IMP_Compose::EDITASNEW,
        'forward_attach' => IMP_Compose::FORWARD_ATTACH,
        'forward_auto' => IMP_Compose::FORWARD_AUTO,
        'forward_body' => IMP_Compose::FORWARD_BODY,
        'forward_both' => IMP_Compose::FORWARD_BOTH
    );

    /**
     * Reply mapping of id -> compose object constant.
     *
     * @var array
     */
    public $reply_map = array(
        'reply' => IMP_Compose::REPLY_SENDER,
        'reply_all' => IMP_Compose::REPLY_ALL,
        'reply_auto' => IMP_Compose::REPLY_AUTO,
        'reply_list' => IMP_Compose::REPLY_LIST
    );

    /**
     * Compose object.
     *
     * @var IMP_Compose
     */
    protected $_compose;

    /**
     * Compose type.
     *
     * @var string
     */
    protected $_type;

    /**
     * Constuctor.
     *
     * @param IMP_Compose $ob  Compose object.
     * @param string $type     Compose type.
     */
    public function __construct(IMP_Compose $ob, $type = null)
    {
        $this->_composeOb = $ob;
        $this->_type = $type;
    }

    /**
     */
    public function getResponse($result)
    {
        $ob = $this->getBaseResponse($result);

        $ob->body = $result['body'];
        $ob->format = $result['format'];
        $ob->identity = $result['identity'];

        if (!empty($result['attach'])) {
            $ob->opts->attach = 1;
        }

        if ($search = array_search($result['type'], $this->reply_map)) {
            if ($this->_type == 'reply_auto') {
                $ob->opts->auto = $search;

                if (isset($result['reply_list_id'])) {
                    $ob->opts->reply_list_id = $result['reply_list_id'];
                }
                if (isset($result['reply_recip'])) {
                    $ob->opts->reply_recip = $result['reply_recip'];
                }
            }

            if (!empty($result['lang'])) {
                $ob->opts->reply_lang = array_values($result['lang']);
            }

            $ob->opts->focus = 'composeMessage';
        } elseif ($search = array_search($result['type'], $this->forward_map)) {
            if ($this->_type == 'forward_auto') {
                $ob->opts->auto = $search;
            }
        } else {
            $ob->opts->priority = $result['priority'];
            $ob->opts->readreceipt = $result['readreceipt'];
        }

        return $ob;
    }

    /**
     */
    public function getBaseResponse($result = array())
    {
        $ob = new stdClass;
        $ob->body = '';
        $ob->opts = new stdClass;
        $ob->subject = isset($result['subject'])
            ? $result['subject']
            : '';
        $ob->type = $this->_type;

        if (isset($result['addr'])) {
            $ob->addr = array(
                'to' => array_map('strval', $result['addr']['to']->base_addresses),
                'cc' => array_map('strval', $result['addr']['cc']->base_addresses),
                'bcc' => array_map('strval', $result['addr']['bcc']->base_addresses),
            );
        }

        return $ob;
    }

}
