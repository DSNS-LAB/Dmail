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
 * List information display.
 * Usable in both basic and dynamic views.
 *
 * @author    Michael Slusarz <slusarz@horde.org>
 * @category  Horde
 * @copyright 2013-2015 Horde LLC
 * @license   http://www.horde.org/licenses/gpl GPL
 * @package   IMP
 */
class IMP_Basic_Listinfo extends IMP_Basic_Base
{
    /**
     */
    protected function _init()
    {
        global $injector, $page_output;

        /* Parse the message. */
        try {
            $imp_contents = $injector->getInstance('IMP_Factory_Contents')->create($this->indices);
        } catch (IMP_Exception $e) {
            throw new IMP_Exception(_("Could not load message."));
        }

        $view = new Horde_View(array(
            'templatePath' => IMP_TEMPLATES . '/listinfo'
        ));

        $listheaders = $injector->getInstance('Horde_ListHeaders');
        $mime_headers = $imp_contents->getHeader();

        $view->headers = array();
        foreach ($listheaders->headers() as $key => $val) {
            if ($data = $mime_headers->getValue($key)) {
                $view->headers[$val] = $this->_parseListHeaders($key, $data);
            }
        }

        $this->output = $view->render('listinfo');
        $this->title = _("Mailing List Information");

        $page_output->addInlineScript(array(
            'window.resizeBy(0, window.document.body.scrollHeight - window.innerHeight + 20)'
        ), true);

        $page_output->topbar = $page_output->sidebar = false;
    }

    /**
     */
    public function status()
    {
    }

    /**
     * @param array $opts  Options:
     * <pre>
     *   - buid: (string) BUID of message.
     *   - full: (boolean) Full URL?
     *   - mailbox: (string) Mailbox of message.
     * </pre>
     */
    static public function url(array $opts = array())
    {
        $url = Horde::url('basic.php')
            ->add('page', 'listinfo')
            ->unique()
            ->setRaw(!empty($opts['full']));

        if (!empty($opts['mailbox'])) {
            $url->add(array(
                'buid' => $opts['buid'],
                'mailbox' => IMP_Mailbox::get($opts['mailbox'])->form_to
            ));
        }

        return $url;
    }

    /**
     * Parse the information in mailing list headers.
     *
     * @param string $id    The header ID.
     * @param string $data  The header text to process.
     *
     * @return string  The HTML-escaped header value.
     */
    protected function _parseListHeaders($id, $data)
    {
        global $injector;

        $parser = $injector->getInstance('Horde_ListHeaders');
        $text_filter = $injector->getInstance('Horde_Core_Factory_TextFilter');

        $parsed = $parser->parse($id, $data);

        if ($parsed instanceof Horde_ListHeaders_Id) {
            $out = $parsed->id;
            if ($parsed->label) {
                $out .= ' -- <em>' . $parsed->label . '</em>';
            }
            return $out;
        }

        foreach ($parsed as $val) {
            /* RFC 2369 [2] states that we should only show the *FIRST* URL
             * that appears in a header that we can adequately handle. */
            if (stripos($val->url, 'mailto:') === 0) {
                $url = substr($val->url, 7);
                $clink = new IMP_Compose_Link($url);
                $out = Horde::link($clink->link()) . $url . '</a>';
                foreach ($val->comments as $val2) {
                    $out .= htmlspecialchars('(' . $val2 . ')');
                }
                return $out;
            } elseif ($url = $text_filter->filter($val->url, 'Linkurls')) {
                $out = $url;
                foreach ($val->comments as $val2) {
                    $out .= htmlspecialchars('(' . $val2 . ')');
                }
                return $out;
            }
        }

        /* Pass through Linkurls filter anyway, since it is possible the
         * sender did not correctly put URL between brackets. */
        return Horde_Text_Filter_Linkurls::decode(htmlspecialchars(
            $text_filter->filter($data, 'Linkurls', array('encode' => true))
        ));
    }

}
