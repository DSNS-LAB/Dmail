<form method="post" id="contacts" action="<?php echo $this->action ?>">
 <input type="hidden" name="searched" value="1" />
 <input type="hidden" name="to_only" id="to_only" value="<?php echo $this->to_only ?>" />
 <input type="hidden" id="sa" name="sa" />

<h1 class="header">
 <?php echo _("Address Book") ?>
</h1>

<div id="contactstable" class="headerbox item">
 <p class="control">
  <label for="search"><strong><?php echo _("Find") ?>:</strong></label>
  <input value="<?php echo $this->escape($this->search) ?>" id="search" name="search" />
<?php if (is_array($this->source_list)): ?>
  <strong><label for="source"><?php echo _("from") ?></label></strong>
  <select id="source" name="source">
<?php foreach ($this->source_list as $v): ?>
   <?php echo $this->optionTag($v['val'], $this->escape($v['label']), $v['selected']) ?>
<?php endforeach; ?>
  </select>
<?php else: ?>
  <input name="source" type="hidden" value="<?php echo $this->source_list ?>" />
<?php endif; ?>
  <input type="submit" value="<?php echo _("Search") ?>" />
  <input id="btn_clear" type="submit" style="display:none" value="<?php echo _("Reset") ?>" />
 </p>

 <table width="100%" cellspacing="2">
  <tr>
   <td width="45%">
    <label for="search_results" class="hidden"><?php echo _("Search Results") ?></label>
    <select id="search_results" name="search_results" multiple="multiple" size="10">
     <option disabled="disabled" value="">* <?php echo _("Select address(es)") ?> *</option>
<?php foreach (array_map(array($this, 'escape'), $this->a_list) as $v): ?>
     <?php echo $this->optionTag($v, $v) ?>
<?php endforeach; ?>
    </select>
   </td>
   <td width="10%" class="contactsButtons">
    <input id="btn_add_to" type="button" value="<?php echo _("To") ?> &gt;&gt;" /><br />&nbsp;<br />
<?php if (!$this->to_only): ?>
    <input id="btn_add_cc" type="button" value="<?php echo _("Cc") ?> &gt;&gt;" /><br />&nbsp;<br />
    <input id="btn_add_bcc" type="button" value="<?php echo _("Bcc") ?> &gt;&gt;" />
<?php endif; ?>
   </td>
   <td width="45%">
    <label for="selected_addresses" class="hidden"><?php echo _("Selected Addresses") ?></label>
    <select id="selected_addresses" name="selected_addresses" multiple="multiple" size="10">
     <option disabled="disabled" value="">* <?php echo _("Add these by clicking OK") ?> *</option>
<?php foreach (array_map(array($this, 'escape'), $this->sa) as $v): ?>
     <?php echo $this->optionTag($v, $v) ?>
<?php endforeach; ?>
    </select>
   </td>
  </tr>
  <tr>
   <td colspan="2">&nbsp;</td>
   <td>
    <input id="btn_delete" type="button" value="<?php echo _("Remove") ?>" />
   </td>
  </tr>
 </table>
</div>

<br class="spacer" />

<div>
 <input id="btn_update" type="button" class="horde-default" value="<?php echo _("OK") ?>" />
 <input id="btn_cancel" type="button" class="horde-cancel" value="<?php echo _("Cancel") ?>" />
</div>

</form>
