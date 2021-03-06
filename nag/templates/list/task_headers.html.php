<thead>
 <tr class="">
  <th id="s<?php echo Nag::SORT_COMPLETION ?>"<?php if ($this->sortby == Nag::SORT_COMPLETION) echo ' class="' . $this->sortdirclass . '"' ?> width="2%">
   <?php echo $this->headerWidget($this->baseurl, $this->sortdir, $this->sortby, Nag::SORT_COMPLETION, Horde::img('checked.png', _("Completed?"))) ?>
  </th>
<?php if (in_array('tasklist', $this->columns)): ?>
  <th id="s<?php echo Nag::SORT_OWNER ?>" class="horde-split-left<?php if ($this->sortby == Nag::SORT_OWNER) echo ' ' . $this->sortdirclass ?>" width="2%">
   <?php echo $this->headerWidget($this->baseurl, $this->sortdir, $this->sortby, Nag::SORT_OWNER, _("_Task List")) ?>
  </th>
<?php endif; if (in_array('priority', $this->columns)): ?>
  <th id="s<?php echo Nag::SORT_PRIORITY ?>" class="horde-split-left<?php if ($this->sortby == Nag::SORT_PRIORITY) echo ' ' . $this->sortdirclass ?>" width="2%">
   <?php echo $this->headerWidget($this->baseurl, $this->sortdir, $this->sortby, Nag::SORT_PRIORITY, _("P_ri")) ?>
  </th>
<?php endif; ?>
  <th width="2%" class="horde-split-left nosort">
   <?php echo Horde::img('edit.png', _("Edit Task")) ?>
  </th>
  <th id="s<?php echo Nag::SORT_NAME ?>" class="horde-split-left<?php if ($this->sortby == Nag::SORT_NAME) echo ' ' . $this->sortdirclass ?>">
   <?php echo $this->headerWidget($this->baseurl, $this->sortdir, $this->sortby, Nag::SORT_NAME, _("Na_me")) ?>
  </th>
  <th width="2%" class="horde-split-left nosort"><?php echo Horde::img('note.png', _("Task Note?")) ?></th>
  <th width="2%" class="horde-split-left nosort"><?php echo Horde::img('alarm.png', _("Task Alarm?")) ?></th>
<?php if (in_array('due', $this->columns)): ?>
  <th id="s<?php echo Nag::SORT_DUE ?>" class="horde-split-left<?php if ($this->sortby == Nag::SORT_DUE) echo ' ' . $this->sortdirclass ?>" width="2%">
   <?php echo $this->headerWidget($this->baseurl, $this->sortdir, $this->sortby, Nag::SORT_DUE, _("_Due Date")) ?>
  </th>
<?php endif; if (in_array('start', $this->columns)): ?>
  <th id="s<?php echo Nag::SORT_START ?>" class="horde-split-left<?php if ($this->sortby == Nag::SORT_START) echo ' ' . $this->sortdirclass ?>" width="2%">
   <?php echo $this->headerWidget($this->baseurl, $this->sortdir, $this->sortby, Nag::SORT_START, _("_Start Date")) ?>
  </th>
<?php endif; if (in_array('estimate', $this->columns)): ?>
  <th id="s<?php echo Nag::SORT_ESTIMATE ?>" class="horde-split-left<?php if ($this->sortby == Nag::SORT_ESTIMATE) echo ' ' . $this->sortdirclass ?>" width="10%">
   <?php echo $this->headerWidget($this->baseurl, $this->sortdir, $this->sortby, Nag::SORT_ESTIMATE, _("Estimated Time")) ?>
  </th>
<?php endif; if (in_array('assignee', $this->columns)): ?>
  <th id="s<?php echo Nag::SORT_ASSIGNEE ?>" class="horde-split-left<?php if ($this->sortby == Nag::SORT_ASSIGNEE) echo ' ' . $this->sortdirclass ?>" width="10%">
   <?php echo $this->headerWidget($this->baseurl, $this->sortdir, $this->sortby, Nag::SORT_ASSIGNEE, _("Assignee")) ?>
  </th>
<?php endif; ?>
 </tr>
</thead>
