function clone_parent_form_group(node) {
    var $formGroup = $(node).parents('.form-group');
    var $newFormGroup = $formGroup.clone(true);
    $newFormGroup.find('input').val('');
    $newFormGroup.insertAfter($formGroup);
    update_form_group_labels($newFormGroup);
}

function delete_parent_form_group(node) {
    var $formGroup = $(node).parents('.form-group');
    var $prevFormGroup = $formGroup.prev();
    $formGroup.remove();
    update_form_group_labels($prevFormGroup);
}

function update_form_group_labels($formGroup) {
    $formGroups = $formGroup.parent().children('.' + $formGroup.attr('class').replace(/ /g, '.'));

    for (var i = 0; i < $formGroups.length; i++) {
        var $label = $formGroups.eq(i).find('label');
        $label.text($label.text().replace(/\d+/, (i + 1)));
    }
}
