
# Functions to "unpack" DWARF attributes
def expect_str(attr):
    assert(attr.form in ['DW_FORM_string', 'DW_FORM_strp'])
    return attr.value

def expect_int(attr):
    assert(attr.form in ['DW_FORM_sdata', 'DW_FORM_data1', 'DW_FORM_data2', 'DW_FORM_data4', 'DW_FORM_data8'])
    return attr.value

def expect_ref(attr):
    assert(attr.form in ['DW_FORM_ref1', 'DW_FORM_ref2', 'DW_FORM_ref4', 'DW_FORM_ref8'])
    return attr.value

def expect_flag(attr):
    assert(attr.form in ['DW_FORM_flag','DW_FORM_flag_present'])
    return attr.value

def expect_addr(attr):
    assert(attr.form in ['DW_FORM_addr'])
    return attr.value

def get_flag(die, attrname, default=None):
    try:
        attr = die.attributes[attrname]
    except KeyError:
        return default
    else:
        return expect_flag(attr)

def get_str(die, attrname, default=None, allow_none=True):
    try:
        attr = die.attributes[attrname]
    except KeyError:
        return default
    else:
        return expect_str(attr)

def get_int(die, attrname, default=None):
    try:
        attr = die.attributes[attrname]
    except KeyError:
        return default
    else:
        return expect_int(attr)

def get_ref(die, attrname, default=None):
    try:
        attr = die.attributes[attrname]
    except KeyError:
        return default
    else:
        return expect_ref(attr)

def get_addr(die, attrname, default=None):
    try:
        attr = die.attributes[attrname]
    except KeyError:
        return default
    else:
        return expect_addr(attr)

def get_abstr(die, attrname, default=None):
    try:
        attr = die.attributes[attrname]
    except KeyError:
        return default
    else:
        return expect_ref(attr)

def not_none(x):
    assert x is not None
    return x
