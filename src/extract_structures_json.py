#!/usr/bin/python
# (C) W.J. van der Laan 2012
'''
Extract structures from DWARF data to JSON for the C structure
pretty-printer.
'''
from __future__ import print_function, division, unicode_literals
import argparse
import os, sys
from pyelftools.elf.elffile import ELFFile
from dwarfhelpers import get_flag, get_str, get_int, get_ref, not_none, expect_str
'''
Output format JSON/Python:
  enums
  structures (name, field offsets)
  simple field types (size, type, structure, pointer to structure  + offset)
'''

DEBUG=False 

# Logging
def error(x):
    print('Error: '+x, file=sys.stderr)
def warning(x):
    print('Warning: '+x, file=sys.stderr)
def progress(x):
    print('* '+x, file=sys.stderr)

def type_name(die):
    if die is None:
        return 'void' # predefined nothing type
    type_name = get_str(die, 'name')
    if type_name is None: # Make up a name if it is not provided by DWARF
        return '%s_%i' % (die.tag, die.offset)
    return type_name

def parse_type(type, dies_dict):
    '''
    Parse type by removing modifiers and counting pointer
    indirections.
    '''
   
    indirection = 0
    while type is not None and type.tag in ['DW_TAG_const_type', 'DW_TAG_volatile_type', 'DW_TAG_typedef', 'DW_TAG_pointer_type']:
        if type.tag == 'DW_TAG_pointer_type':
            indirection += 1
        type = dies_dict.get(get_ref(type, 'DW_AT_type'), None)
    
    return (type, indirection)

def visit_base_type(die,dies_dict):
    type_info = {
        'kind': 'DW_AT_base_type',
        'byte_size': get_int(die, 'DW_AT_byte_size'),
        'encoding': 'DW_AT_encoding',
    }
    if DEBUG:
        print(type_info)
    return type_info

def visit_enumeration_type(die,dies_dict):
    type_info = {
        'kind': 'DW_AT_enumeration_type',
        'byte_size': get_int(die, 'DW_AT_byte_size'),
    }
    enumerators = []
    for child in die._children:
        if child.tag != 'DW_TAG_enumerator':
            continue
        enumerator_info = {
            'name': get_str(child, 'DW_AT_name'),
            'value': get_int(child, 'DW_AT_const_value'),
        }
        enumerators.append(enumerator_info)
        
    type_info['enumerators'] = enumerators
    if DEBUG:
        print(type_info)
    return type_info

def visit_array_type(die,dies_dict):
    type = dies_dict.get(get_ref(die, 'DW_AT_type'))
    (type,indirection) = parse_type(type, dies_dict)
    type_info = {
        'kind': 'DW_AT_array_type',
        'indirection': indirection,
        'type': type_name(type),
        'length': None
    }
    for child in die._children:
        if child.tag != "DW_TAG_subrange_type":
            continue
        upper_bound = get_int(child, 'DW_AT_upper_bound')
        if upper_bound is not None:
            type_info['length'] = upper_bound + 1
    if DEBUG:
        print(type_info)
    return type_info

def visit_structure_type(die,dies_dict):
    # enumerate members of structure or union
    type_info = {
        'kind': die.tag,
        'byte_size': get_int(die, 'DW_AT_byte_size')
    }
    members = []
    for child in die._children:
        name = get_str(child, 'name')
        member_info = {
            'name': name
        }
        # handle union as "structure with all fields at offset 0"
        offset = 0
        if 'DW_AT_data_member_location' in child.attributes:
            attr = child.attributes['DW_AT_data_member_location']
            if attr.form == 'expr':
                expr = attr.value
                assert(expr[0] == 0x23)
                offset = expr[1]
            elif attr.form in ['DW_AT_data1', 'DW_AT_data2', 'DW_AT_data4', 'DW_ATdata']:
                offset = attr.value
            else:
                assert(0) # unhandled form
        
        member_info['offset'] = offset

        type = dies_dict.get(get_ref(child, 'DW_AT_type'))
        (type,indirection) = parse_type(type, dies_dict)
        member_info['indirection'] = indirection
        member_info['type'] = type_name(type)
        members.append(member_info)
        if DEBUG:
            print(member_info)
        worklist.append(type)

    type_info['members'] = members
    return type_info

def make_dies_dict(cu):
    dies_dict = dict()
    for die in cu._dielist:
        offset = die.offset - cu.cu_offset
        dies_dict.update({offset:die})
    return dies_dict

def bytes_to_string(cu):
    for die in cu._dielist:
        if 'DW_AT_name' in die.attributes:
            valueStr = die.attributes['DW_AT_name'].value.decode('utf-8')
            die.attributes['DW_AT_name'] = die.attributes['DW_AT_name']._replace(value=valueStr)
    return cu  

def process_compile_unit(dwarf, cu, roots):

    cu = bytes_to_string(cu)
    cu_die = cu.get_top_DIE()
    # Generate actual syntax tree
    global worklist
    global visited
    types = {}
    worklist = []

    dies_dict = make_dies_dict(cu)

    for child in cu_die._children:
        visited = set()

        name = get_str(child, 'DW_AT_name')
        if name is not None: # non-anonymous
            if name in roots: # nest into this structure
                worklist.append(child)
              
    while worklist:
        die = worklist.pop()
        if die is None or die.offset in visited:
            continue
        visited.add(die.offset)
        if get_flag(die, "DW_AT_declaration"): # only predeclaration, skip
            continue

        if DEBUG:
            print("[%s]" % (type_name(die)))
        if die.tag in ['DW_TAG_structure_type', 'DW_TAG_union_type']:
            type_info = visit_structure_type(die, dies_dict)
        elif die.tag in ['DW_TAG_base_type']:
            type_info = visit_base_type(die, dies_dict)
        elif die.tag in ['DW_TAG_array_type']:
            type_info = visit_array_type(die, dies_dict)
        elif die.tag in ['DW_TAG_enumeration_type']:
            type_info = visit_enumeration_type(die, dies_dict)
        else:
            warning('%s not handled' % die.tag)
            type_info = {}

        type_info['name'] = type_name(die)
        types[type_info['name']] = type_info

    return types


# Main conversion function
def parse_dwarf(infile, roots):
    if not os.path.isfile(infile):
        error("No such file %s" % infile)
        exit(1)

    with open(infile, 'rb') as f:
            elffile = ELFFile(f)
            if not elffile.has_dwarf_info():
                print('  file has no DWARF info')
                return
    
    dwarf = elffile.get_dwarf_info()

    for cu in dwarf.iter_CUs():
        progress("Processing %s" % cu.get_top_DIE().get_full_path())
        types = process_compile_unit(dwarf, cu, roots)
        if all(x in types for x in roots): # return if all roots found
            return types

    return None # not found

def parse_arguments():
    parser = argparse.ArgumentParser(description='Extract structures from DWARF as parseable format')
    parser.add_argument('input', metavar='INFILE', type=str, 
            help='Input file (ELF)')
    parser.add_argument('roots', metavar='ROOT', type=str, nargs='+',
            help='Root data structure name')
    return parser.parse_args()        

def main():
    import json
    args = parse_arguments()
    types = parse_dwarf(args.input, args.roots)
    if types == None:
        error('Did not find all roots (%s) in any compile unit' % args.roots)
        exit(1)
    json.dump(types, sys.stdout,
            sort_keys=True, indent=4, separators=(',', ': '))
    print()

if __name__ == '__main__':
    main()
