#!/usr/bin/python
'''
Convert DWARF annotations in ELF executable to C declarations
'''
# Copyright (C) 2012 W.J. van der Laan
#
# Permission is hereby granted, free of charge, to any person obtaining a copy 
# of this software and associated documentation files (the "Software"), to deal 
# in the Software without restriction, including without limitation the rights 
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies 
# of the Software, and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all 
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
# INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
# PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT 
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION 
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE 
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
from __future__ import print_function, division, unicode_literals
import argparse

import sys, os
from collections import defaultdict

DEBUG=False

# Logging
def error(x):
    print('Error: '+x, file=sys.stderr)
def warning(x):
    print('Warning: '+x, file=sys.stderr)
def progress(x):
    print('* '+x, file=sys.stderr)

# Command-line argument parsing
def parse_arguments():
    parser = argparse.ArgumentParser(description='Convert DWARF annotations in ELF executable to C declarations')
    parser.add_argument('input', metavar='INFILE', type=str, 
            help='Input file (ELF)')
    parser.add_argument('cuname', metavar='CUNAME', type=str, 
            help='Compilation unit name', nargs='*')
    return parser.parse_args()        

from pyelftools.elf.elffile import ELFFile
from pycunparser.c_generator import CGenerator
from pycunparser import c_ast
from dwarfhelpers import get_flag, get_str, get_int, get_ref, not_none, expect_str, get_abstr
from pyelftools.dwarf.die import DIE

# DWARF die to syntax tree fragment
#     Algorithm: realize types when needed for processing
#     keep cache for types that have been built
#    
#     Structs and unions and enums can be predeclared
#     Do this as needed
#     Both anonymous and non-anonymous types can be moved as needed
#     Named types by predeclaring, anonymous types can just be generated where they are needed
class ERROR(object):
    def __init__(self, offset):
        self.offset = offset
    def __call__(self, name):
        raise ValueError('Error: %s (for die %i)' % (name, self.offset))

# Create enum/struct/union <name> to predefine types
TAG_NODE_CONS = {
    "DW_TAG_enumeration_type": c_ast.Enum,
    "DW_TAG_structure_type":   c_ast.Struct,
    "DW_TAG_union_type":       c_ast.Union
}

WRITTEN_NONE = 0   # Nothing has been written about this type
WRITTEN_PREREF = 1 # Predefinition has been written
WRITTEN_FINAL = 2  # Final structure has been written

def unistr(x):
    return (str(x).encode('latin-1'))

# Syntax tree helpers
def Comment(x):
    return c_ast.DummyNode(postcomment=x) 
def IntConst(n):
    if n is None:
        return None
    return c_ast.Constant('int', str(n))
def EnumItem(key, value):
    return c_ast.Enumerator(key,IntConst(value), postcomment = 
            (('0x%08x' % value) if value>=0 else None))
def SimpleDecl(x):
    return c_ast.Decl(None, [], [], [], x, None, None) 


# Main function to process a Dwarf die to a syntax tree fragment
def to_c_process(die, by_offset, names, rv, written, preref=False, isConst=False):
    if DEBUG:
        print("to_c_process", die.offset, preref)
    def get_type_ref(die, attr, isConst=False):
        '''
        Get type ref for a type attribute.
        A type ref is a function that, given a name, constructs a syntax tree
        for referring to that type.
        '''
        type_ = get_ref(die, 'DW_AT_type')
        if DEBUG:
            print (die.offset, "->", type_)
        if type_ is None:
            ref = base_type_ref('void')
        else:
            ref = names.get(type_)
            if ref is None or isConst:
                #ref = base_type_ref('unknown_%i' % type_)
                ref = to_c_process(by_offset[type_], by_offset, names, rv, written, preref=True, isConst=isConst)
            elif ref is ERROR:
                raise ValueError("Unexpected recursion")
        return ref
        
    names[die.offset] = typeref = ERROR(die.offset) # prevent unbounded recursion

    # Typeref based on name: simple
    name = get_str(die, 'DW_AT_name')
    if name is not None:
        try:
            prefix = TAG_NODE_CONS[die.tag](name, None)
        except KeyError:
            pass
        else: # store early, to allow self-reference
            names[die.offset] = typeref = lambda name: c_ast.TypeDecl(name,[],prefix)
            if preref: # early-out
                return typeref

    if die.tag == 'DW_TAG_enumeration_type':
        items = []
        for enumval in die._children:
            assert(enumval.tag == 'DW_TAG_enumerator')
            (sname, const_value) = (not_none(get_str(enumval,'DW_AT_name')), 
                                   not_none(get_int(enumval,'DW_AT_const_value')))
            items.append(EnumItem(sname, const_value))
        enum = c_ast.Enum(name, c_ast.EnumeratorList(items))
        if name is None:
            typeref = anon_ref(enum)
        else:
            if written[(die.tag, name)] != WRITTEN_FINAL:
                rv.append(SimpleDecl(enum))
                written[(die.tag, name)] = WRITTEN_FINAL # typedef is always final

    elif die.tag == 'DW_TAG_typedef':
        assert(name is not None)
        ref = get_type_ref(die, 'DW_AT_type')
        if written[(die.tag, name)] != WRITTEN_FINAL:
            rv.append(c_ast.Typedef(name, [], ['typedef'], ref(name)))
            written[(die.tag, name)] = WRITTEN_FINAL # typedef is always final
        typeref = base_type_ref(name) 

    elif die.tag == 'DW_TAG_base_type': # IdentifierType
        if name is None: 
            name = 'unknown_base' #??
        if isConst is True:
            name = "const " + name
        if written[(die.tag, name)] != WRITTEN_FINAL:
            rv.append(Comment("Basetype: %s" % name))
            written[(die.tag, name)] = WRITTEN_FINAL # typedef is always final
        typeref = base_type_ref(name)

    elif die.tag == 'DW_TAG_pointer_type':
        ref = get_type_ref(die, 'DW_AT_type')
        typeref = ptr_to_ref(ref) 

    elif die.tag in ['DW_TAG_const_type', 'DW_TAG_volatile_type', 'DW_TAG_restrict_type']:
        ref = get_type_ref(die, 'DW_AT_type', isConst=(die.tag is 'DW_TAG_const_type'))
        typeref = qualified_ref(ref, die.tag)

    elif die.tag in ['DW_TAG_structure_type', 'DW_TAG_union_type']:
        if get_flag(die, 'DW_AT_declaration', False):
            items = None # declaration only
            level = WRITTEN_PREREF
        else:
            items = []
            for enumval in die._children:
                if enumval.tag != 'DW_TAG_member':
                    warning('Unexpected tag %s inside struct or union (die %i)' %
                            (enumval.tag, die.offset))
                    continue
                # data_member_location and bit_size / bit_offset as comment for fields
                bit_size = None
                comment = []
                if 'DW_AT_data_member_location' in enumval.attributes:
                    ml = enumval.attributes['DW_AT_data_member_location']
                    if ml.form in ['DW_FORM_sdata', 'DW_FORM_data1', 'DW_FORM_data2', 'DW_FORM_data4', 'DW_FORM_data8']:
                        comment.append("+0x%x" % ml.value)
                    elif ml.form in ['DW_FORM_block', 'DW_FORM_block1']:
                        expr = ml.value
                        if len(expr) >= 1 and expr[0] == 0x23: #DW_OP.plus_uconst
                            comment.append("+0x%x" % expr[1])

                if 'DW_AT_bit_size' in enumval.attributes:
                    bit_size = get_int(enumval, 'DW_AT_bit_size')
                if 'DW_AT_bit_offset' in enumval.attributes:
                    bit_offset = get_int(enumval, 'DW_AT_bit_offset')
                    comment.append('bit %i..%i' % (bit_offset, bit_offset+bit_size-1))
                if 'DW_AT_byte_size' in enumval.attributes:
                    comment.append('of %i' % (8*get_int(enumval, 'DW_AT_byte_size')))
                # TODO: validate member location (alignment), bit offset
                if 'DW_AT_name' in enumval.attributes:
                    ename = expect_str(enumval.attributes['DW_AT_name'])
                else:
                    ename = None
                ref = get_type_ref(enumval, 'DW_AT_type')
                items.append(c_ast.Decl(ename,[],[],[], ref(ename), None,
                    IntConst(bit_size), postcomment=(' '.join(comment))))
            level = WRITTEN_FINAL

        cons = TAG_NODE_CONS[die.tag](name, items)
        if name is None: # anonymous structure
            typeref = anon_ref(cons)
        else:
            if written[(die.tag,name)] < level:
                rv.append(SimpleDecl(cons))
                written[(die.tag,name)] = level

    elif die.tag == 'DW_TAG_array_type':
        subtype = get_type_ref(die, 'DW_AT_type')
        arrSize = []
        count = None
        for val in die._children:
            if val.tag == 'DW_TAG_subrange_type':
                count = get_int(val, 'DW_AT_upper_bound')
                if count is not None:
                    count += 1 # count is upper_bound + 1
                    arrSize.append(count)
        #typeref = array_ref(subtype, count)
        if len(arrSize) > 1:
            typeref = multiArray_ref(subtype, arrSize)
        else:
            typeref = array_ref(subtype, count)

    elif die.tag in ['DW_TAG_subroutine_type', 'DW_TAG_subprogram']:
        inline = get_int(die, 'DW_AT_inline', 0)
        returntype = get_type_ref(die, 'DW_AT_type')
        args = []
        body = []
        for i, val in enumerate(die._children):
            if val.tag == "DW_TAG_formal_parameter":
                argtype = get_type_ref(val, 'DW_AT_type')
                argname = get_str(val, 'DW_AT_name', '')
                args.append(c_ast.Typename([], argtype(argname)))
            if val.tag == "DW_TAG_variable":
                vartype = get_type_ref(val, 'DW_AT_type')
                varname = get_str(val, 'DW_AT_name', '')
                if varname != '__PRETTY_FUNCTION__':
                    body.append(SimpleDecl(vartype(varname)))
            if val.tag == "DW_TAG_inlined_subroutine":
                absOffset = get_abstr(val, "DW_AT_abstract_origin")
                absDie = by_offset[absOffset]
                abstype = get_type_ref(absDie, 'DW_AT_type')
                absname = get_str(absDie, 'DW_AT_name', '')
                absfunc = c_ast.FuncDecl(None, abstype(absname))
                high = val.attributes["DW_AT_high_pc"].value
                low = val.attributes["DW_AT_low_pc"].value
                comment = "inline low: %s, high: %s" % (hex(low), hex(high))
                body.append(c_ast.Decl(None, [], [], [], absfunc, None, None, None, postcomment=comment))
        cons = lambda name: c_ast.FuncDecl(c_ast.ParamList(args), returntype(name))

        if die.tag == 'DW_TAG_subprogram':
            # Is it somehow specified whether this function is static or external?
            assert(name is not None)
            if written[(die.tag,name)] != WRITTEN_FINAL:
                if inline: # Generate commented declaration for inlined function
                    rv.append(Comment("inline"))                
                funcDecl = (SimpleDecl(cons(name)))
                comp = c_ast.Compound(body)
                rv.append(c_ast.FuncDef(funcDecl, None, comp))
                written[(die.tag,name)] = WRITTEN_FINAL
        else: # DW_TAG.subroutine_type
            typeref = cons
    
    elif die.tag == 'DW_TAG_variable':
        subtype = get_type_ref(die, 'DW_AT_type')
        if written[(die.tag, name)] != WRITTEN_FINAL:
            rv.append(SimpleDecl(subtype(name)))
            written[(die.tag, name)] = WRITTEN_FINAL
    
    else:
        # reference_type, class_type, set_type   etc
        # variable
        if name is None or written[(die.tag,name)] != WRITTEN_FINAL:
            rv.append(Comment("Unhandled: %s\n%s" % (die.tag, unistr(die))))
            written[(die.tag,name)] = WRITTEN_FINAL
        warning("unhandled %s (die %i)" % (die.tag, die.offset))

    names[die.offset] = typeref
    return typeref

# Functions for manipulating "type references"
# Effectively these are unary functions that return a constructed
# syntax tree from a name.
from functools import partial
def anon_ref(type_def):
    '''Return reference to anonymous struct or enum'''
    return lambda name: c_ast.TypeDecl(name,[],type_def)

def base_type_ref(basetypename):
    basetypename = basetypename.split(' ')
    return lambda x: c_ast.TypeDecl(x,[],c_ast.IdentifierType(basetypename))

def ptr_to_ref(ref):
    return lambda x: c_ast.PtrDecl([], ref(x))

def qualified_ref(ref, tag):
    # XXX nested qualifiers are in reversed order in C
    # tag: DW_TAG.const_type, DW_TAG.volatile_type, DW_TAG.restrict_type
    return lambda x: ref(x) #Const(ref(x))

def array_ref(ref, count=None):
    return lambda x: c_ast.ArrayDecl(ref(x), dim=IntConst(count))

def multiArray_ref(ref, listcount=None):
    dimlist = []
    for l in listcount:
        dimlist.append(IntConst(l))
    return lambda x: c_ast.MultiArrayDecl(ref(x), dimlist)

# Main conversion function
def parse_dwarf(infile, cuname):
    if not os.path.isfile(infile):
        error("No such file %s" % infile)
        exit(1)

    with open(infile, 'rb') as f:
        elffile = ELFFile(f)
        if not elffile.has_dwarf_info():
            print('  file has no DWARF info')
            return

        dwarf = elffile.get_dwarf_info()
        # Keep track of what has been written to the syntax tree
        # Indexed by (tag,name)
        # Instead of using this, it may be better to just collect and
        # to dedup later, so that we can check that there are no name conflicts.
        written = defaultdict(int) 
        

        if cuname:
            # TODO: handle multiple specific compilation units
            cu = None
            for c in dwarf.iter_CUs():
                cuDie = DIE(cu=c, stream=c.dwarfinfo.debug_info_sec.stream, offset=c.cu_die_offset)
                c_file = cuDie.get_full_path()
                if c_file.endswith(cuname[0]):
                    cu = c
                    break
            if cu is None:
                print("Can't find compilation unit %s" % cuname, file=sys.stderr)
            statements = process_compile_unit(dwarf, cu, written)
        else:
            statements = []
            for cu in dwarf.iter_CUs():
                progress("Processing %s" % cu.get_top_DIE().get_full_path())
                statements.extend(process_compile_unit(dwarf, cu, written))
        return statements

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

def process_compile_unit(dwarf, cu, written):
    c_file = cu.get_top_DIE().get_full_path() # cu name is main file path

    cu = bytes_to_string(cu)
    cu_die = cu.get_top_DIE()

    statements = []
    prev_decl_file = object()

    #dies_dict = 
    dies_dict = make_dies_dict(cu)

    # Generate actual syntax tree
    names = {} # Defined names for dies, as references, indexed by offset
    for child in cu_die.iter_children():
        decl_file_id = get_int(child, 'DW_AT_decl_file')
        decl_file = c_file if decl_file_id is not None else None
        # TODO: usefully keep track of decl_file per (final) symbol
        '''
        if decl_file != prev_decl_file:
            if decl_file == c_file:
                s = "Defined in compilation unit"
            elif decl_file is not None:
                s = "Defined in " + decl_file
            else:
                s = "Defined in base"
            statements.append(Comment("======== " + s))
        '''
        name = get_str(child, 'DW_AT_name')
        if name is not None: # non-anonymous
            if DEBUG:
                print("root", child.offset)
            if written[(child.tag, name)] != WRITTEN_FINAL:
                to_c_process(child, dies_dict, names, statements, written)

        prev_decl_file = decl_file
    return statements

def generate_c_code(statements):
    '''Generate syntax tree'''
    rv = c_ast.FileAST(statements)
    #print( rv.show())
    return rv

def main():
    # The main idea is to convert the DWARF tree to a C syntax tree, then 
    # generate C code using cgen
    args = parse_arguments()
    statements = parse_dwarf(args.input,args.cuname)
    ast = generate_c_code(statements)
    progress('Generating output')
    sys.stdout.write(CGenerator().visit(ast))

if __name__ == '__main__':
    main()
