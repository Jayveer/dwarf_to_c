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

def parse_arguments():
    parser = argparse.ArgumentParser(description='Convert DWARF annotations in ELF executable to C declarations')
    parser.add_argument('input', metavar='INFILE', type=str, 
            help='Input file (ELF)')
    parser.add_argument('cuname', metavar='CUNAME', type=str, 
            help='Compilation unit name')
    return parser.parse_args()        

from bintools.dwarf import DWARF
from bintools.dwarf.enums import DW_AT, DW_TAG, DW_LANG, DW_ATE, DW_FORM, DW_OP
from pycunparser.c_generator import CGenerator
from pycunparser import c_ast

# Functions to "unpack" DWARF attributes
def expect_str(attr):
    assert(attr.form in ['string', 'strp'])
    return attr.value

def expect_int(attr):
    assert(attr.form in ['sdata', 'data1', 'data2', 'data4', 'data8'])
    return attr.value

def expect_ref(attr):
    assert(attr.form in ['ref1', 'ref2', 'ref4', 'ref8'])
    return attr.value

def expect_flag(attr):
    assert(attr.form in ['flag'])
    return attr.value

def get_flag(die, attrname, default=None):
    try:
        attr = die.attr_dict[attrname]
    except KeyError:
        return default
    else:
        return expect_flag(attr)

def get_str(die, attrname, default=None, allow_none=True):
    try:
        attr = die.attr_dict[attrname]
    except KeyError:
        return default
    else:
        return expect_str(attr)

def get_int(die, attrname, default=None):
    try:
        attr = die.attr_dict[attrname]
    except KeyError:
        return default
    else:
        return expect_int(attr)

def get_ref(die, attrname, default=None):
    try:
        attr = die.attr_dict[attrname]
    except KeyError:
        return default
    else:
        return expect_ref(attr)

def not_none(x):
    assert x is not None
    return x

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
    DW_TAG.enumeration_type: c_ast.Enum,
    DW_TAG.structure_type:   c_ast.Struct,
    DW_TAG.union_type:       c_ast.Union
}

WRITTEN_NONE = 0   # Nothing has been written about this type
WRITTEN_PREREF = 1 # Predefinition has been written
WRITTEN_FINAL = 2  # Final structure has been written

# Syntax tree helpers
def Comment(x):
    return c_ast.DummyNode(postcomment=x) 
def IntConst(n):
    if n is None:
        return None
    return c_ast.Constant('int', str(n))
def EnumItem(key, value):
    return c_ast.Enumerator(key,IntConst(value), postcomment = '0x%08x' % value)
def SimpleDecl(x):
    return c_ast.Decl(None, [], [], [], x, None, None) 

# Main function to process a Dwarf die to a syntax tree fragment
def to_c_process(die, by_offset, names, rv, written, preref=False):
    if DEBUG:
        print("to_c_process", die.offset, preref)
    def get_type_ref(die, attr, allow_missing=True):
        '''
        Get type ref for a type attribute.
        A type ref is a function that, given a name, constructs a syntax tree
        for referring to that type.
        '''
        type_ = get_ref(die, 'type')
        if DEBUG:
            print (die.offset, "->", type_)
        if type_ is None:
            if not allow_missing:
                raise ValueError('Missing required field %s in die %i' % (attr, die.offset))
            ref = base_type_ref('void')
        else:
            ref = names.get(type_)
            if ref is None:
                #ref = base_type_ref('unknown_%i' % type_)
                ref = to_c_process(by_offset[type_], by_offset, names, rv, written, preref=True)
            elif ref is ERROR:
                raise ValueError("Unexpected recursion")
        return ref
        
    names[die.offset] = typeref = ERROR(die.offset) # prevent unbounded recursion

    # Typeref based on name: simple
    name = get_str(die, 'name')
    if name is not None:
        try:
            prefix = TAG_NODE_CONS[die.tag](name, None)
        except KeyError:
            pass
        else: # store early, to allow self-reference
            names[die.offset] = typeref = lambda name: c_ast.TypeDecl(name,[],prefix)
            if preref: # early-out
                return typeref

    if die.tag == DW_TAG.enumeration_type:
        items = []
        for enumval in die.children:
            assert(enumval.tag == DW_TAG.enumerator)
            (sname, const_value) = (not_none(get_str(enumval,'name')), 
                                   not_none(get_int(enumval,'const_value')))
            items.append(EnumItem(sname, const_value))
        enum = c_ast.Enum(name, c_ast.EnumeratorList(items))
        if name is None:
            typeref = anon_ref(enum)
        else:
            rv.append(SimpleDecl(enum))

    elif die.tag == DW_TAG.typedef:
        assert(name is not None)
        ref = get_type_ref(die, 'type')
        rv.append(c_ast.Typedef(name, [], ['typedef'], ref(name)))
        written[die.offset] = WRITTEN_FINAL
        typeref = base_type_ref(name) 

    elif die.tag == DW_TAG.base_type: # IdentifierType
        if name is None: 
            name = 'unknown_base' #??
            rv.append(Comment(str(die)))
        rv.append(Comment("Basetype: %s" % name))
        typeref = base_type_ref(name)

    elif die.tag == DW_TAG.pointer_type:
        ref = get_type_ref(die, 'type')
        typeref = ptr_to_ref(ref) 

    elif die.tag in [DW_TAG.const_type, DW_TAG.volatile_type]:
        ref = get_type_ref(die, 'type')
        typeref = qualified_ref(ref, die.tag) 

    elif die.tag in [DW_TAG.structure_type, DW_TAG.union_type]:
        if get_flag(die, 'declaration', False):
            items = None # declaration only
        else:
            items = []
            for enumval in die.children:
                assert(enumval.tag == DW_TAG.member)
                # data_member_location and bit_size / bit_offset as comment for fields
                bit_size = None
                comment = []
                if 'data_member_location' in enumval.attr_dict:
                    expr = enumval.attr_dict['data_member_location'].value
                    assert(expr.instructions[0].opcode == DW_OP.plus_uconst)
                    comment.append("+0x%x" % expr.instructions[0].operand_1)
                if 'bit_size' in enumval.attr_dict:
                    bit_size = get_int(enumval, 'bit_size')
                if 'bit_offset' in enumval.attr_dict:
                    bit_offset = get_int(enumval, 'bit_offset')
                    comment.append('bit %i..%i' % (bit_offset, bit_offset+bit_size-1))
                if 'byte_size' in enumval.attr_dict:
                    comment.append('of %i' % (8*get_int(enumval, 'byte_size')))
                # TODO: validate member location (alignment), bit offset
                ename = expect_str(enumval.attr_dict['name'])
                ref = get_type_ref(enumval, 'type', allow_missing=False)
                items.append(c_ast.Decl(ename,[],[],[], ref(ename), None,
                    IntConst(bit_size), postcomment=(' '.join(comment))))
        cons = TAG_NODE_CONS[die.tag](name, items)
        if name is None: # anonymous structure
            typeref = anon_ref(cons)
        else:
            rv.append(SimpleDecl(cons))
            written[die.offset] = WRITTEN_FINAL

    elif die.tag == DW_TAG.array_type:
        subtype = get_type_ref(die, 'type')
        count = None
        for val in die.children:
            if val.tag == DW_TAG.subrange_type:
                count = get_int(val, 'upper_bound')
        if count is not None:
            count += 1 # count is upper_bound + 1
        typeref = array_ref(subtype, count) 

    elif die.tag in [DW_TAG.subroutine_type, DW_TAG.subprogram]:
        inline = get_int(die, 'inline', 0)
        returntype = get_type_ref(die, 'type')
        args = []
        for i,val in enumerate(die.children):
            if val.tag == DW_TAG.formal_parameter:
                argtype = get_type_ref(val, 'type')
                argname = get_str(val, 'name', '')
                args.append(c_ast.Typename([], argtype(argname)))
        cons = lambda name: c_ast.FuncDecl(c_ast.ParamList(args), returntype(name))

        if die.tag == DW_TAG.subprogram:
            assert(name is not None)
            if inline: # Generate commented declaration for inlined function
                #rv.append(Comment('\n'.join(cons.generate())))
                rv.append(Comment('Inline function %s' % name))
            else:
                rv.append(SimpleDecl(cons(name)))
            written[die.offset] = WRITTEN_FINAL
        else: # DW_TAG.subroutine_type
            typeref = cons
    else:
        # reference_type, class_type, set_type   etc
        print("Warning: unhandled %s (die %i)" % (DW_TAG[die.tag], die.offset))
        rv.append(Comment("Unhandled: %s\n%s" % (DW_TAG[die.tag], die)))

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
    # tag: DW_TAG.const_type, DW_TAG.volatile_type
    return lambda x: ref(x) #Const(ref(x))

def array_ref(ref, count=None):
    return lambda x: c_ast.ArrayDecl(ref(x), dim=IntConst(count))

# Main conversion function
def parse_dwarf(infile, cuname):
    if not os.path.isfile(infile):
        print("No such file %s" % infile, file=sys.stderr)
        exit(1)
    dwarf = DWARF(infile)

    cu = None
    for i, c in enumerate(dwarf.info.cus):
        if c.name.endswith(cuname):
            cu = c
            break
    if cu is None:
        print("Can't find compilation unit %s" % cuname, file=sys.stderr)
    # enumerate all dies (flat list)
    #for die in cu.dies:
    #    print DW_TAG[die.tag]
    statements = process_compile_unit(dwarf, cu)
    return statements

def process_compile_unit(dwarf, cu):
    cu_die = cu.compile_unit
    c_file = cu.name # cu name is main file path
    statements = []
    prev_decl_file = object()
    # Collect type information
    by_offset = {}
    for child in cu_die.children:
        by_offset[child.offset] = child 
    # Generate actual syntax tree
    names = {} # Defined names for dies, as references, indexed by offset
    written = defaultdict(int) # What has been written to syntax tree?
    for child in cu_die.children:
        decl_file_id = get_int(child, 'decl_file')
        decl_file = cu.get_file_path(decl_file_id) if decl_file_id is not None else None
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
        if 'name' in child.attr_dict:
            if DEBUG:
                print("root", child.offset)
            if written[child.offset] != WRITTEN_FINAL:
                to_c_process(child, by_offset, names, statements, written)

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
    sys.stdout.write(CGenerator().visit(ast))

if __name__ == '__main__':
    main()