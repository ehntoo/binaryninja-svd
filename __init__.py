from binaryninja import *
from binaryninja.types import Type, Symbol
from .svdmmap import parse

def load_svd(bv):
    svd_file = interaction.get_open_filename_input("SVD File")
    device = parse(svd_file)
    for p in device['peripherals'].values():
        bv.add_auto_section(p['name'], p['base'], p['size'],
                            SectionSemantics.ReadWriteDataSectionSemantics)
        bv.add_auto_segment(p['base'], p['size'], 0, 0,
                            SegmentFlag.SegmentContainsData | SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable)

        struct_type = None
        if 'derives' in p:
            print("Hey, we hit it")
            struct_type = bv.get_type_by_name(device['peripherals'][p['derives']]['name'])
        else:
            s = Structure()
            for r in p['registers'].values():
                s.insert(r['offset'], Type.int(int(r['size']/8), False), r['name'])
            struct_type = Type.structure_type(s)
            bv.define_user_type(p['name'], struct_type)
        bv.define_data_var(p['base'], struct_type)
        bv.define_auto_symbol(Symbol(SymbolType.ImportedDataSymbol, p['base'], p['name']))


PluginCommand.register(
    "Load SVD",
    "Apply an SVD's memory map",
    load_svd
)
