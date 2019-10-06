from binaryninja import *
from binaryninja.types import Type, Symbol
from .svdmmap import parse

def load_svd(bv):
    svd_file = interaction.get_open_filename_input("SVD File")
    device = parse(svd_file)
    peripherals = device['peripherals'].values()
    base_peripherals = [p for p in peripherals if 'derives' not in p]
    derived_peripherals = [p for p in peripherals if 'derives' in p]

    def register_peripheral(p, struct_type):
        bv.add_auto_section(p['name'], p['base'], p['size'],
                            SectionSemantics.ReadWriteDataSectionSemantics)
        bv.add_auto_segment(p['base'], p['size'], 0, 0,
                            SegmentFlag.SegmentContainsData | SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable)
        bv.define_data_var(p['base'], struct_type)
        bv.define_auto_symbol(Symbol(SymbolType.ImportedDataSymbol, p['base'], p['name']))

    for p in base_peripherals:
        s = Structure()
        for r in p['registers'].values():
            if r['size'] is None:
                s.insert(r['offset'], Type.int(4, False), r['name'])
            else:
                s.insert(r['offset'], Type.int(int(r['size']/8), False), r['name'])
        struct_type = Type.structure_type(s)
        bv.define_user_type(p['name'], struct_type)
        register_peripheral(p, struct_type)

    for p in derived_peripherals:
        struct_type = bv.get_type_by_name(device['peripherals'][p['derives']]['name'])
        register_peripheral(p, struct_type)


PluginCommand.register(
    "Load SVD",
    "Apply an SVD's memory map",
    load_svd
)
