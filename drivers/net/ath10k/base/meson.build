sources = [
    'ath10k_osdep.c',
    'bmi.c',
    'ce.c',
    'core.c',
    'debug.c',
    'dma.c',
    'firmware.c',
    'htc.c',
    'htt.c',
    'htt_rx.c',
    'htt_tx.c',
    'hw.c',
    'linux_completion.c',
    'linux_idr.c',
    'mac.c',
    'pci.c',
    'regd.c',
    'sleepqueue.c',
    'swap.c',
    'taskqueue.c',
    'txrx.c',
    'wmi.c',
    'wmi-tlv.c'
]

error_cflags = ['-Wno-uninitialized', '-Wno-unused-parameter',
    '-Wno-unused-variable', '-Wno-misleading-indentation',
    '-Wno-implicit-fallthrough',
    '-Wno-incompatible-pointer-types',
    '-Wno-unused-function'
    ]
c_args = cflags
foreach flag: error_cflags
    if cc.has_argument(flag)
        c_args += flag
    endif
endforeach

base_lib = static_library('ath10k_base', sources,
    dependencies: [rte_eal, dep_rte_net, dep_rte_timer, dep_rte_wifi, dep_rte_hash, dep_rte_pci, dep_rte_bus_pci],
    c_args: c_args)
base_objs = base_lib.extract_all_objects()
