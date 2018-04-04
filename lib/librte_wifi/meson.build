version = 2
sources = files(
    'cfg.c',
    'chan.c',
    'dev.c',
    #'flow_dissector.c',
    'ht.c',
    'ibss.c',
    'iface.c',
    'mlme.c',
    'rate.c',
    'rte_80211.c',
    'rte_general.c',
    'rte_ieee80211dev.c',
    'scan.c',
    'sta_info.c',
    'status.c',
    'tx.c',
    'util.c',
    'vht.c',
    'wireless_chan.c',
    'rte_wifi.c')

headers = files(
    'codel.h',
    'codel_impl.h',
    'flow_dissector.h',
    'fq.h',
    'fq_impl.h',
    'netdevice.h',
    'rte_80211.h',
    'rte_cfg80211.h',
    'rte_general.h',
    'rte_ieee80211dev.h',
    'rte_ieee80211.h',
    'rte_ieee80211_i.h',
    'rte_ieee80211_radiotap.h',
    'rte_ieee80211regulatory.h',
    'rte_mac80211.h',
    'rte_nl80211.h',
    'rte_rate.h',
    'rte_sta_info.h',
    'rte_types.h',
    'rte_wifi.h')

cflags += [
'-Wno-incompatible-pointer-types',
'-Wno-unused-function',
'-Wno-unused-variable',
'-Wno-unused-but-set-variable',
'-Wno-sign-compare',
'-Wno-unused-value',
'-Wno-cast-qual',
'-Wno-comment',
'-Wno-implicit-function-declaration',
'-Wno-attributes',
'-Wno-int-conversion',
'-Wno-maybe-uninitialized'
]

deps += ['ethdev', 'net', 'timer', 'hash']
