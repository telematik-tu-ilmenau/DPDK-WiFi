sources = files(
  'test-ath10k.c',
)

deps = ['ethdev', 'pmd_ath10k']

dep_objs = []
foreach d:deps
	dep_objs += get_variable('dep_rte_' + d)
endforeach

link_libs = []
if get_option('default_library') == 'static'
	link_libs = dpdk_drivers
endif

executable('dpdk-test-ath10k',
	sources,
	link_whole: link_libs,
	dependencies: dep_objs,
	link_args: eal_extra_link_arg, # add -ldl for linux, -lexecinfo for BSD
	install_rpath: join_paths(get_option('prefix'), driver_install_path),
	install: true)
