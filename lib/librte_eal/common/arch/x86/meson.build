#   BSD LICENSE
#
#   Copyright(c) 2017 Intel Corporation.
#   All rights reserved.
#
#   Redistribution and use in source and binary forms, with or without
#   modification, are permitted provided that the following conditions
#   are met:
#
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in
#       the documentation and/or other materials provided with the
#       distribution.
#     * Neither the name of Intel Corporation nor the names of its
#       contributors may be used to endorse or promote products derived
#       from this software without specific prior written permission.
#
#   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
#   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
#   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
#   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
#   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
#   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
#   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
#   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
#   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

eal_common_arch_sources = files('rte_spinlock.c', 'rte_cpuflags.c',
	'rte_cycles.c', 'rte_memcpy.c', 'rte_memcpy_sse.c')
eal_common_arch_objs = []

# Disabled for APU2C4, use SSE implementation

# if dpdk_conf.has('RTE_MACHINE_CPUFLAG_AVX512F')
# 	eal_common_arch_sources += files('rte_memcpy_avx512f.c',
# 			'rte_memcpy_avx2.c')
# else
# 	# no avx512f instruction set guaranteed
# 	# check if compiler supports
# 	if cc.has_argument('-mavx512f')
# 		avx512_tmplib = static_library('memcpy_avx512_tmp',
# 				'rte_memcpy_avx512f.c',
# 				c_args: ['-mavx512f',
# 					'-DRTE_MACHINE_CPUFLAG_AVX512F'],
# 				include_directories: eal_inc)
# 		eal_common_arch_objs += avx512_tmplib.extract_objects(
# 				'rte_memcpy_avx512f.c')
# 	endif
# 	# check for mandatory AVX2 support
# 	if dpdk_conf.has('RTE_MACHINE_CPUFLAG_AVX2')
# 		eal_common_arch_sources += files('rte_memcpy_avx2.c')
# 	elif cc.has_argument('-mavx2') != ''
# 		avx2_tmplib = static_library('memcpy_avx2_tmp',
# 				'rte_memcpy_avx2.c',
# 				c_args: '-mavx2',
# 				include_directories: eal_inc)
# 		eal_common_arch_objs += avx2_tmplib.extract_objects(
# 				'rte_memcpy_avx2.c')
# 	endif
# endif
