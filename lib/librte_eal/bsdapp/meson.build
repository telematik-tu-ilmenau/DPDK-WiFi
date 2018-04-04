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

subdir('eal')
kmods = ['contigmem', 'nic_uio']

# for building kernel modules, we use kernel build system using make, as
# with Linux. We have a skeleton BSDmakefile, which pulls many of its
# values from the environment. Each module only has a single source file
# right now, which allows us to simplify things. We pull in the source files
# from the individual meson.build files, and then use a custom target to call
# make, passing in the values as environmental parameters.
kmod_cflags = ['-I' + meson.build_root(),
		'-I' + join_paths(meson.source_root(), 'config'),
		'-include rte_config.h']
foreach k:kmods
	subdir(k)
	custom_target(k,
		input: [files('BSDmakefile.meson'), sources],
		output: k + '.ko',
		command: ['make', '-f', '@INPUT0@',
			'KMOD_SRC=@INPUT1@',
			'KMOD=' + k,
			'VPATH=' + join_paths(meson.current_source_dir(), k),
			'KMOD_CFLAGS=' + ' '.join(kmod_cflags)],
		build_by_default: get_option('enable_kmods'))
endforeach
