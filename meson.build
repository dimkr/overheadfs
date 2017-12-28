# This file is part of overheadfs.
#
# Copyright 2017 Dima Krasner
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
# USA.

project('overheadfs', 'c', version: '0.1', license: 'GPLv2')

api_level = 30
fuse = dependency('fuse3', required: false)
if not fuse.found()
	fuse = dependency('fuse')
	api_level = 26
endif

overheadfs = executable('overheadfs',
                        'overheadfs.c',
                        dependencies: [fuse, meson.get_compiler('c').find_library('dl')],
                        c_args: ['-D_GNU_SOURCE', '-DFUSE_USE_VERSION=@0@'.format(api_level)],
                        install: true,
                        install_dir: get_option('sbindir'))

install_man('overheadfs.8')

install_data('README', 'AUTHORS', 'COPYING',
             install_dir: join_paths(get_option('datadir'), 'doc', 'overheadfs'))
