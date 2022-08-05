api_version = '0.1'

vala_rt_sources = [
  'vala-rt.c',
  'backend_direct.c',
  'backend_separate.c',
  'backend_section.c',
  'copied.c'
]

vala_rt_headers = [
  'vala-rt.h',
]

version_split = meson.project_version().split('.')
MAJOR_VERSION = version_split[0]
MINOR_VERSION = version_split[1]
MICRO_VERSION = version_split[2]

version_conf = configuration_data()
version_conf.set('VERSION', meson.project_version())
version_conf.set('MAJOR_VERSION', MAJOR_VERSION)
version_conf.set('MINOR_VERSION', MINOR_VERSION)
version_conf.set('MICRO_VERSION', MICRO_VERSION)

configure_file(
  input: 'vala_rt-version.h.in',
  output: 'vala_rt-version.h',
  configuration: version_conf,
  install: true,
  install_dir: join_paths(get_option('includedir'), 'vala-rt')
)

vala_rt_deps = [
  dependency('libunwind'),
  dependency('libdw')
]

vala_rt_lib = static_library('vala-rt-' + api_version,
  vala_rt_sources,
  dependencies: vala_rt_deps,
  install: true,
)

install_headers(vala_rt_headers, subdir: 'vala-rt')

pkg = import('pkgconfig')

pkg.generate(
  description: 'A static library for doing stuff',
    libraries: vala_rt_lib,
         name: 'vala-rt',
     filebase: 'vala-rt-' + api_version,
      version: meson.project_version(),
      requires: ['libunwind', 'libdw'],
      subdirs: 'vala-rt',
  install_dir: join_paths(get_option('libdir'), 'pkgconfig')
)
