project('vala-rt', 'c', 'vala',
          version: '0.1.0',
    meson_version: '>= 0.59.0',
  default_options: [ 'warning_level=3',
                     'werror=false',
                     'c_std=gnu11',
                   ],
)



config_h = configuration_data()
config_h.set_quoted('PACKAGE_VERSION', meson.project_version())
configure_file(
  output: 'vala_rt-config.h',
  configuration: config_h,
)
add_project_arguments([
  '-I' + meson.project_build_root(),
  '-fno-omit-frame-pointer',
  '-g3',
  '-pedantic'
], language: 'c')


subdir('src')
