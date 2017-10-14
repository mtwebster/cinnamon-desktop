libcinnamon_desktop_inc = [
  rootInclude,
  include_directories('libgsystem')
]

gsystem_src = [
  'libgsystem/gsystem-local-alloc.h',
  'libgsystem/gsystem-local-alloc.c',
  'libgsystem/gsystem-file-utils.h',
  'libgsystem/gsystem-file-utils.c',
  'libgsystem/libgsystem.h',
]
gsystem_lib = static_library('gsystem',
  gsystem_src,
  dependencies : cinnamon_deps,
  include_directories : libcinnamon_desktop_inc,
  install : false,
)

introspection_sources = [
  'gnome-desktop-utils.c',
  'gnome-desktop-thumbnail.c',
  'gnome-thumbnail-pixbuf-utils.c',
  'gnome-bg.c',
  'gnome-bg-crossfade.c',
  'display-name.c',
  'gnome-installer.c',
  'gnome-rr.c',
  'gnome-rr-config.c',
  'gnome-rr-output-info.c',
  'gnome-rr-labeler.c',
  'gnome-pnp-ids.c',
  'gnome-wall-clock.c',
  'gnome-xkb-info.c',
  'edid-parse.c',
]
libcinnamon_desktop_src = [
  'gnome-datetime-source.h',
  'gnome-datetime-source.c',
  'gnome-rr-private.h',
  'edid.h',
  'private.h',
] + introspection_sources

libcinnamon_desktop_hdr = [
  'cdesktop-enums.h',
  'gnome-bg-crossfade.h',
  'gnome-bg.h',
  'gnome-desktop-thumbnail.h',
  'gnome-desktop-utils.h',
  'gnome-installer.h',
  'gnome-pnp-ids.h',
  'gnome-rr-config.h',
  'gnome-rr-labeler.h',
  'gnome-rr.h',
  'gnome-wall-clock.h',
  'gnome-xkb-info.h',
]

libcinnamon_desktop = shared_library('cinnamon-desktop',
  libcinnamon_desktop_src,
  include_directories : libcinnamon_desktop_inc,
  c_args : [ '-DPNP_IDS="."', '-DXKB_BASE="/usr/share/X11/xkb"' ],
  dependencies : cinnamon_deps,
  link_with : gsystem_lib,
  install : true,
  version : LT_VERSION,
)

install_headers(
  libcinnamon_desktop_hdr,
  subdir : join_paths('cinnamon-desktop', 'libcinnamon-desktop')
)

pkgconfig.generate(
  name : 'cinnamon-desktop',
  description : 'Utility library for loading.desktop files',
  version : LT_VERSION,
  requires : ['gtk+-3.0', ],
  requires_private : ['xkbfile', ],
  libraries : libcinnamon_desktop,
  subdirs : join_paths('cinnamon-desktop'),
  variables : [ 'exec_prefix=${prefix}'],
)

# pkgconfig.generate(
#   name : 'cinnamon-desktop-uninstalled',
#   description : 'Utility library for loading.desktop files',
#   version : LT_VERSION,
#   requires : ['gtk+-3.0', ],
#   libraries : libcinnamon_desktop,
#   subdirs : join_paths('cinnamon-desktop'),
#   variables : [ 'exec_prefix=${prefix}'],
# )


# if USE_INTERNAL_PNP_IDS
install_data(
  'pnp.ids',
  install_dir : join_paths(get_option('datadir'), 'libcinnamon-desktop')
)
# endif

#TODO introspection
