# Meson build file

# https://github.com/linuxmint/cinnamon-desktop
project('cinnamon-desktop', 'c', version : '3.5.0',
  meson_version : '>=0.40.0'
)

# Before making a release, the LT_VERSION string should be modified.
# The string is of the form C.R.A.
# - If interfaces have been changed or added, but binary compatibility has
#   been preserved, change to C+1.0.A+1
# - If binary compatibility has been broken (eg removed or changed interfaces)
#   change to C+1.0.0
# - If the interface is the same as the previous version, change to C.R+1.A
LT_VERSION='4.0.0'

################################################################################
conf = configuration_data()

pkgconfig = import('pkgconfig')
i18n      = import('i18n')
gnome     = import('gnome')

cc                = meson.get_compiler('c')
prefix            = get_option('prefix')
buildtype         = get_option('buildtype')
deprecation_flags = get_option('deprecation_flags')

conf.set_quoted('PACKAGE_VERSION', meson.project_version())
conf.set('datadir', get_option('datadir'))

if deprecation_flags
  add_global_arguments('-Wno-deprecated-declarations', language : 'c')
endif

################################################################################

math    = cc.find_library('m')

accserv = dependency('accountsservice')
gdk_pixb= dependency('gdk-pixbuf-2.0', version : '>=2.22.0')
gio     = dependency('gio-2.0',  version : '>=2.37.3')
glib    = dependency('glib-2.0', version : '>=2.37.3')
gtk     = dependency('gtk+-3.0', version : '>=3.3.16')

x11     = dependency('x11')
xext    = dependency('xext',     version : '>=1.1')
xkbconf = dependency('xkeyboard-config')
xkbfile = dependency('xkbfile')
xrandr  = dependency('xrandr',   version : '>=1.3')

cinnamon_deps = [
  accserv,
  gdk_pixb,
  gio,
  glib,
  gtk,
  math,
  x11,
  xext,
  xkbconf,
  xkbfile,
  xrandr,
]

# CVC dependencies
gobject = dependency('gobject-2.0')
pulse   = dependency('libpulse')
pulsegl = dependency('libpulse-mainloop-glib')

cvc_deps = cinnamon_deps + [
  pulse,
  pulsegl,
  gobject,
]

################################################################################
# Translation
# gettext_package = 'cinnamon-desktop'
gettext_package = meson.project_name()

conf.set('HAVE_GETTEXT',  true)
conf.set('HAVE_LOCALE_H', cc.has_header('locale.h'))
conf.set('ENABLE_NLS',    cc.has_header('libintl.h'))

localedir = join_paths([ get_option('prefix'), get_option('localedir') ])
conf.set_quoted('GETTEXT_PACKAGE',gettext_package)
conf.set_quoted('GNOMELOCALEDIR', localedir)
conf.set_quoted('LOCALE_DIR',     localedir)
conf.set_quoted('LOCALEDIR',      localedir)

################################################################################
# XKB_BASE=$($PKG_CONFIG --variable xkb_base xkeyboard-config)

rootInclude = include_directories('.')

configure_file(
  input : 'config.h.meson.in',
  output: 'config.h',
  configuration : conf
)

po_subdir = join_paths(meson.current_source_dir(), 'po')

subdir('files')
subdir('libcinnamon-desktop')
subdir('libcvc')
subdir('po')
subdir('schemas')


message('         prefix:                       ' + get_option('prefix'))
message('         exec_prefix:                  ' + get_option('prefix'))
message('         libdir:                       ' + get_option('libdir'))
message('         bindir:                       ' + get_option('bindir'))
message('         sbindir:                      ' + get_option('sbindir'))
message('         sysconfdir:                   ' + get_option('sysconfdir'))
message('         localstatedir:                ' + get_option('localstatedir'))
message('         datadir:                      ' + get_option('datadir'))
message('         source code location:         ' + meson.source_root())
message('         compiler:                     ' + cc.get_id())
message('         debugging support:            ' + buildtype)
# message('         cflags:                       ' + get_option('CFLAGS'))
message('         Use *_DISABLE_DEPRECATED:     ' + (deprecation_flags ? 'no' : 'yes'))
