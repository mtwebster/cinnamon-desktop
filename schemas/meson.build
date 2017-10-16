desktop_gschemas = [
  'a11y.applications',
  'a11y.keyboard',
  'a11y.magnifier',
  'a11y.mouse',
  'background',
  'default-applications',
  'input-sources',
  'interface',
  'keybindings.media-keys',
  'keybindings.wm',
  'keybindings',
  'lockdown',
  'media-handling',
  'notifications',
  'privacy',
  'screensaver',
  'session',
  'sound',
  'thumbnail-cache',
  'thumbnailers',
  'wm.preferences',
]

foreach schema : desktop_gschemas
  configure_file = configure_file(
    input : 'org.cinnamon.desktop.' + schema + '.gschema.xml' + '.in.in',
    output: 'org.cinnamon.desktop.' + schema + '.gschema.xml',
    configuration : conf,
    install : true,
    install_dir : join_paths(get_option('datadir'), 'glib-2.0', 'schemas'),
  )
endforeach
