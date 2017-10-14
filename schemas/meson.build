desktop_gschemas = [
  'org.cinnamon.desktop.default-applications.gschema.xml',
  'org.cinnamon.desktop.interface.gschema.xml',
  'org.cinnamon.desktop.lockdown.gschema.xml',
  'org.cinnamon.desktop.sound.gschema.xml',
  'org.cinnamon.desktop.thumbnail-cache.gschema.xml',
  'org.cinnamon.desktop.a11y.keyboard.gschema.xml',
  'org.cinnamon.desktop.a11y.applications.gschema.xml',
  'org.cinnamon.desktop.a11y.magnifier.gschema.xml',
  'org.cinnamon.desktop.a11y.mouse.gschema.xml',
  'org.cinnamon.desktop.thumbnailers.gschema.xml',
  'org.cinnamon.desktop.session.gschema.xml',
  'org.cinnamon.desktop.background.gschema.xml',
  'org.cinnamon.desktop.media-handling.gschema.xml',
  'org.cinnamon.desktop.screensaver.gschema.xml',
  'org.cinnamon.desktop.wm.preferences.gschema.xml',
  'org.cinnamon.desktop.notifications.gschema.xml',
  'org.cinnamon.desktop.input-sources.gschema.xml',
  'org.cinnamon.desktop.keybindings.gschema.xml',
  'org.cinnamon.desktop.keybindings.media-keys.gschema.xml',
  'org.cinnamon.desktop.keybindings.wm.gschema.xml',
  'org.cinnamon.desktop.privacy.gschema.xml',
]

dataConf = configuration_data()
dataConf.set('GETTEXT_PACKAGE', 'cinnamon-desktop')
dataConf.set('datadir', get_option('datadir'))

# gnome.compile_schemas()
foreach schema : desktop_gschemas
  configure_file = configure_file(
    input : schema + '.in.in',
    output: schema,
    configuration : dataConf,
    install : true,
    install_dir : join_paths(get_option('datadir'), 'glib-2.0', 'schemas'),
  )
endforeach
