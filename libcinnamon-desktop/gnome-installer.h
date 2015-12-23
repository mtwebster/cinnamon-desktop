/*
 * Copyright (C) 2012 Collabora Ltd.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * Authors: Guillaume Desmottes <guillaume.desmottes@collabora.com>
 */

#ifndef __GNOME_INSTALLER__
#define __GNOME_INSTALLER__

#include <glib.h>
#include <gio/gio.h>

typedef void (* GnomeInstallerInstallCallback) (gboolean success,
                                                gpointer user_data);

typedef void (* GnomeInstallerCheckCallback) (gboolean   success,
                                              gchar    **missing_packages,
                                              gpointer   user_data);

void gnome_installer_install_packages (const gchar                 **packages, 
                                       GnomeInstallerInstallCallback callback,
                                       gpointer                      user_data);

void gnome_installer_check_for_packages (const gchar               **packages,
                                         GnomeInstallerCheckCallback callback,
                                         gpointer                   user_data);

#endif