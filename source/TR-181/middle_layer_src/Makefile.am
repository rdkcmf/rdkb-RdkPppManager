################################################################################
# /*
#  * If not stated otherwise in this file or this component's LICENSE file the
#  * following copyright and licenses apply:
#  *
#  * Copyright 2020 Sky
#  *
#  * Licensed under the Apache License, Version 2.0 (the "License");
#  * you may not use this file except in compliance with the License.
#  * You may obtain a copy of the License at
#  *
#  *     http://www.apache.org/licenses/LICENSE-2.0
#  *
#  * Unless required by applicable law or agreed to in writing, software
#  * distributed under the License is distributed on an "AS IS" BASIS,
#  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  * See the License for the specific language governing permissions and
#  * limitations under the License.
#  */
################################################################################

AM_CFLAGS = -D_ANSC_LINUX
AM_CFLAGS += -D_ANSC_USER
AM_LDFLAGS = -lccsp_common

AM_CPPFLAGS = -Wall -Werror
ACLOCAL_AMFLAGS = -I m4
hardware_platform = i686-linux-gnu

noinst_LTLIBRARIES = libpppmanager_middle_layer_src.la
libpppmanager_middle_layer_src_la_CPPFLAGS = -I$(top_srcdir)/source/TR-181/include -I$(top_srcdir)/source/TR-181/middle_layer_src -I$(top_srcdir)/source/PppManager/ -I$(top_srcdir)/../CcspCommonLibrary/source/ccsp/include

libpppmanager_middle_layer_src_la_SOURCES = pppmgr_dml_plugin_main_apis.c pppmgr_dml_plugin_main.c pppmgr_dml_utils.c pppmgr_dml.c pppmgr_dml_ppp_apis.c pppmgr_dml_apis_bus_utils.c
libpppmanager_middle_layer_src_la_LDFLAGS = -lccsp_common -lsyscfg -lsysevent -lrdkloggers -lhal_platform $(DBUS_LIBS) $(SYSTEMD_LDFLAGS) 


