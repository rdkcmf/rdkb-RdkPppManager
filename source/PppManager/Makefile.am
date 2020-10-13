###########################################################################
# If not stated otherwise in this file or this component's LICENSE file the
# following copyright and licenses apply:
#
# Copyright 2020 Sky
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
###########################################################################
AM_CFLAGS = -g
AM_CFLAGS = -D_ANSC_LINUX
AM_CFLAGS += -D_ANSC_USER
AM_LDFLAGS = -lccsp_common
CFLAGS += -D_USE_NM_MSG_SOCK

AM_LDFLAGS += -lsysevent -lulog
AM_CPPFLAGS = -Wall -Werror
ACLOCAL_AMFLAGS = -I m4
hardware_platform = i686-linux-gnu
bin_PROGRAMS = pppmanager
pppmanager_CPPFLAGS = -I$(top_srcdir)/source/TR-181/include                   \
        -I$(top_srcdir)/../hal/include                                                \
        -I$(top_srcdir)/../CcspCommonLibrary/source/cosa/include/                  \
        -I$(top_srcdir)/../CcspCommonLibrary/source/ccsp/components/include/       \
        -I$(top_srcdir)/source/TR-181/middle_layer_src $(CPPFLAGS)

pppmanager_DEPENDENCIES= \
    $(EXTRA_DEPENDENCIES) \
    ${top_builddir}/source/TR-181/middle_layer_src/libpppmanager_middle_layer_src.la 

pppmanager_CFLAGS = $(SYSTEMD_CFLAGS) $(NONROOT_CFLAGS)
pppmanager_SOURCES = pppmgr_ssp_action.c pppmgr_ssp_main.c pppmgr_ssp_messagebus_interface.c pppmgr_ipc.c pppmgr_mgr.c
pppmanager_LDFLAGS = -lccsp_common -ldl $(SYSTEMD_LDFLAGS) -lrdkloggers -lhal_platform -lnanomsg
pppmanager_LDADD =  $(pppmanager_DEPENDENCIES)

