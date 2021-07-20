/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2020 Sky
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/*
 * Copyright [2014] [Cisco Systems, Inc.]
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     LICENSE-2.0" target="_blank" rel="nofollow">http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*********************************************************************************

    description:

        This is the template file of ssp_messagebus_interface.h for XxxxSsp.
        You don't need to do anything here.

    ------------------------------------------------------------------------------

    revision:

        09/08/2011    initial revision.

**********************************************************************************/

#ifndef  _PPPMGR_SSP_MESSAGEBUS_INTERFACE_H_
#define  _PPPMGR_SSP_MESSAGEBUS_INTERFACE_H_

#include "ccsp_memory.h"

#define  COMMON_COMPONENT_FREERESOURCES_PRIORITY_High  1
#define  COMMON_COMPONENT_FREERESOURCES_PRIORITY_Low   2

ANSC_STATUS
ssp_Mbi_MessageBusEngage
    (
        char * component_id,
        char * config_file,
        char * path
    );

int
ssp_Mbi_Initialize
    (
        void * user_data
    );

int
ssp_Mbi_Finalize
    (
        void * user_data
    );

int
ssp_Mbi_Buscheck
    (
        void * user_data
    );

int
ssp_Mbi_FreeResources
    (
        int priority,
        void * user_data
    );

#endif
