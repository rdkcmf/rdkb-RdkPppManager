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
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*------------------Include file---------------------------*/
#include "pppmgr_ssp_global.h"

/*-------------------Extern declarations--------------------*/
extern int PppManager_StartIpcServer();

ANSC_STATUS PppMgr_Init()
{
    /* Start IPC server to receive events from ppp client */
    if( PppMgr_StartIpcServer() == ANSC_STATUS_FAILURE )
    {
        CcspTraceInfo(("%s %d - IPC server start failed!\n", __FUNCTION__, __LINE__ ));

        return ANSC_STATUS_FAILURE;
    }
    CcspTraceInfo(("%s %d - IPC server started successfully!\n", __FUNCTION__, __LINE__ ));

    // Initialise syscfg
    if (syscfg_init() < 0)
    {
        CcspTraceError(("failed to initialise syscfg"));
        return ANSC_STATUS_FAILURE;
    }

    return ANSC_STATUS_SUCCESS;

}

