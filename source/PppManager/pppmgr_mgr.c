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
/*------------------Include file---------------------------*/
#include "pppmgr_ssp_global.h"

/*-------------------declarations--------------------*/
int       sysevent_fd = -1;
token_t   sysevent_token;

/*-------------------Extern declarations--------------------*/
extern int PppManager_StartIpcServer();

/* DmlPppSyseventInit() */
static int DmlPppSyseventInit( void )
{
    char sysevent_ip[] = "127.0.0.1";
    char sysevent_name[] = "pppmgr";

    sysevent_fd =  sysevent_open( sysevent_ip, SE_SERVER_WELL_KNOWN_PORT, SE_VERSION, sysevent_name, &sysevent_token );

    if ( sysevent_fd < 0 ){
        return -1;
    }

    return 0;
}

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

    // Initialize sysevent
    if ( DmlPppSyseventInit( ) < 0 )
    {
        return ANSC_STATUS_FAILURE;
    }

    return ANSC_STATUS_SUCCESS;

}

