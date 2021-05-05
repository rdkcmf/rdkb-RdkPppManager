/*
 * Copyright (C) 2020 Sky
 * --------------------------------------------------------------------------
 * THIS SOFTWARE CONTRIBUTION IS PROVIDED ON BEHALF OF SKY PLC.
 * BY THE CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING,
 * BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED
 * ******************************************************************
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
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


#ifndef  _PPPMGR_SSP_INTERNAL_H_
#define  _PPPMGR_SSP_INTERNAL_H_

#include "pppmgr_dml_plugin_main_apis.h"

#define  RDK_COMPONENT_ID_PPP_MANAGER                             "com.cisco.spvtg.ccsp.pppmanager"
#define  RDK_COMPONENT_NAME_PPP_MANAGER                           "com.cisco.spvtg.ccsp.pppmanager"
#define  RDK_COMPONENT_VERSION_PPP_MANAGER                        1
#define  RDK_COMPONENT_PATH_PPP_MANAGER                           "/com/cisco/spvtg/ccsp/pppmanager"

#define  RDK_COMMON_COMPONENT_HEALTH_Red                   1
#define  RDK_COMMON_COMPONENT_HEALTH_Yellow                2
#define  RDK_COMMON_COMPONENT_HEALTH_Green                 3

#define  RDK_COMMON_COMPONENT_STATE_Initializing           1
#define  RDK_COMMON_COMPONENT_STATE_Running                2
#define  RDK_COMMON_COMPONENT_STATE_Blocked                3
#define  RDK_COMMON_COMPONENT_STATE_Paused                 3

typedef  struct
_COMPONENT_COMMON_PPP_MANAGER 
{
    char*                           Name;
    ULONG                           Version;
    char*                           Author;
    ULONG                           Health;
    ULONG                           State;

    BOOL                            LogEnable;
    ULONG                           LogLevel;

    ULONG                           MemMaxUsage;
    ULONG                           MemMinUsage;
    ULONG                           MemConsumed;

}
COMPONENT_COMMON_PPP_MANAGER, *PCOMPONENT_COMMON_PPP_MANAGER;

#define ComponentCommonDmInit(component_com_pppmanager)                                          \
        {                                                                                             \
            AnscZeroMemory(component_com_pppmanager, sizeof(COMPONENT_COMMON_PPP_MANAGER));      \
            component_com_pppmanager->Name        = NULL;                                        \
            component_com_pppmanager->Version     = 1;                                           \
            component_com_pppmanager->Author      = NULL;                                        \
            component_com_pppmanager->Health      = RDK_COMMON_COMPONENT_HEALTH_Red;            \
            component_com_pppmanager->State       = RDK_COMMON_COMPONENT_STATE_Running;         \
            if(g_iTraceLevel >= CCSP_TRACE_LEVEL_EMERGENCY)                                           \
                component_com_pppmanager->LogLevel = (ULONG) g_iTraceLevel;                      \
            component_com_pppmanager->LogEnable   = TRUE;                                        \
            component_com_pppmanager->MemMaxUsage = 0;                                           \
            component_com_pppmanager->MemMinUsage = 0;                                           \
            component_com_pppmanager->MemConsumed = 0;                                           \
        }


int PppManagerDmlInit
(
    ULONG                       uMaxVersionSupported,
    void*                       hPlugInfo         /* PCOSA_PLUGIN_INFO passed in by the caller */
);


ANSC_STATUS
ssp_create
(
);

ANSC_STATUS
ssp_engage
(
);

ANSC_STATUS
ssp_cancel
(
);

char*
ssp_CcdIfGetComponentName
    (
        ANSC_HANDLE                     hThisObject
    );

ULONG
ssp_CcdIfGetComponentVersion
    (
        ANSC_HANDLE                     hThisObject
    );

char*
ssp_CcdIfGetComponentAuthor
    (
        ANSC_HANDLE                     hThisObject
    );

ULONG
ssp_CcdIfGetComponentHealth
    (
        ANSC_HANDLE                     hThisObject
    );

ULONG
ssp_CcdIfGetComponentState
    (
        ANSC_HANDLE                     hThisObject
    );

BOOL
ssp_CcdIfGetLoggingEnabled
    (
        ANSC_HANDLE                     hThisObject
    );

ANSC_STATUS
ssp_CcdIfSetLoggingEnabled
    (
        ANSC_HANDLE                     hThisObject,
        BOOL                            bEnabled
    );

ULONG
ssp_CcdIfGetLoggingLevel
    (
        ANSC_HANDLE                     hThisObject
    );

ANSC_STATUS
ssp_CcdIfSetLoggingLevel
    (
        ANSC_HANDLE                     hThisObject,
        ULONG                           LogLevel
    );


ULONG
ssp_CcdIfGetMemMaxUsage
    (
        ANSC_HANDLE                     hThisObject
    );

ULONG
ssp_CcdIfGetMemMinUsage
    (
        ANSC_HANDLE                     hThisObject
    );

ULONG
ssp_CcdIfGetMemConsumed
    (
        ANSC_HANDLE                     hThisObject
    );

ANSC_STATUS
ssp_CcdIfApplyChanges
    (
        ANSC_HANDLE                     hThisObject
    );


#endif
