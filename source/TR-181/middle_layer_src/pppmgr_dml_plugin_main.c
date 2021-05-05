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

#include "pppmgr_dml_plugin_main.h"
#include "pppmgr_dml_plugin_main_apis.h"
#include "pppmgr_dml.h"
#include "pppmgr_dml_apis.h"

#define THIS_PLUGIN_VERSION                         1

void *                                g_pDslhDmlAgent;
COSAGetParamValueByPathNameProc       g_GetParamValueByPathNameProc;
COSASetParamValueByPathNameProc       g_SetParamValueByPathNameProc;
COSAGetParamValueStringProc           g_GetParamValueString;
COSAGetParamValueUlongProc            g_GetParamValueUlong;
COSAGetParamValueIntProc              g_GetParamValueInt;
COSAGetParamValueBoolProc             g_GetParamValueBool;
COSASetParamValueStringProc           g_SetParamValueString;
COSASetParamValueUlongProc            g_SetParamValueUlong;
COSASetParamValueIntProc              g_SetParamValueInt;
COSASetParamValueBoolProc             g_SetParamValueBool;
COSAGetInstanceNumbersProc            g_GetInstanceNumbers;
COSAValidateHierarchyInterfaceProc    g_ValidateInterface;
COSAGetHandleProc                     g_GetRegistryRootFolder;
COSAGetInstanceNumberByIndexProc      g_GetInstanceNumberByIndex;
COSAGetInterfaceByNameProc            g_GetInterfaceByName;
COSAGetHandleProc                     g_GetMessageBusHandle;
COSAGetSubsystemPrefixProc            g_GetSubsystemPrefix;
PCCSP_CCD_INTERFACE                   g_pPnmCcdIf;
ANSC_HANDLE                           g_MessageBusHandle;
char*                                 g_SubsystemPrefix;
COSARegisterCallBackAfterInitDmlProc  g_RegisterCallBackAfterInitDml;
COSARepopulateTableProc               g_RepopulateTable;
PBACKEND_MANAGER_OBJECT               g_pBEManager;
extern ANSC_HANDLE                    g_MessageBusHandle_Irep;
extern char                           g_SubSysPrefix_Irep[32];

int PppManagerDmlInit
    (
        ULONG                       uMaxVersionSupported,
        void*                       hPlugInfo         /* PCOSA_PLUGIN_INFO passed in by the caller */
    )
{
    PCOSA_PLUGIN_INFO               pPlugInfo  = (PCOSA_PLUGIN_INFO)hPlugInfo;

    COSAGetParamValueByPathNameProc pGetParamValueByPathNameProc = (COSAGetParamValueByPathNameProc)NULL;
    COSASetParamValueByPathNameProc pSetParamValueByPathNameProc = (COSASetParamValueByPathNameProc)NULL;
    COSAGetParamValueStringProc     pGetStringProc              = (COSAGetParamValueStringProc       )NULL;
    COSAGetParamValueUlongProc      pGetParamValueUlongProc     = (COSAGetParamValueUlongProc        )NULL;
    COSAGetParamValueIntProc        pGetParamValueIntProc       = (COSAGetParamValueIntProc          )NULL;
    COSAGetParamValueBoolProc       pGetParamValueBoolProc      = (COSAGetParamValueBoolProc         )NULL;
    COSASetParamValueStringProc     pSetStringProc              = (COSASetParamValueStringProc       )NULL;
    COSASetParamValueUlongProc      pSetParamValueUlongProc     = (COSASetParamValueUlongProc        )NULL;
    COSASetParamValueIntProc        pSetParamValueIntProc       = (COSASetParamValueIntProc          )NULL;
    COSASetParamValueBoolProc       pSetParamValueBoolProc      = (COSASetParamValueBoolProc         )NULL;
    COSAGetInstanceNumbersProc      pGetInstanceNumbersProc     = (COSAGetInstanceNumbersProc        )NULL;

    COSAGetCommonHandleProc         pGetCHProc                  = (COSAGetCommonHandleProc           )NULL;
    COSAValidateHierarchyInterfaceProc 
                                    pValInterfaceProc           = (COSAValidateHierarchyInterfaceProc)NULL;
    COSAGetHandleProc               pGetRegistryRootFolder      = (COSAGetHandleProc                 )NULL;
    COSAGetInstanceNumberByIndexProc
                                    pGetInsNumberByIndexProc    = (COSAGetInstanceNumberByIndexProc  )NULL;
    COSAGetHandleProc               pGetMessageBusHandleProc    = (COSAGetHandleProc                 )NULL;
    COSAGetInterfaceByNameProc      pGetInterfaceByNameProc     = (COSAGetInterfaceByNameProc        )NULL;
    ULONG                           ret                         = 0;
    int        rc = -1;

    if ( uMaxVersionSupported < THIS_PLUGIN_VERSION )
    {
      /* this version is not supported */
        return -1;
    }   
    
    pPlugInfo->uPluginVersion       = THIS_PLUGIN_VERSION;

    g_pDslhDmlAgent                 = pPlugInfo->hDmlAgent;
    pGetParamValueByPathNameProc = (COSAGetParamValueByPathNameProc)pPlugInfo->AcquireFunction("COSAGetParamValueByPathName");
    if( pGetParamValueByPathNameProc != NULL)
    {
        g_GetParamValueByPathNameProc = pGetParamValueByPathNameProc;   
    }
    else
    {
        goto EXIT;
    }
    pSetParamValueByPathNameProc = (COSASetParamValueByPathNameProc)pPlugInfo->AcquireFunction("COSASetParamValueByPathName");

    if( pSetParamValueByPathNameProc != NULL)
    {
        g_SetParamValueByPathNameProc = pSetParamValueByPathNameProc;   
    }
    else
    {
        goto EXIT;
    }
    pGetStringProc = (COSAGetParamValueStringProc)pPlugInfo->AcquireFunction("COSAGetParamValueString");

    if( pGetStringProc != NULL)
    {
        g_GetParamValueString = pGetStringProc;   
    }
    else
    {
        goto EXIT;
    }
    pGetParamValueUlongProc = (COSAGetParamValueUlongProc)pPlugInfo->AcquireFunction("COSAGetParamValueUlong");

    if( pGetParamValueUlongProc != NULL)
    {
        g_GetParamValueUlong = pGetParamValueUlongProc;   
    }
    else
    {
        goto EXIT;
    }

    pGetParamValueIntProc = (COSAGetParamValueUlongProc)pPlugInfo->AcquireFunction("COSAGetParamValueInt");

    if( pGetParamValueIntProc != NULL)
    {
        g_GetParamValueInt = pGetParamValueIntProc;   
    }
    else
    {
        goto EXIT;
    }
    pGetParamValueBoolProc = (COSAGetParamValueBoolProc)pPlugInfo->AcquireFunction("COSAGetParamValueBool");

    if( pGetParamValueBoolProc != NULL)
    {
        g_GetParamValueBool = pGetParamValueBoolProc;   
    }
    else
    {
        goto EXIT;
    }
    pSetStringProc = (COSASetParamValueStringProc)pPlugInfo->AcquireFunction("COSASetParamValueString");

    if( pSetStringProc != NULL)
    {
        g_SetParamValueString = pSetStringProc;   
    }
    else
    {
        goto EXIT;
    }
    pSetParamValueUlongProc = (COSASetParamValueUlongProc)pPlugInfo->AcquireFunction("COSASetParamValueUlong");

    if( pSetParamValueUlongProc != NULL)
    {
        g_SetParamValueUlong = pSetParamValueUlongProc;   
    }
    else
    {
        goto EXIT;
    }

    pSetParamValueIntProc = (COSASetParamValueIntProc)pPlugInfo->AcquireFunction("COSASetParamValueInt");

    if( pSetParamValueIntProc != NULL)
    {
        g_SetParamValueInt = pSetParamValueIntProc;   
    }
    else
    {
        goto EXIT;
    }
    pSetParamValueBoolProc = (COSASetParamValueBoolProc)pPlugInfo->AcquireFunction("COSASetParamValueBool");

    if( pSetParamValueBoolProc != NULL)
    {
        g_SetParamValueBool = pSetParamValueBoolProc;   
    }
    else
    {
        goto EXIT;
    }
    pGetInstanceNumbersProc = (COSAGetInstanceNumbersProc)pPlugInfo->AcquireFunction("COSAGetInstanceNumbers");

    if( pGetInstanceNumbersProc != NULL)
    {
        g_GetInstanceNumbers = pGetInstanceNumbersProc;   
    }
    else
    {
        goto EXIT;
    }
    pValInterfaceProc = (COSAValidateHierarchyInterfaceProc)pPlugInfo->AcquireFunction("COSAValidateHierarchyInterface");

    if ( pValInterfaceProc )
    {
        g_ValidateInterface = pValInterfaceProc;
    }
    else
    {
        goto EXIT;
    }
    pGetRegistryRootFolder = (COSAGetHandleProc)pPlugInfo->AcquireFunction("COSAGetRegistryRootFolder");

    if ( pGetRegistryRootFolder != NULL )
    {
        g_GetRegistryRootFolder = pGetRegistryRootFolder;
    }
    else
    {
        CcspTraceInfo(("!!! haha, catcha !!!\n"));
        goto EXIT;
    }
    pGetInsNumberByIndexProc = (COSAGetInstanceNumberByIndexProc)pPlugInfo->AcquireFunction("COSAGetInstanceNumberByIndex");

    if ( pGetInsNumberByIndexProc != NULL )
    {
        g_GetInstanceNumberByIndex = pGetInsNumberByIndexProc;
    }
    else
    {
        goto EXIT;
    }
    pGetInterfaceByNameProc = (COSAGetInterfaceByNameProc)pPlugInfo->AcquireFunction("COSAGetInterfaceByName");

    if ( pGetInterfaceByNameProc != NULL )
    {
        g_GetInterfaceByName = pGetInterfaceByNameProc;
    }
    else
    {
        goto EXIT;
    }
    g_pPnmCcdIf = g_GetInterfaceByName(g_pDslhDmlAgent, CCSP_CCD_INTERFACE_NAME);

    if ( !g_pPnmCcdIf )
    {
        CcspTraceError(("g_pPnmCcdIf is NULL !\n"));

        goto EXIT;
    }
    g_RegisterCallBackAfterInitDml = (COSARegisterCallBackAfterInitDmlProc)pPlugInfo->AcquireFunction("COSARegisterCallBackAfterInitDml");

    if ( !g_RegisterCallBackAfterInitDml )
    {
        goto EXIT;
    }
    g_RepopulateTable = (COSARepopulateTableProc)pPlugInfo->AcquireFunction("COSARepopulateTable");

    if ( !g_RepopulateTable )
    {
        goto EXIT;
    }
    /* Get Message Bus Handle */
    g_GetMessageBusHandle = (PFN_CCSPCCDM_APPLY_CHANGES)pPlugInfo->AcquireFunction("COSAGetMessageBusHandle");
    if ( g_GetMessageBusHandle == NULL )
    {
        goto EXIT;
    }
    g_MessageBusHandle = (ANSC_HANDLE)g_GetMessageBusHandle(g_pDslhDmlAgent);
    if ( g_MessageBusHandle == NULL )
    {
        goto EXIT;
    }
    g_MessageBusHandle_Irep = g_MessageBusHandle;
    
    /* Get Subsystem prefix */
    g_GetSubsystemPrefix = (COSAGetSubsystemPrefixProc)pPlugInfo->AcquireFunction("COSAGetSubsystemPrefix");
    if ( g_GetSubsystemPrefix != NULL )
    {
        char*   tmpSubsystemPrefix;
        
        if ( tmpSubsystemPrefix = g_GetSubsystemPrefix(g_pDslhDmlAgent) )
        {
            AnscCopyString(g_SubSysPrefix_Irep, tmpSubsystemPrefix);
        }

        /* retrieve the subsystem prefix */
        g_SubsystemPrefix = g_GetSubsystemPrefix(g_pDslhDmlAgent);
    }

    /* register the back-end apis for the data model */
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "PPP_GetParamBoolValue",  PPP_GetParamBoolValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "PPP_GetParamIntValue",  PPP_GetParamIntValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "PPP_GetParamUlongValue",  PPP_GetParamUlongValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "PPP_GetParamStringValue",  PPP_GetParamStringValue);

    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "Interface_GetEntryCount",  Interface_GetEntryCount);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "Interface_GetEntry",  Interface_GetEntry);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "Interface_AddEntry",  Interface_AddEntry);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "Interface_DelEntry",  Interface_DelEntry);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "Interface_GetParamBoolValue",  Interface_GetParamBoolValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "Interface_GetParamUlongValue",  Interface_GetParamUlongValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "Interface_GetParamStringValue",  Interface_GetParamStringValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "Interface_SetParamBoolValue",  Interface_SetParamBoolValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "Interface_SetParamIntValue",  Interface_SetParamIntValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "Interface_SetParamUlongValue",  Interface_SetParamUlongValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "Interface_SetParamStringValue",  Interface_SetParamStringValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "Interface_Validate",  Interface_Validate);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "Interface_Commit",  Interface_Commit);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "Interface_Rollback",  Interface_Rollback);

    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "PPPoE_GetParamBoolValue",  PPPoE_GetParamBoolValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "PPPoE_GetParamIntValue",  PPPoE_GetParamIntValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "PPPoE_GetParamUlongValue",  PPPoE_GetParamUlongValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "PPPoE_GetParamStringValue",  PPPoE_GetParamStringValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "PPPoE_SetParamBoolValue",  PPPoE_SetParamBoolValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "PPPoE_SetParamIntValue",  PPPoE_SetParamIntValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "PPPoE_SetParamUlongValue",  PPPoE_SetParamUlongValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "PPPoE_SetParamStringValue",  PPPoE_SetParamStringValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "PPPoE_Validate",  PPPoE_Validate);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "PPPoE_Commit",  PPPoE_Commit);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "PPPoE_Rollback",  PPPoE_Rollback);

    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "IPCP_GetParamBoolValue",  IPCP_GetParamBoolValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "IPCP_GetParamIntValue",  IPCP_GetParamIntValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "IPCP_GetParamUlongValue",  IPCP_GetParamUlongValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "IPCP_GetParamStringValue",  IPCP_GetParamStringValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "IPCP_SetParamBoolValue",  IPCP_SetParamBoolValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "IPCP_SetParamIntValue",  IPCP_SetParamIntValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "IPCP_SetParamUlongValue",  IPCP_SetParamUlongValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "IPCP_SetParamStringValue",  IPCP_SetParamStringValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "IPCP_Validate",  IPCP_Validate);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "IPCP_Commit",  IPCP_Commit);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "IPCP_Rollback",  IPCP_Rollback);

    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "IPv6CP_GetParamStringValue",  IPv6CP_GetParamStringValue);

    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "Stats_GetParamUlongValue",  Stats_GetParamUlongValue);

    /* Create backend framework */
    g_pBEManager = (PBACKEND_MANAGER_OBJECT)BackEndManagerCreate();

    if ( g_pBEManager && g_pBEManager->Initialize )
    {
        g_pBEManager->hPluginInfo = pPlugInfo;

        g_pBEManager->Initialize   ((ANSC_HANDLE)g_pBEManager);
    }

    return  0;
EXIT:

    return -1;
}
