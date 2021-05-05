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
#include "pppmgr_ssp_internal.h"
#include "pppmgr_dml_plugin_main.h"

PCOMPONENT_COMMON_PPP_MANAGER            g_pComponentCommonPppManager      = NULL;
PCCSP_CCD_INTERFACE                      pSsdCcdIf                         = (PCCSP_CCD_INTERFACE) NULL;
PDSLH_LCB_INTERFACE                      pDslhLcbIf                        = (PDSLH_LCB_INTERFACE) NULL;
PDSLH_CPE_CONTROLLER_OBJECT              pDslhCpeController                = NULL;
extern  ANSC_HANDLE                      bus_handle;
extern char                              g_Subsystem[32];
extern  ULONG                            g_ulAllocatedSizePeak;

#define  DATAMODEL_XML_FILE           "/usr/rdk/pppmanager/RdkPppManager.xml"

ANSC_STATUS ssp_create()
{
    int rc = ANSC_STATUS_FAILURE;

    g_pComponentCommonPppManager = (PCOMPONENT_COMMON_PPP_MANAGER) AnscAllocateMemory(sizeof(COMPONENT_COMMON_PPP_MANAGER));

    if(!g_pComponentCommonPppManager)
    {
        return ANSC_STATUS_RESOURCES;
    }

    ComponentCommonDmInit(g_pComponentCommonPppManager);

    g_pComponentCommonPppManager->Name    = AnscCloneString(RDK_COMPONENT_NAME_PPP_MANAGER);
    g_pComponentCommonPppManager->Version = 1;
    g_pComponentCommonPppManager->Author  = AnscCloneString("Your Name");

    /* Create ComponentCommonDatamodel interface*/
    if (!pSsdCcdIf)
    {
        pSsdCcdIf = (PCCSP_CCD_INTERFACE) AnscAllocateMemory(sizeof(CCSP_CCD_INTERFACE));

        if ( !pSsdCcdIf )
        {
            return ANSC_STATUS_RESOURCES;
        }
        else
        {
            AnscCopyString(pSsdCcdIf->Name, CCSP_CCD_INTERFACE_NAME);

            pSsdCcdIf->InterfaceId              = CCSP_CCD_INTERFACE_ID;
            pSsdCcdIf->hOwnerContext            = NULL;
            pSsdCcdIf->Size                     = sizeof(CCSP_CCD_INTERFACE);

            pSsdCcdIf->GetComponentName         = ssp_CcdIfGetComponentName;
            pSsdCcdIf->GetComponentVersion      = ssp_CcdIfGetComponentVersion;
            pSsdCcdIf->GetComponentAuthor       = ssp_CcdIfGetComponentAuthor;
            pSsdCcdIf->GetComponentHealth       = ssp_CcdIfGetComponentHealth;
            pSsdCcdIf->GetComponentState        = ssp_CcdIfGetComponentState;
            pSsdCcdIf->GetLoggingEnabled        = ssp_CcdIfGetLoggingEnabled;
            pSsdCcdIf->SetLoggingEnabled        = ssp_CcdIfSetLoggingEnabled;
            pSsdCcdIf->GetLoggingLevel          = ssp_CcdIfGetLoggingLevel;
            pSsdCcdIf->SetLoggingLevel          = ssp_CcdIfSetLoggingLevel;
            pSsdCcdIf->GetMemMaxUsage           = ssp_CcdIfGetMemMaxUsage;
            pSsdCcdIf->GetMemMinUsage           = ssp_CcdIfGetMemMinUsage;
            pSsdCcdIf->GetMemConsumed           = ssp_CcdIfGetMemConsumed;
            pSsdCcdIf->ApplyChanges             = ssp_CcdIfApplyChanges;
        }
    }

    /* Create ComponentCommonDatamodel interface*/
    if (!pDslhLcbIf)
    {
        pDslhLcbIf = (PDSLH_LCB_INTERFACE) AnscAllocateMemory(sizeof(DSLH_LCB_INTERFACE));

        if (!pDslhLcbIf)
        {
            return ANSC_STATUS_RESOURCES;
        }
        else
        {
            AnscCopyString(pDslhLcbIf->Name, CCSP_LIBCBK_INTERFACE_NAME);

            pDslhLcbIf->InterfaceId              = CCSP_LIBCBK_INTERFACE_ID;
            pDslhLcbIf->hOwnerContext            = NULL;
            pDslhLcbIf->Size                     = sizeof(DSLH_LCB_INTERFACE);

            pDslhLcbIf->InitLibrary              = PppManagerDmlInit;
        }
    }

    pDslhCpeController = DslhCreateCpeController(NULL, NULL, NULL);

    if (!pDslhCpeController)
    {
        CcspTraceWarning(("CANNOT Create pDslhCpeController... Exit!\n"));
        return ANSC_STATUS_RESOURCES;
    }

    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS
ssp_engage ()
{
    ANSC_STATUS                     returnStatus                = ANSC_STATUS_SUCCESS;
    PCCC_MBI_INTERFACE              pSsdMbiIf                   = (PCCC_MBI_INTERFACE)MsgHelper_CreateCcdMbiIf((void*)bus_handle, g_Subsystem);
    char                            CrName[256];

    g_pComponentCommonPppManager->Health = RDK_COMMON_COMPONENT_HEALTH_Yellow;

    /* data model configuration */
    pDslhCpeController->AddInterface((ANSC_HANDLE)pDslhCpeController, (ANSC_HANDLE)pDslhLcbIf);
    pDslhCpeController->AddInterface((ANSC_HANDLE)pDslhCpeController, (ANSC_HANDLE)pSsdMbiIf);
    pDslhCpeController->AddInterface((ANSC_HANDLE)pDslhCpeController, (ANSC_HANDLE)pSsdCcdIf);
    pDslhCpeController->SetDbusHandle((ANSC_HANDLE)pDslhCpeController, (ANSC_HANDLE)bus_handle);
    pDslhCpeController->Engage((ANSC_HANDLE)pDslhCpeController);

    if ( g_Subsystem[0] != 0 )
    {
        sprintf(CrName, "%s%s", g_Subsystem, CCSP_DBUS_INTERFACE_CR);
    }
    else
    {
        sprintf(CrName, "%s", CCSP_DBUS_INTERFACE_CR);
    }

    returnStatus =
        pDslhCpeController->RegisterCcspDataModel
        (
         (ANSC_HANDLE)pDslhCpeController,
         CrName, /* CCSP_DBUS_INTERFACE_CR,*/              /* CCSP CR ID */
         DATAMODEL_XML_FILE,             /* Data Model XML file. Can be empty if only base data model supported. */
         RDK_COMPONENT_NAME_PPP_MANAGER,            /* Component Name    */
         RDK_COMPONENT_VERSION_PPP_MANAGER,         /* Component Version */
         RDK_COMPONENT_PATH_PPP_MANAGER,            /* Component Path    */
         g_Subsystem /* Component Prefix  */
        );

    if ( returnStatus == ANSC_STATUS_SUCCESS || returnStatus == CCSP_SUCCESS)
    {
        /* System is fully initialized */
        g_pComponentCommonPppManager->Health = RDK_COMMON_COMPONENT_HEALTH_Green;
    }

    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS
ssp_cancel ()
{
    int                             nRet  = 0;
    char                            CrName[256];
    char                            CpName[256];

    if(  g_pComponentCommonPppManager == NULL)
    {
        return ANSC_STATUS_SUCCESS;
    }

    if ( g_Subsystem[0] != 0 )
    {
        sprintf(CrName, "%s%s", g_Subsystem, CCSP_DBUS_INTERFACE_CR);
        sprintf(CpName, "%s%s", g_Subsystem, RDK_COMPONENT_NAME_PPP_MANAGER);
    }
    else
    {
        sprintf(CrName, "%s", CCSP_DBUS_INTERFACE_CR);
        sprintf(CpName, "%s", RDK_COMPONENT_NAME_PPP_MANAGER);
    }
    /* unregister component */
    nRet = CcspBaseIf_unregisterComponent(bus_handle, CrName, CpName );  
    AnscTrace("unregisterComponent returns %d\n", nRet);

    pDslhCpeController->Cancel((ANSC_HANDLE)pDslhCpeController);
    AnscFreeMemory(pDslhCpeController);

    if ( pSsdCcdIf ) AnscFreeMemory(pSsdCcdIf);
    if (  g_pComponentCommonPppManager ) AnscFreeMemory( g_pComponentCommonPppManager);

     g_pComponentCommonPppManager = NULL;
    pSsdCcdIf                = NULL;
    pDslhCpeController       = NULL;

    return ANSC_STATUS_SUCCESS;
}

char*
ssp_CcdIfGetComponentName (ANSC_HANDLE hThisObject)
{
    return  g_pComponentCommonPppManager->Name;
}


ULONG
ssp_CcdIfGetComponentVersion (ANSC_HANDLE hThisObject)
{
    return  g_pComponentCommonPppManager->Version;
}


char* ssp_CcdIfGetComponentAuthor (ANSC_HANDLE hThisObject)
{
    return  g_pComponentCommonPppManager->Author;
}


ULONG
ssp_CcdIfGetComponentHealth (ANSC_HANDLE hThisObject)
{
    return  g_pComponentCommonPppManager->Health;
}


ULONG
ssp_CcdIfGetComponentState (ANSC_HANDLE hThisObject)
{
    return  g_pComponentCommonPppManager->State;
}


BOOL
ssp_CcdIfGetLoggingEnabled (ANSC_HANDLE hThisObject)
{
    return  g_pComponentCommonPppManager->LogEnable;
}


ANSC_STATUS
ssp_CcdIfSetLoggingEnabled (ANSC_HANDLE hThisObject, BOOL bEnabled)
{
    if(g_pComponentCommonPppManager->LogEnable == bEnabled) 
    {
        return ANSC_STATUS_SUCCESS;
    }

    g_pComponentCommonPppManager->LogEnable = bEnabled;
        
    if(bEnabled) 
    {
        g_iTraceLevel = (INT) g_pComponentCommonPppManager->LogLevel;
    }
    else 
    {
        g_iTraceLevel = CCSP_TRACE_INVALID_LEVEL;
    }
    return ANSC_STATUS_SUCCESS;
}


ULONG
ssp_CcdIfGetLoggingLevel (ANSC_HANDLE hThisObject)
{
    return  g_pComponentCommonPppManager->LogLevel;
}


ANSC_STATUS
ssp_CcdIfSetLoggingLevel
    (
        ANSC_HANDLE                     hThisObject,
        ULONG                           LogLevel
    )
{
    if(g_pComponentCommonPppManager->LogLevel == LogLevel) 
    {
        return ANSC_STATUS_SUCCESS;
    }

    g_pComponentCommonPppManager->LogLevel = LogLevel;

    if(g_pComponentCommonPppManager->LogEnable) 
    {
        g_iTraceLevel = (INT) g_pComponentCommonPppManager->LogLevel;
    }

    return ANSC_STATUS_SUCCESS;
}

ULONG
ssp_CcdIfGetMemMaxUsage
    (
        ANSC_HANDLE                     hThisObject
    )
{
    return g_ulAllocatedSizePeak;
}


ULONG
ssp_CcdIfGetMemMinUsage
    (
        ANSC_HANDLE                     hThisObject
    )
{
    return  g_pComponentCommonPppManager->MemMinUsage;
}


ULONG
ssp_CcdIfGetMemConsumed
    (
        ANSC_HANDLE                     hThisObject
    )
{
    LONG             size = 0;

    size = AnscGetComponentMemorySize(RDK_COMPONENT_NAME_PPP_MANAGER);
    if (size == -1 )
        size = 0;

    return size;
}


ANSC_STATUS
ssp_CcdIfApplyChanges
    (
        ANSC_HANDLE                     hThisObject
    )
{
    ANSC_STATUS                         returnStatus    = ANSC_STATUS_SUCCESS;
    /* Assume the parameter settings are committed immediately. */
    /* AnscSetTraceLevel((INT) g_pComponentCommonPppManager->LogLevel); */

    return returnStatus;
}

