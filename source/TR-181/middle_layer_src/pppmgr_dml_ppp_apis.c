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

#include "pppmgr_ssp_global.h"
#include "pppmgr_dml_plugin_main_apis.h"
#include "pppmgr_dml_ppp_apis.h"
#include "pppmgr_dml.h"

extern char g_Subsystem[32];
extern ANSC_HANDLE bus_handle;

extern PBACKEND_MANAGER_OBJECT               g_pBEManager;

ANSC_STATUS
PppDmlGetSupportedNCPs
    (
        ANSC_HANDLE                 hContext,
        PULONG                      puLong
    )
{
    *puLong = (DML_PPP_SUPPORTED_NCP_IPCP | DML_PPP_SUPPORTED_NCP_IPv6CP);
    return ANSC_STATUS_SUCCESS;
}

ULONG
PppDmlIfGetNumberOfEntries ()
{
    PDATAMODEL_PPP           pPpp         = (PDATAMODEL_PPP)g_pBEManager->hPPP;

    return pPpp->ulIfNextInstance;
}

ANSC_STATUS
PppDmlGetIfStats
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulPppIfInstanceNumber,
        PDML_IF_STATS          pStats
)
{
    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS
PPPDmlGetIfInfo
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulInstanceNumber,
        PDML_PPP_IF_INFO       pInfo
    )
{

    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS
PppDmlIfReset
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulInstanceNumber
    )
{
    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS
PppDmlGetIfCfg
    (
        ANSC_HANDLE                 hContext,
        PDML_PPP_IF_CFG        pCfg        /* Identified by InstanceNumber */
    )
{
    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS
PppDmlAddIfEntry
    (
        ANSC_HANDLE                 hContext,
        PDML_PPP_IF_FULL       pEntry
    )
{
    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS
PppDmlDelIfEntry
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulInstanceNumber
    )
{
    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS
PppDmlSetIfCfg
    (
        ANSC_HANDLE                 hContext,
        PDML_PPP_IF_CFG        pCfg        /* Identified by InstanceNumber */
    )
{
    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS
PppDmlSetIfValues
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulIndex,
        ULONG                       ulInstanceNumber,
        char*                       pAlias
    )
{
    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS
PPPIfRegGetInfo
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PDATAMODEL_PPP             pMyObject               = (PDATAMODEL_PPP      )hThisObject;
    PSLIST_HEADER                   pListHead               = (PSLIST_HEADER            )&pMyObject->IfList;
    PPOAM_IREP_FOLDER_OBJECT        pPoamIrepFoPPPIf        = (PPOAM_IREP_FOLDER_OBJECT )pMyObject->hIrepFolderPPPIf;
    PPOAM_IREP_FOLDER_OBJECT        pPoamIrepFoPPPIfSp      = (PPOAM_IREP_FOLDER_OBJECT )NULL;
    PDML_PPP_IF_FULL           pEntry                  = (PDML_PPP_IF_FULL    )NULL;
    PPPP_IF_LINK_OBJECT       pLinkContext            = (PPPP_IF_LINK_OBJECT)NULL;
    PSLAP_VARIABLE                  pSlapVariable           = (PSLAP_VARIABLE           )NULL;
    ULONG                           ulEntryCount            = 0;
    ULONG                           ulIndex                 = 0;
    ULONG                           ulInstanceNumber        = 0;
    char*                           pFolderName             = NULL;
    char*                           pAlias                  = NULL;

    if ( !pPoamIrepFoPPPIf )
    {
        return ANSC_STATUS_FAILURE;
    }

    /* Load the newly added but not yet commited entries */

    ulEntryCount = pPoamIrepFoPPPIf->GetFolderCount((ANSC_HANDLE)pPoamIrepFoPPPIf);

    for ( ulIndex = 0; ulIndex < ulEntryCount; ulIndex++ )
    {
        pFolderName =
            pPoamIrepFoPPPIf->EnumFolder
                (
                    (ANSC_HANDLE)pPoamIrepFoPPPIf,
                    ulIndex
                );

        if ( !pFolderName )
        {
            continue;
        }

        pPoamIrepFoPPPIfSp = pPoamIrepFoPPPIf->GetFolder((ANSC_HANDLE)pPoamIrepFoPPPIf, pFolderName);

        AnscFreeMemory(pFolderName);

        if ( !pPoamIrepFoPPPIfSp )
        {
            continue;
        }

        if ( TRUE )
        {
            pSlapVariable =
                (PSLAP_VARIABLE)pPoamIrepFoPPPIfSp->GetRecord
                    (
                        (ANSC_HANDLE)pPoamIrepFoPPPIfSp,
                        DML_RR_NAME_PPPIFInsNum,
                        NULL
                    );

            if ( pSlapVariable )
            {
                ulInstanceNumber = pSlapVariable->Variant.varUint32;

                SlapFreeVariable(pSlapVariable);
            }
        }

        if ( TRUE )
        {
            pSlapVariable =
                (PSLAP_VARIABLE)pPoamIrepFoPPPIfSp->GetRecord
                    (
                        (ANSC_HANDLE)pPoamIrepFoPPPIfSp,
                        DML_RR_NAME_PPPIFAlias,
                        NULL
                    );

            if ( pSlapVariable )
            {
                pAlias = AnscCloneString(pSlapVariable->Variant.varString);

                SlapFreeVariable(pSlapVariable);
            }
        }

        pLinkContext = (PPPP_IF_LINK_OBJECT)AnscAllocateMemory(sizeof(PPP_IF_LINK_OBJECT));

        if ( !pLinkContext )
        {
            AnscFreeMemory(pAlias);

            return ANSC_STATUS_RESOURCES;
        }

        pEntry = (PDML_PPP_IF_FULL)AnscAllocateMemory(sizeof(DML_PPP_IF_FULL));

        if ( !pEntry )
        {
            AnscFreeMemory(pAlias);
            AnscFreeMemory(pLinkContext);

            return ANSC_STATUS_RESOURCES;
        }

        AnscCopyString(pEntry->Cfg.Alias, pAlias);

        pEntry->Cfg.InstanceNumber = ulInstanceNumber;

        pLinkContext->InstanceNumber        = ulInstanceNumber;
        pLinkContext->bNew                  = TRUE;
        pLinkContext->hContext              = (ANSC_HANDLE)pEntry;
        pLinkContext->hParentTable          = NULL;
        pLinkContext->hPoamIrepUpperFo      = (ANSC_HANDLE)pPoamIrepFoPPPIf;
        pLinkContext->hPoamIrepFo           = (ANSC_HANDLE)pPoamIrepFoPPPIfSp;

        PppSListPushEntryByInsNum(pListHead, pLinkContext);

        if ( pAlias )
        {
            AnscFreeMemory(pAlias);

            pAlias = NULL;
        }
    }

    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS
PppSListPushEntryByInsNum
    (
        PSLIST_HEADER               pListHead,
        PPPP_IF_LINK_OBJECT   pLinkContext
    )
{
    ANSC_STATUS                     returnStatus      = ANSC_STATUS_SUCCESS;
    PPPP_IF_LINK_OBJECT       pLinkContextEntry = (PPPP_IF_LINK_OBJECT)NULL;
    PSINGLE_LINK_ENTRY              pSLinkEntry       = (PSINGLE_LINK_ENTRY       )NULL;
    ULONG                           ulIndex           = 0;

    if ( pListHead->Depth == 0 )
    {
        AnscSListPushEntryAtBack(pListHead, &pLinkContext->Linkage);
    }
    else
    {
        pSLinkEntry = AnscSListGetFirstEntry(pListHead);

        for ( ulIndex = 0; ulIndex < pListHead->Depth; ulIndex++ )
        {
            pLinkContextEntry = ACCESS_PPP_IF_LINK_OBJECT(pSLinkEntry);
            pSLinkEntry       = AnscSListGetNextEntry(pSLinkEntry);

            if ( pLinkContext->InstanceNumber < pLinkContextEntry->InstanceNumber )
            {
                AnscSListPushEntryByIndex(pListHead, &pLinkContext->Linkage, ulIndex);

                return ANSC_STATUS_SUCCESS;
            }
        }

        AnscSListPushEntryAtBack(pListHead, &pLinkContext->Linkage);
    }

    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS
PPPIfRegAddInfo
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hCosaContext
    )
{
    ANSC_STATUS                     returnStatus            = ANSC_STATUS_SUCCESS;
    PDATAMODEL_PPP             pMyObject               = (PDATAMODEL_PPP      )hThisObject;
    PPOAM_IREP_FOLDER_OBJECT        pPoamIrepFoPPPIf        = (PPOAM_IREP_FOLDER_OBJECT )pMyObject->hIrepFolderPPPIf;
    PPOAM_IREP_FOLDER_OBJECT        pPoamIrepFoPPPIfSp      = (PPOAM_IREP_FOLDER_OBJECT )NULL;
    PPPP_IF_LINK_OBJECT       pCosaContext            = (PPPP_IF_LINK_OBJECT)hCosaContext;
    PDML_PPP_IF_FULL           pEntry                  = (PDML_PPP_IF_FULL    )pCosaContext->hContext;
    PSLAP_VARIABLE                  pSlapVariable           = (PSLAP_VARIABLE           )NULL;

    if ( !pPoamIrepFoPPPIf )
    {
        return ANSC_STATUS_FAILURE;
    }
    else
    {
        pPoamIrepFoPPPIf->EnableFileSync((ANSC_HANDLE)pPoamIrepFoPPPIf, FALSE);
    }

    if ( TRUE )
    {
        SlapAllocVariable(pSlapVariable);

        if ( !pSlapVariable )
        {
            returnStatus = ANSC_STATUS_RESOURCES;

            goto  EXIT1;
        }
    }
    if ( TRUE )
    {
        returnStatus =
            pPoamIrepFoPPPIf->DelRecord
                (
                    (ANSC_HANDLE)pPoamIrepFoPPPIf,
                    DML_RR_NAME_PPPIFNextInsNunmber
                );

        pSlapVariable->Syntax            = SLAP_VAR_SYNTAX_uint32;
        pSlapVariable->Variant.varUint32 = pMyObject->ulIfNextInstance;

        returnStatus =
            pPoamIrepFoPPPIf->AddRecord
                (
                    (ANSC_HANDLE)pPoamIrepFoPPPIf,
                    DML_RR_NAME_PPPIFNextInsNunmber,
                    SYS_REP_RECORD_TYPE_UINT,
                    SYS_RECORD_CONTENT_DEFAULT,
                    pSlapVariable,
                    0
                );

        SlapCleanVariable(pSlapVariable);
        SlapInitVariable (pSlapVariable);
    }

    if ( TRUE )
    {
        pPoamIrepFoPPPIfSp =
            pPoamIrepFoPPPIf->AddFolder
                (
                    (ANSC_HANDLE)pPoamIrepFoPPPIf,
                    pEntry->Cfg.Alias,
                    0
                );

        if ( !pPoamIrepFoPPPIfSp )
        {
            returnStatus = ANSC_STATUS_FAILURE;

            goto  EXIT1;
        }

        if ( TRUE )
        {
            pSlapVariable->Syntax            = SLAP_VAR_SYNTAX_uint32;
            pSlapVariable->Variant.varUint32 = pEntry->Cfg.InstanceNumber;

            returnStatus =
                pPoamIrepFoPPPIfSp->AddRecord
                    (
                        (ANSC_HANDLE)pPoamIrepFoPPPIfSp,
                        DML_RR_NAME_PPPIFInsNum,
                        SYS_REP_RECORD_TYPE_UINT,
                        SYS_RECORD_CONTENT_DEFAULT,
                        pSlapVariable,
                        0
                    );

            SlapCleanVariable(pSlapVariable);
            SlapInitVariable (pSlapVariable);
        }

        if ( TRUE )
        {
            pSlapVariable->Syntax            = SLAP_VAR_SYNTAX_string;
            pSlapVariable->Variant.varString = AnscCloneString(pEntry->Cfg.Alias);

            returnStatus =
                pPoamIrepFoPPPIfSp->AddRecord
                    (
                        (ANSC_HANDLE)pPoamIrepFoPPPIfSp,
                        DML_RR_NAME_PPPIFAlias,
                        SYS_REP_RECORD_TYPE_ASTR,
                        SYS_RECORD_CONTENT_DEFAULT,
                        pSlapVariable,
                        0
                    );

            SlapCleanVariable(pSlapVariable);
            SlapInitVariable (pSlapVariable);
        }

        pCosaContext->hPoamIrepUpperFo = (ANSC_HANDLE)pPoamIrepFoPPPIf;
        pCosaContext->hPoamIrepFo      = (ANSC_HANDLE)pPoamIrepFoPPPIfSp;
    }

EXIT1:

    if ( pSlapVariable )
    {
        SlapFreeVariable(pSlapVariable);
    }

    pPoamIrepFoPPPIf->EnableFileSync((ANSC_HANDLE)pPoamIrepFoPPPIf, TRUE);

    return returnStatus;
}

ANSC_STATUS
PPPIfRegDelInfo
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hCosaContext
    )
{
    ANSC_STATUS                     returnStatus      = ANSC_STATUS_SUCCESS;
    PDATAMODEL_PPP             pMyObject         = (PDATAMODEL_PPP      )hThisObject;
    PPPP_IF_LINK_OBJECT       pCosaContext      = (PPPP_IF_LINK_OBJECT)hCosaContext;
    PPOAM_IREP_FOLDER_OBJECT        pPoamIrepUpperFo  = (PPOAM_IREP_FOLDER_OBJECT )pCosaContext->hPoamIrepUpperFo;
    PPOAM_IREP_FOLDER_OBJECT        pPoamIrepFo       = (PPOAM_IREP_FOLDER_OBJECT )pCosaContext->hPoamIrepFo;

    if ( !pPoamIrepUpperFo || !pPoamIrepFo )
    {
        return ANSC_STATUS_FAILURE;
    }
    else
    {
        pPoamIrepUpperFo->EnableFileSync((ANSC_HANDLE)pPoamIrepUpperFo, FALSE);
    }

    if ( TRUE )
    {
        pPoamIrepFo->Close((ANSC_HANDLE)pPoamIrepFo);

        pPoamIrepUpperFo->DelFolder
            (
                (ANSC_HANDLE)pPoamIrepUpperFo,
                pPoamIrepFo->GetFolderName((ANSC_HANDLE)pPoamIrepFo)
            );

        pPoamIrepUpperFo->EnableFileSync((ANSC_HANDLE)pPoamIrepUpperFo, TRUE);

        AnscFreeMemory(pPoamIrepFo);
    }

    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS
PppDmlGetIfEntry
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulIndex,
        PDML_PPP_IF_FULL       pEntry
    )
{
    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS PppMgr_checkPidExist(pid_t pppPid)
{

    pid_t pid = 0;
    char line[64] = { 0 };
    FILE *command = NULL;

    if(pppPid)
    {
        command = popen("ps | grep pppd | grep -v grep | awk '{print $1}'","r");

        if(command != NULL)
        {
            while(fgets(line, 64, command))
            {
                pid = strtoul(line, NULL,10);

                if(pid == pppPid)
                {
                    pclose(command);
                    return ANSC_STATUS_SUCCESS;
                }
            }
            pclose(command);
        }

    }
    return ANSC_STATUS_FAILURE;
}

ANSC_STATUS PppMgr_stopPppProcess(pid_t pid)
{

    kill(pid, SIGKILL);

    return ANSC_STATUS_SUCCESS;
}

pid_t PppMgr_getPppPid()
{
    char line[64] = { 0 };
    FILE *command = NULL;
    pid_t pid = 0;

    command = popen("ps | grep pppd | grep -v grep | tail -1 | awk '{print $1}'","r");

    if(command != NULL)
    {
        fgets(line, 64, command);

        pid = strtoul(line, NULL,10);

        pclose(command);
    }
    return pid;
}

static ANSC_STATUS DmlPppMgrGetParamValues(char *pComponent, char *pBus, char *pParamName, char *pReturnVal)
{
    CCSP_MESSAGE_BUS_INFO *bus_info = (CCSP_MESSAGE_BUS_INFO *)bus_handle;
    parameterValStruct_t **retVal;
    char *ParamName[1];
    int ret = 0,
        nval;

    //Assign address for get parameter name
    ParamName[0] = pParamName;

    ret = CcspBaseIf_getParameterValues(
        bus_handle,
        pComponent,
        pBus,
        ParamName,
        1,
        &nval,
        &retVal);

    //Copy the value
    if (CCSP_SUCCESS == ret)
    {
        CcspTraceWarning(("%s parameterValue[%s]\n", __FUNCTION__, retVal[0]->parameterValue));

        if (NULL != retVal[0]->parameterValue)
        {
            memcpy(pReturnVal, retVal[0]->parameterValue, strlen(retVal[0]->parameterValue) + 1);
        }

        if (retVal)
        {
            free_parameterValStruct_t(bus_handle, nval, retVal);
        }

        return ANSC_STATUS_SUCCESS;
    }

    if (retVal)
    {
        free_parameterValStruct_t(bus_handle, nval, retVal);
    }

    return ANSC_STATUS_FAILURE;
}

ANSC_STATUS DmlPppMgrGetWanMgrInstanceNumber(char *pLowerLayers, INT *piInstanceNumber)
{
    char acTmpReturnValue[256] = {0};
    char acTmpQueryParam[256] = {0};
    INT iLoopCount;
    INT iTotalNoofEntries;

    //Validate buffer
    if ((NULL == pLowerLayers) || (NULL == piInstanceNumber))
    {
        CcspTraceError(("%s Invalid Buffer\n", __FUNCTION__));
        return ANSC_STATUS_FAILURE;
    }

    //Initialise default value
    *piInstanceNumber = -1;

    if (ANSC_STATUS_FAILURE == DmlPppMgrGetParamValues(WAN_COMPONENT_NAME, WAN_DBUS_PATH, WAN_NOE_PARAM_NAME, acTmpReturnValue))
    {
    CcspTraceError(("%s %d Failed to get param value\n", __FUNCTION__, __LINE__));
    return ANSC_STATUS_FAILURE;
    }

    //Total count
    iTotalNoofEntries = atoi(acTmpReturnValue);
    CcspTraceInfo(("%s %d - TotalNoofEntries:%d\n", __FUNCTION__, __LINE__, iTotalNoofEntries));

    if (0 >= iTotalNoofEntries)
    {
        return ANSC_STATUS_SUCCESS;
    }

    //Traverse from loop
    for (iLoopCount = 0; iLoopCount < iTotalNoofEntries; iLoopCount++)
    {
        //Query
        snprintf(acTmpQueryParam, sizeof(acTmpQueryParam), WAN_PHY_PATH_PARAM_NAME, iLoopCount + 1);

        memset(acTmpReturnValue, 0, sizeof(acTmpReturnValue));
        if (ANSC_STATUS_FAILURE == DmlPppMgrGetParamValues(WAN_COMPONENT_NAME, WAN_DBUS_PATH, acTmpQueryParam, acTmpReturnValue))
        {
            CcspTraceError(("%s %d Failed to get param value\n", __FUNCTION__, __LINE__));
            continue;
        }

        //Compare name
        if (0 == strcmp(acTmpReturnValue, pLowerLayers))
        {
            *piInstanceNumber = iLoopCount + 1;
            break;
        }
    }

    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS DmlWanmanagerSetParamValues(const char *pComponent, const char *pBus,
        const char *pParamName, const char *pParamVal, enum dataType_e type, unsigned int bCommitFlag)
{
    CCSP_MESSAGE_BUS_INFO *bus_info = (CCSP_MESSAGE_BUS_INFO *)bus_handle;
    parameterValStruct_t param_val[1] = {0};
    char *faultParam = NULL;
    int ret = 0;

    param_val[0].parameterName = pParamName;
    param_val[0].parameterValue = pParamVal;
    param_val[0].type = type;

    ret = CcspBaseIf_setParameterValues(
            bus_handle,
            pComponent,
            pBus,
            0,
            0,
            &param_val,
            1,
            bCommitFlag,
            &faultParam);

    CcspTraceInfo(("Value being set [%d] \n", ret));

    if ((ret != CCSP_SUCCESS) && (faultParam != NULL))
    {
        CcspTraceError(("%s-%d Failed to set %s\n", __FUNCTION__, __LINE__, pParamName));
        bus_info->freefunc(faultParam);
        return ANSC_STATUS_FAILURE;
    }

    return ANSC_STATUS_SUCCESS;
}
