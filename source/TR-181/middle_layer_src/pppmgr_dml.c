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

#include "pppmgr_ssp_global.h"
#include "pppmgr_dml_plugin_main_apis.h"
#include "pppmgr_dml.h"
#include "pppmgr_dml_apis.h"
#include "pppmgr_dml_ppp_apis.h"
#include "ccsp_psm_helper.h"

#define PPP_IF_SERVICE_NAME "atm0.0.0.38"
#define PPP_IF_NAME         "pppoa0"
#define WAN_IF_NAME         "wan0"
#define PPPoE_VLAN_IF_NAME  "vlan101"
#define GET_PPPID_ATTEMPT 5

extern char g_Subsystem[32];
extern ANSC_HANDLE bus_handle;

extern PBACKEND_MANAGER_OBJECT               g_pBEManager;
static void* PppMgr_StartPppdDaemon( void *arg );

static int set_syscfg(char *pValue,char *param)
{
    if((syscfg_set(NULL, param, pValue) != 0))
    {
        return -1;
    }
    else
    {
        if(syscfg_commit() != 0)
        {
            return -1;
        }
        return 0;
    }
}

/***********************************************************************

 APIs for Object:

    PPP.

    *  PPP_GetParamBoolValue
    *  PPP_GetParamIntValue
    *  PPP_GetParamUlongValue
    *  PPP_GetParamStringValue

***********************************************************************/
/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        PPP_GetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL*                       pBool
            );

    description:

        This function is called to retrieve Boolean parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL*                       pBool
                The buffer of returned boolean value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
PPP_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    )
{
    /* check the parameter name and return the corresponding value */

    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        PPP_GetParamIntValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                int*                        pInt
            );

    description:

        This function is called to retrieve integer parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                int*                        pInt
                The buffer of returned integer value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
PPP_GetParamIntValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        int*                        pInt
    )
{
    /* check the parameter name and return the corresponding value */

    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        PPP_GetParamUlongValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG*                      puLong
            );

    description:

        This function is called to retrieve ULONG parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG*                      puLong
                The buffer of returned ULONG value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
PPP_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      puLong
    )
{
    /* check the parameter name and return the corresponding value */

    if (AnscEqualString(ParamName, "InterfaceNumberOfEntries", TRUE))
    {
        *puLong = PppDmlIfGetNumberOfEntries();
    }

    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        PPP_GetParamStringValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                char*                       pValue,
                ULONG*                      pUlSize
            );

    description:

        This function is called to retrieve string parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                char*                       pValue,
                The string value buffer;

                ULONG*                      pUlSize
                The buffer of length of string value;
                Usually size of 1023 will be used.
                If it's not big enough, put required size here and return 1;

    return:     0 if succeeded;
                1 if short of buffer size; (*pUlSize = required size)
                -1 if not supported.

**********************************************************************/
ULONG
PPP_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    )
{
    /* check the parameter name and return the corresponding value */
    if (AnscEqualString(ParamName, "SupportedNCPs", TRUE))
    {
        ULONG flag;
        
        PppDmlGetSupportedNCPs(NULL, &flag);

        AnscCopyString(pValue, "");

        if (flag & DML_PPP_SUPPORTED_NCP_ATCP)
        {
            strncat(pValue, "ATCP,",sizeof("ATCP,"));
        }

        if (flag & DML_PPP_SUPPORTED_NCP_IPCP)
        {
            strncat(pValue, "IPCP,",sizeof("IPCP,"));
        }

        if (flag & DML_PPP_SUPPORTED_NCP_IPXCP)
        {
            strncat(pValue, "IPXCP,",sizeof("IPXCP,"));
        }

        if (flag & DML_PPP_SUPPORTED_NCP_NBFCP)
        {
            strncat(pValue, "NBFCP,",sizeof("NBFCP,"));
        }

        if (flag & DML_PPP_SUPPORTED_NCP_IPv6CP)
        {
            strncat(pValue, "IPv6CP,",sizeof("IPv6CP,"));
        }

        return 0;
    }

    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return -1;
}


/***********************************************************************

 APIs for Object:

    PPP.Interface.{i}.

    *  Interface_GetEntryCount
    *  Interface_GetEntry
    *  Interface_AddEntry
    *  Interface_DelEntry
    *  Interface_GetParamBoolValue
    *  Interface_GetParamIntValue
    *  Interface_GetParamUlongValue
    *  Interface_GetParamStringValue
    *  Interface_SetParamBoolValue
    *  Interface_SetParamIntValue
    *  Interface_SetParamUlongValue
    *  Interface_SetParamStringValue
    *  Interface_Validate
    *  Interface_Commit
    *  Interface_Rollback

***********************************************************************/
/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        Interface_GetEntryCount
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to retrieve the count of the table.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The count of the table

**********************************************************************/
ULONG
Interface_GetEntryCount
    (
        ANSC_HANDLE                 hInsContext
    )
{
    PDATAMODEL_PPP             pMyObject = (PDATAMODEL_PPP)g_pBEManager->hPPP;
    
    return AnscSListQueryDepth(&pMyObject->IfList);
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ANSC_HANDLE
        Interface_GetEntry
            (
                ANSC_HANDLE                 hInsContext,
                ULONG                       nIndex,
                ULONG*                      pInsNumber
            );

    description:

        This function is called to retrieve the entry specified by the index.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                ULONG                       nIndex,
                The index of this entry;

                ULONG*                      pInsNumber
                The output instance number;

    return:     The handle to identify the entry

**********************************************************************/
ANSC_HANDLE
Interface_GetEntry
    (
        ANSC_HANDLE                 hInsContext,
        ULONG                       nIndex,
        ULONG*                      pInsNumber
    )
{
    PDATAMODEL_PPP             pMyObject               = (PDATAMODEL_PPP      )g_pBEManager->hPPP;
    PSLIST_HEADER                   pListHead               = (PSLIST_HEADER            )&pMyObject->IfList;
    PPPP_IF_LINK_OBJECT       pContext            = (PPPP_IF_LINK_OBJECT)NULL;
    PSINGLE_LINK_ENTRY              pSLinkEntry             = (PSINGLE_LINK_ENTRY       )NULL;
    PDML_PPP_IF_FULL           pEntry                  = (PDML_PPP_IF_FULL    )NULL;

    pthread_mutex_lock(&pEntry->mDataMutex);

    pSLinkEntry = AnscSListGetEntryByIndex(&pMyObject->IfList, nIndex);

    if ( pSLinkEntry )
    {
        pContext = ACCESS_PPP_IF_LINK_OBJECT(pSLinkEntry);

        *pInsNumber = pContext->InstanceNumber;

        pEntry = pContext->hContext;
        
        PppDmlGetIfCfg(NULL, &pEntry->Cfg);
    }
    pthread_mutex_unlock(&pEntry->mDataMutex);

    return pContext;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ANSC_HANDLE
        Interface_AddEntry
            (
                ANSC_HANDLE                 hInsContext,
                ULONG*                      pInsNumber
            );

    description:

        This function is called to add a new entry.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                ULONG*                      pInsNumber
                The output instance number;

    return:     The handle of new added entry.

**********************************************************************/
ANSC_HANDLE
Interface_AddEntry
    (
        ANSC_HANDLE                 hInsContext,
        ULONG*                      pInsNumber
    )
{
    PDATAMODEL_PPP             pMyObject               = (PDATAMODEL_PPP      )g_pBEManager->hPPP;
    PSLIST_HEADER                   pListHead               = (PSLIST_HEADER            )&pMyObject->IfList;
    PDML_PPP_IF_FULL           pEntry                  = (PDML_PPP_IF_FULL    )NULL;
    PPPP_IF_LINK_OBJECT       pLinkContext            = (PPPP_IF_LINK_OBJECT)NULL;

#ifdef _COSA_DRG_CNS_
    return NULL;
#endif

    pEntry = (PDML_PPP_IF_FULL)AnscAllocateMemory(sizeof(DML_PPP_IF_FULL));

    if (!pEntry)
    {
        return NULL;
    }
    pthread_mutex_lock(&pEntry->mDataMutex);    

    memset(pEntry, 0, sizeof(PDML_PPP_IF_FULL));

    sprintf(pEntry->Cfg.Alias, "erouter%d", pMyObject->ulIfNextInstance);

    strncpy(pEntry->Info.InterfaceServiceName, PPP_IF_SERVICE_NAME,sizeof(pEntry->Info.InterfaceServiceName));

    strncpy(pEntry->Info.Name, PPP_IF_NAME,sizeof(pEntry->Info.Name));

    pEntry->Info.AuthenticationProtocol = DML_PPP_AUTH_CHAP;

    if (pthread_mutex_init(&pEntry->mDataMutex, NULL) != 0)
    { 
        AnscFreeMemory(pEntry);

        pthread_mutex_unlock(&pEntry->mDataMutex);

        return NULL;
    } 
    /* Update the cache */
    pLinkContext = (PPPP_IF_LINK_OBJECT)AnscAllocateMemory(sizeof(PPP_IF_LINK_OBJECT));
    if (!pLinkContext)
    {
        AnscFreeMemory(pEntry);

        pthread_mutex_unlock(&pEntry->mDataMutex);

        return NULL;
    }

    pLinkContext->InstanceNumber = pEntry->Cfg.InstanceNumber = pMyObject->ulIfNextInstance;

    pMyObject->ulIfNextInstance++;

    if ( pMyObject->ulIfNextInstance == 0 )
    {
        pMyObject->ulIfNextInstance = 1;
    }

    pLinkContext->hContext        = (ANSC_HANDLE)pEntry;
    pLinkContext->hParentTable    = NULL;
    pLinkContext->bNew            = TRUE;


    PppSListPushEntryByInsNum(pListHead, pLinkContext);


    PPPIfRegAddInfo((ANSC_HANDLE)pMyObject, (ANSC_HANDLE)pLinkContext);

    *pInsNumber = pLinkContext->InstanceNumber;

    pthread_mutex_unlock(&pEntry->mDataMutex);

    return pLinkContext;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        Interface_DelEntry
            (
                ANSC_HANDLE                 hInsContext,
                ANSC_HANDLE                 hInstance
            );

    description:

        This function is called to delete an exist entry.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                ANSC_HANDLE                 hInstance
                The exist entry handle;

    return:     The status of the operation.

**********************************************************************/
ULONG
Interface_DelEntry
    (
        ANSC_HANDLE                 hInsContext,
        ANSC_HANDLE                 hInstance
    )
{
    PPPP_IF_LINK_OBJECT       pLinkContext            = (PPPP_IF_LINK_OBJECT)hInstance;
    PPPP_IF_LINK_OBJECT       pLinkContext2           = (PPPP_IF_LINK_OBJECT)NULL;
    PDML_PPP_IF_FULL           pEntry                  = (PDML_PPP_IF_FULL    )pLinkContext->hContext;
    PDML_PPP_IF_FULL           pNewEntry               = (PDML_PPP_IF_FULL    )NULL;
    PDATAMODEL_PPP             pMyObject               = (PDATAMODEL_PPP      )g_pBEManager->hPPP;
    PSLIST_HEADER                   pListHead               = (PSLIST_HEADER            )&pMyObject->IfList;
    PSINGLE_LINK_ENTRY              pSLinkEntry             = NULL;

#ifdef _COSA_DRG_CNS_
    return ANSC_STATUS_FAILURE;
#endif

    if(pEntry == NULL)
    {
        return ANSC_STATUS_FAILURE;
    }

    pthread_mutex_lock(&pEntry->mDataMutex);

    PppDmlDelIfEntry(NULL, pEntry->Cfg.InstanceNumber);

    /* Update the cache */
    if ( TRUE )
    {
        pSLinkEntry = AnscSListGetFirstEntry(&pMyObject->IfList);

        while ( pSLinkEntry )
        {
            pLinkContext2 = ACCESS_PPP_IF_LINK_OBJECT(pSLinkEntry);
            pSLinkEntry   = AnscSListGetNextEntry(pSLinkEntry);

            pNewEntry = (PDML_PPP_IF_FULL)pLinkContext2->hContext;

            if ( pNewEntry && AnscEqualString(pNewEntry->Cfg.Alias, pEntry->Cfg.Alias, FALSE))
            {
                AnscSListPopEntryByLink(pListHead, &pLinkContext2->Linkage);

				if (pLinkContext->bNew)
	                PPPIfRegDelInfo((ANSC_HANDLE)pMyObject, (ANSC_HANDLE)pLinkContext2);

                AnscFreeMemory(pNewEntry);
                AnscFreeMemory(pLinkContext2);

                break;
            }
        }
    }
    pthread_mutex_unlock(&pEntry->mDataMutex);

    pthread_mutex_destroy(&pEntry->mDataMutex);
        
    return ANSC_STATUS_SUCCESS;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        Interface_GetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL*                       pBool
            );

    description:

        This function is called to retrieve Boolean parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL*                       pBool
                The buffer of returned boolean value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
Interface_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    )
{
    PPPP_IF_LINK_OBJECT       pContextLinkObject      = (PPPP_IF_LINK_OBJECT)hInsContext;
    PDML_PPP_IF_FULL           pEntry                  = (PDML_PPP_IF_FULL)pContextLinkObject->hContext;
    BOOL retStatus = FALSE;

    pthread_mutex_lock(&pEntry->mDataMutex);
    /* check the parameter name and return the corresponding value */
    if( AnscEqualString(ParamName, "Enable", TRUE))
    {
        /* collect value */
        *pBool = pEntry->Cfg.bEnabled;

        retStatus = TRUE;
    }

    if( AnscEqualString(ParamName, "IPCPEnable", TRUE))
    {
        /* collect value */
        *pBool = pEntry->Cfg.bIPCPEnabled;

        retStatus = TRUE;
    }
    
    if( AnscEqualString(ParamName, "IPv6CPEnable", TRUE))
    {
        /* collect value */
        *pBool = pEntry->Cfg.bIPV6CPEnabled;

        retStatus = TRUE;
    }

    if( AnscEqualString(ParamName, "Reset", TRUE))
    {
        /* collect value */
        *pBool = FALSE;

        retStatus = TRUE;
    }
    pthread_mutex_unlock(&pEntry->mDataMutex);

    return retStatus;

}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        Interface_GetParamUlongValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG*                      puLong
            );

    description:

        This function is called to retrieve ULONG parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG*                      puLong
                The buffer of returned ULONG value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
Interface_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      puLong
    )
{
    PPPP_IF_LINK_OBJECT       pContextLinkObject      = (PPPP_IF_LINK_OBJECT)hInsContext;
    PDML_PPP_IF_FULL           pEntry                  = (PDML_PPP_IF_FULL)pContextLinkObject->hContext;
    BOOL retStatus = FALSE;
    char buff[10] = {0};

    pthread_mutex_lock(&pEntry->mDataMutex);
    /* check the parameter name and return the corresponding value */
    if( AnscEqualString(ParamName, "Status", TRUE))
    {
        /* collect value */
        PPPDmlGetIfInfo(pContextLinkObject->hContext, pEntry->Cfg.InstanceNumber, &pEntry->Info);

        *puLong = pEntry->Info.Status;

        retStatus = TRUE;
    }

    if( AnscEqualString(ParamName, "LastChange", TRUE))
    {
        /* collect value */
        PPPDmlGetIfInfo(pContextLinkObject->hContext, pEntry->Cfg.InstanceNumber, &pEntry->Info);

        *puLong = AnscGetTimeIntervalInSeconds(pEntry->Info.LastChange, GetUptimeinSeconds());

        retStatus = TRUE;
    }

    if( AnscEqualString(ParamName, "ConnectionStatus", TRUE))
    {
        /* collect value */
        PPPDmlGetIfInfo(pContextLinkObject->hContext, pEntry->Cfg.InstanceNumber, &pEntry->Info);

        *puLong = pEntry->Info.ConnectionStatus;

        retStatus = TRUE;
    }

    if( AnscEqualString(ParamName, "X_T_ONLINE_DE_SRU", TRUE))
    {

        *puLong =  pEntry->Info.SRU;

        retStatus = TRUE;
    }

    if( AnscEqualString(ParamName, "X_T_ONLINE_DE_SRD", TRUE))
    {

        *puLong =  pEntry->Info.SRD;

        retStatus = TRUE;
    }

    if( AnscEqualString(ParamName, "LastConnectionError", TRUE))
    {
        /* collect value */
        PPPDmlGetIfInfo(pContextLinkObject->hContext, pEntry->Cfg.InstanceNumber, &pEntry->Info);

        *puLong = pEntry->Info.LastConnectionError;

        retStatus = TRUE;
    }

    if( AnscEqualString(ParamName, "AutoDisconnectTime", TRUE))
    {
        /* collect value */
        *puLong = pEntry->Cfg.AutoDisconnectTime;

        retStatus = TRUE;
    }

    if( AnscEqualString(ParamName, "IdleDisconnectTime", TRUE))
    {
        /* collect value */
        *puLong = pEntry->Cfg.IdleDisconnectTime;

        retStatus = TRUE;
    }

    if( AnscEqualString(ParamName, "WarnDisconnectDelay", TRUE))
    {
        /* collect value */
        *puLong = pEntry->Cfg.WarnDisconnectDelay;

        retStatus = TRUE;
    }

    if( AnscEqualString(ParamName, "EncryptionProtocol", TRUE))
    {
        /* collect value */
        PPPDmlGetIfInfo(pContextLinkObject->hContext, pEntry->Cfg.InstanceNumber, &pEntry->Info);

        *puLong = pEntry->Info.EncryptionProtocol;

        retStatus = TRUE;
    }

    if( AnscEqualString(ParamName, "CompressionProtocol", TRUE))
    {
        /* collect value */
        PPPDmlGetIfInfo(pContextLinkObject->hContext, pEntry->Cfg.InstanceNumber, &pEntry->Info);

        *puLong = pEntry->Info.CompressionProtocol;

        retStatus = TRUE;
    }

    if( AnscEqualString(ParamName, "AuthenticationProtocol", TRUE))
    {
        /* collect value */
        PPPDmlGetIfInfo(pContextLinkObject->hContext, pEntry->Cfg.InstanceNumber, &pEntry->Info);

        *puLong = pEntry->Info.AuthenticationProtocol;

        retStatus = TRUE;
    }

    if( AnscEqualString(ParamName, "MaxMRUSize", TRUE))
    {
        /* collect value */
        syscfg_get(NULL, "MaxMRUSize",buff, sizeof(buff));
        pEntry->Cfg.MaxMRUSize = atoi(buff);
        *puLong = pEntry->Cfg.MaxMRUSize;

        retStatus = TRUE;
    }

    if( AnscEqualString(ParamName, "CurrentMRUSize", TRUE))
    {
        /* collect value */
        PPPDmlGetIfInfo(pContextLinkObject->hContext, pEntry->Cfg.InstanceNumber, &pEntry->Info);

        pEntry->Info.CurrentMRUSize = pEntry->Cfg.MaxMRUSize;
        *puLong = pEntry->Info.CurrentMRUSize;

        retStatus = TRUE;
    }

    if( AnscEqualString(ParamName, "ConnectionTrigger", TRUE))
    {
        /* collect value */
        *puLong = pEntry->Cfg.ConnectionTrigger;

        retStatus = TRUE;
    }

    if( AnscEqualString(ParamName, "LCPEcho", TRUE))
    {
        /* collect value */
        PPPDmlGetIfInfo(pContextLinkObject->hContext, pEntry->Cfg.InstanceNumber, &pEntry->Info);

        *puLong = pEntry->Info.LCPEcho;

        retStatus = TRUE;
    }

    if( AnscEqualString(ParamName, "LCPEchoRetry", TRUE))
    {
        /* collect value */
        PPPDmlGetIfInfo(pContextLinkObject->hContext, pEntry->Cfg.InstanceNumber, &pEntry->Info);

        *puLong = pEntry->Info.LCPEchoRetry;

        retStatus = TRUE;
    }

    if( AnscEqualString(ParamName, "X_RDK_LinkType", TRUE))
    {
        /* collect value */
        PPPDmlGetIfInfo(pContextLinkObject->hContext, pEntry->Cfg.InstanceNumber, &pEntry->Info);

        *puLong = pEntry->Cfg.LinkType;

        retStatus = TRUE;
    }

    pthread_mutex_unlock(&pEntry->mDataMutex);

    return retStatus;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        Interface_GetParamStringValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                char*                       pValue,
                ULONG*                      pUlSize
            );

    description:

        This function is called to retrieve string parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                char*                       pValue,
                The string value buffer;

                ULONG*                      pUlSize
                The buffer of length of string value;
                Usually size of 1023 will be used.
                If it's not big enough, put required size here and return 1;

    return:     0 if succeeded;
                1 if short of buffer size; (*pUlSize = required size)
                -1 if not supported.

**********************************************************************/
ULONG
Interface_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    )
{
    PPPP_IF_LINK_OBJECT       pContextLinkObject      = (PPPP_IF_LINK_OBJECT)hInsContext;
    PDML_PPP_IF_FULL           pEntry                  = (PDML_PPP_IF_FULL)pContextLinkObject->hContext;
    PUCHAR                          pString                 = NULL;
    uint32_t retStatus = -1;

    pthread_mutex_lock(&pEntry->mDataMutex);

    /* check the parameter name and return the corresponding value */
    if( AnscEqualString(ParamName, "Alias", TRUE))
    {
        /* collect value */
        AnscCopyString(pValue, pEntry->Cfg.Alias);

        retStatus = 0;
    }

    if( AnscEqualString(ParamName, "Name", TRUE))
    {
        /* collect value */
        PPPDmlGetIfInfo(pContextLinkObject->hContext, pEntry->Cfg.InstanceNumber, &pEntry->Info);

        AnscCopyString(pValue, pEntry->Info.Name);

        retStatus = 0;
    }

    if( AnscEqualString(ParamName, "LowerLayers", TRUE))
    {
        /* collect value */
        AnscCopyString(pValue, pEntry->Cfg.LowerLayers);

        retStatus = 0;
    }

    if( AnscEqualString(ParamName, "Username", TRUE))
    {
		 /* collect value */
        AnscCopyString(pValue, pEntry->Cfg.Username);

        retStatus = 0;
    }

    if( AnscEqualString(ParamName, "Password", TRUE))
    {
		/* collect value */
        AnscCopyString(pValue, "");

        retStatus = 0;
    }
    pthread_mutex_unlock(&pEntry->mDataMutex);

    return retStatus;

}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        Interface_SetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL                        bValue
            );

    description:

        This function is called to set BOOL parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL                        bValue
                The updated BOOL value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
Interface_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    )
{
    PPPP_IF_LINK_OBJECT       pContextLinkObject      = (PPPP_IF_LINK_OBJECT)hInsContext;
    PDML_PPP_IF_FULL           pEntry                  = (PDML_PPP_IF_FULL)pContextLinkObject->hContext;

    char command[1024] = { 0 };
    char config_command[1024] = { 0 };
    char service_name[256] = { 0 };
    char auth_proto[8] = { 0 };
    pthread_t pppdThreadId;
    BOOL retStatus = FALSE;
    uint32_t getAttempts = 0;

    if(pEntry == NULL)
    {
        return FALSE;
    }

    pthread_mutex_lock(&pEntry->mDataMutex);    

    if( AnscEqualString(ParamName, "Enable", TRUE))
    {
        /* save update to backup */
        pEntry->Cfg.bEnabled = bValue;
        if( bValue == true )
        {
            if(ANSC_STATUS_SUCCESS == PppMgr_checkPidExist(pEntry->Info.pppPid))
            {
                CcspTraceInfo(("pppd is already running \n"));

                pthread_mutex_unlock(&pEntry->mDataMutex);

                return TRUE;
            }

            pEntry->Info.pppPid = 0;

            if((strcmp(pEntry->Info.Name,"") != 0) && (strcmp(pEntry->Info.InterfaceServiceName,"") != 0) &&
                    (strcmp(pEntry->Cfg.Username,"") != 0) && (strcmp(pEntry->Cfg.Password,"") != 0) &&
                    (pEntry->Info.AuthenticationProtocol > 0))
            {
                if((pEntry->Info.AuthenticationProtocol == DML_PPP_AUTH_CHAP) ||
                        (pEntry->Info.AuthenticationProtocol ==  DML_PPP_AUTH_PAP))
                {
                    sprintf(auth_proto,"0");
                }
                else
                {
                    /* support for mschap */
                    sprintf(auth_proto,"4");
                }
                if (pEntry->Cfg.LinkType == DML_PPPoA_LINK_TYPE)
                {
            #ifdef USE_PPP_DAEMON
                    snprintf(command, sizeof(command), "pppd -6 -c %s -a %s -u %s -p %s -f %s &",
                        pEntry->Cfg.Alias, pEntry->Info.InterfaceServiceName, pEntry->Cfg.Username,
                        pEntry->Cfg.Password, auth_proto);
            #else
                    /* Assume a default rp-pppoe config exist. Update rp-pppoe configuration */
                    snprintf(config_command, sizeof(config_command), "pppoe_config.sh %s %s %s %s PPPoA", 
                        pEntry->Cfg.Username, pEntry->Cfg.Password, pEntry->Info.InterfaceServiceName, pEntry->Cfg.Alias);

                    system(config_command);

                    /* start rp-pppoe */
                    snprintf(command, sizeof(command), "/usr/sbin/pppoe-start");
            #endif
                
                }
                else if (pEntry->Cfg.LinkType == DML_PPPoE_LINK_TYPE)
                {
            #ifdef USE_PPP_DAEMON
                    snprintf(command, sizeof(command), "pppd -6 -c %s -i %s -u %s -p %s -f %s &",
                        pEntry->Cfg.Alias, PPPoE_VLAN_IF_NAME, pEntry->Cfg.Username, pEntry->Cfg.Password, auth_proto);
            #else
                    /* Assume a defule rp-pppoe config exist. Update rp-pppoe configuration */
                    snprintf(config_command, sizeof(config_command), "pppoe_config.sh %s %s %s %s PPPoE", 
                        pEntry->Cfg.Username, pEntry->Cfg.Password, PPPoE_VLAN_IF_NAME, pEntry->Cfg.Alias);

                    system(config_command);

                    /* start rp-pppoe */
                    snprintf(command, sizeof(command), "/usr/sbin/pppoe-start");
            #endif
                }
                CcspTraceInfo(("parameters were set\n"));
            }
            else
            {
                pthread_mutex_unlock(&pEntry->mDataMutex);

                return FALSE;
            }
            CcspTraceInfo(("command to execute is  '%s'\n", command));

            pthread_mutex_unlock(&pEntry->mDataMutex);
            //system(command);
            int iErrorCode = pthread_create( &pppdThreadId, NULL, &PppMgr_StartPppdDaemon, (void*) command );
            if( 0 != iErrorCode )
            {
                CcspTraceInfo(("%s %d - Failed to start Pppmgr_StartPppdDaemon  %d\n", __FUNCTION__, __LINE__,
                            iErrorCode ));

                return FALSE;
            }
            /* lock while updating pid */
            pthread_mutex_lock(&pEntry->mDataMutex);

            do 
            {
                if(getAttempts)
                {
                    //wait for 1 second
                    sleep(1);
                }
                pEntry->Info.pppPid = PppMgr_getPppPid();

                getAttempts++;

            }while(pEntry->Info.pppPid <= 0 && getAttempts < GET_PPPID_ATTEMPT);
            
            CcspTraceInfo(("pid got in attempt  '%d'\n", getAttempts));

            DmlPppMgrGetWanMgrInstanceNumber(pEntry->Cfg.LowerLayers, &(pEntry->Cfg.WanInstanceNumber));

            CcspTraceInfo(("pid table value  '%d'\n", pEntry->Info.pppPid));
        }
        else
        {
#ifdef USE_PPP_DAEMON
            PppMgr_stopPppProcess(pEntry->Info.pppPid);
#else
	    system("/usr/sbin/pppoe-stop");
            //Allow enough time for rp-pppoe to gracefully stop the daemon
            sleep(5);	    
#endif
            pEntry->Info.pppPid = 0;
        }

        /* we are unlocking at end */
        retStatus = TRUE;
    }

    if( AnscEqualString(ParamName, "IPCPEnable", TRUE))
    {
        /* save update to backup */
        pEntry->Cfg.bIPCPEnabled = bValue;

        retStatus = TRUE;
    }

    if( AnscEqualString(ParamName, "IPv6CPEnable", TRUE))
    {
        /* save update to backup */
        pEntry->Cfg.bIPV6CPEnabled = bValue;

        retStatus = TRUE;
    }

    if( AnscEqualString(ParamName, "Reset", TRUE))
    {
        /* save update to backup */
        if ( pEntry->Cfg.bEnabled && bValue )
        {
            PppDmlIfReset(NULL, pEntry->Cfg.InstanceNumber);
        }

        retStatus = TRUE;
    }

    pthread_mutex_unlock(&pEntry->mDataMutex);

    return retStatus;

}

static void* PppMgr_StartPppdDaemon( void *arg )
{
    FILE *pf;
    const char *pCommand = (char *) arg;

    pthread_detach(pthread_self());

    if( NULL == pCommand )
    {
        CcspTraceError(("%s Invalid Memory\n", __FUNCTION__));
        return ANSC_STATUS_FAILURE;
    }

    pf = popen(pCommand, "r");
    if(!pf)
    {
        fprintf(stderr, "Could not open pipe for output.\n");
        return;
    }

    if (pclose(pf) != 0)
    {
        fprintf(stderr," Error: Failed to close command stream \n");
    }

    return NULL;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        Interface_SetParamIntValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                int                         iValue
            );

    description:

        This function is called to set integer parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                int                         iValue
                The updated integer value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
Interface_SetParamIntValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        int                         iValue
    )
{
    /* check the parameter name and set the corresponding value */

    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        Interface_SetParamUlongValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG                       uValue
            );

    description:

        This function is called to set ULONG parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG                       uValue
                The updated ULONG value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
Interface_SetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG                       uValue
    )
{
    PPPP_IF_LINK_OBJECT       pContextLinkObject      = (PPPP_IF_LINK_OBJECT)hInsContext;
    PDML_PPP_IF_FULL          pEntry                  = (PDML_PPP_IF_FULL)pContextLinkObject->hContext;
    BOOL retStatus = FALSE;
    char buf[10] = {0};

    if(pEntry == NULL)
    {
        return FALSE;
    }

    pthread_mutex_lock(&pEntry->mDataMutex);

    /* check the parameter name and set the corresponding value */
    if( AnscEqualString(ParamName, "AutoDisconnectTime", TRUE))
    {
        /* save update to backup */
        pEntry->Cfg.AutoDisconnectTime = uValue;

        retStatus = TRUE;
    }

    if( AnscEqualString(ParamName, "IdleDisconnectTime", TRUE))
    {
        /* save update to backup */
        pEntry->Cfg.IdleDisconnectTime = uValue;

        retStatus = TRUE;
    }

    if( AnscEqualString(ParamName, "WarnDisconnectDelay", TRUE))
    {
        /* save update to backup */
        pEntry->Cfg.WarnDisconnectDelay = uValue;

        retStatus = TRUE;
    }

    if( AnscEqualString(ParamName, "MaxMRUSize", TRUE))
    {
        /* save update to backup */
#ifdef _COSA_DRG_CNS_
        /*not supported*/
        retStatus = FALSE;
#else
        pEntry->Cfg.MaxMRUSize = uValue;
        snprintf(buf,sizeof(buf),"%d",uValue);
        set_syscfg(buf,"MaxMRUSize");

        retStatus = TRUE;
#endif
    }

    if( AnscEqualString(ParamName, "ConnectionTrigger", TRUE))
    {
        /* save update to backup */
#ifdef _COSA_DRG_CNS_
        /*don't support manual*/
        if (uValue == PPP_DML_CONN_TRIGGER_Manual) 
        {
            pthread_mutex_unlock(&pEntry->Info.mDataMutex);

            return FALSE;
        }
#endif
        pEntry->Cfg.ConnectionTrigger = uValue;

        retStatus = TRUE;
    }

    if( AnscEqualString(ParamName, "X_RDK_LinkType", TRUE))
    {
        pEntry->Cfg.LinkType = uValue;

        retStatus = TRUE;
    }

    pthread_mutex_unlock(&pEntry->mDataMutex);

    return retStatus;

}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        Interface_SetParamStringValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                char*                       pString
            );

    description:

        This function is called to set string parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                char*                       pString
                The updated string value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
Interface_SetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pString
    )
{
    PPPP_IF_LINK_OBJECT       pContextLinkObject      = (PPPP_IF_LINK_OBJECT)hInsContext;
    PDML_PPP_IF_FULL           pEntry                  = (PDML_PPP_IF_FULL)pContextLinkObject->hContext;

    int instancenum = 1;
    BOOL retStatus = FALSE;

    if(pEntry == NULL)
    {
        return FALSE;
    }

    pthread_mutex_lock(&pEntry->mDataMutex);

    /* check the parameter name and set the corresponding value */
    if( AnscEqualString(ParamName, "Alias", TRUE))
    {
        /* save update to backup */
        AnscCopyString(pEntry->Cfg.Alias, pString);

        retStatus = TRUE;
    }

    if( AnscEqualString(ParamName, "LowerLayers", TRUE))
    {
        /* save update to backup */
        AnscCopyString(pEntry->Cfg.LowerLayers, pString);

        retStatus = TRUE;
    }

    if( AnscEqualString(ParamName, "Username", TRUE))
    {
        instancenum = pEntry->Cfg.InstanceNumber;

        AnscCopyString(pEntry->Cfg.Username, pString);

        retStatus = TRUE;
    }

    if( AnscEqualString(ParamName, "Password", TRUE))
    {
        instancenum = pEntry->Cfg.InstanceNumber;

        AnscCopyString(pEntry->Cfg.Password, pString);

        retStatus = TRUE;
    }

    pthread_mutex_unlock(&pEntry->mDataMutex);
    
    return retStatus;

}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        Interface_Validate
            (
                ANSC_HANDLE                 hInsContext,
                char*                       pReturnParamName,
                ULONG*                      puLength
            );

    description:

        This function is called to finally commit all the update.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       pReturnParamName,
                The buffer (128 bytes) of parameter name if there's a validation. 

                ULONG*                      puLength
                The output length of the param name. 

    return:     TRUE if there's no validation.

**********************************************************************/
BOOL
Interface_Validate
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pReturnParamName,
        ULONG*                      puLength
    )
{
    PDATAMODEL_PPP             pMyObject         = (PDATAMODEL_PPP      )g_pBEManager->hPPP;
    PSLIST_HEADER                   pListHead         = (PSLIST_HEADER            )&pMyObject->IfList;
    PPPP_IF_LINK_OBJECT       pLinkContext      = (PPPP_IF_LINK_OBJECT)hInsContext;
    PDML_PPP_IF_FULL           pEntry            = (PDML_PPP_IF_FULL    )pLinkContext->hContext;
    PPPP_IF_LINK_OBJECT       pLinkContext2     = (PPPP_IF_LINK_OBJECT)NULL;
    PDML_PPP_IF_FULL           pEntry2           = (PDML_PPP_IF_FULL    )NULL;
    PSINGLE_LINK_ENTRY              pSLinkEntry       = (PSINGLE_LINK_ENTRY       )NULL;

    pSLinkEntry = AnscSListGetFirstEntry(pListHead);

    pthread_mutex_lock(&pEntry->mDataMutex);

    while ( pSLinkEntry )
    {
        pLinkContext2 = ACCESS_PPP_IF_LINK_OBJECT(pSLinkEntry);
        pSLinkEntry   = AnscSListGetNextEntry(pSLinkEntry);

        pEntry2       = (PDML_PPP_IF_FULL)pLinkContext2->hContext;

        if ( 
                 pEntry2 && 
                 ((ULONG)pEntry2 != (ULONG)pEntry) && 
                 AnscEqualString(pEntry->Cfg.Alias, pEntry2->Cfg.Alias, TRUE) 
           )
        {
            AnscCopyString(pReturnParamName, "Alias");

            *puLength = AnscSizeOfString("Aliias");

            pthread_mutex_unlock(&pEntry->mDataMutex);
            
            return FALSE;
        }
    }

    pthread_mutex_unlock(&pEntry->mDataMutex);    

    return TRUE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        Interface_Commit
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to finally commit all the update.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.

**********************************************************************/
ULONG
Interface_Commit
    (
        ANSC_HANDLE                 hInsContext
    )
{
    PDATAMODEL_PPP             pMyObject               = (PDATAMODEL_PPP      )g_pBEManager->hPPP;
    PPPP_IF_LINK_OBJECT       pContextLinkObject      = (PPPP_IF_LINK_OBJECT)hInsContext;
    PDML_PPP_IF_FULL           pEntry                  = (PDML_PPP_IF_FULL    )pContextLinkObject->hContext;

    pthread_mutex_lock(&pEntry->mDataMutex);

    if ( pContextLinkObject->bNew )
    {
        pContextLinkObject->bNew = FALSE;

        PppDmlAddIfEntry(NULL, pEntry);
        PPPIfRegDelInfo((ANSC_HANDLE)pMyObject, (ANSC_HANDLE)pContextLinkObject);
    }
    else
    {
        PppDmlSetIfCfg(NULL, &pEntry->Cfg);
    }
    pthread_mutex_unlock(&pEntry->mDataMutex);    

    return 0;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        Interface_Rollback
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to roll back the update whenever there's a 
        validation found.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.

**********************************************************************/
ULONG
Interface_Rollback
    (
        ANSC_HANDLE                 hInsContext
    )
{
    PPPP_IF_LINK_OBJECT       pContextLinkObject      = (PPPP_IF_LINK_OBJECT)hInsContext;
    PDML_PPP_IF_FULL           pEntry                  = (PDML_PPP_IF_FULL)pContextLinkObject->hContext;
    
    pthread_mutex_lock(&pEntry->mDataMutex);

    PppDmlGetIfCfg(NULL, &pEntry->Cfg);

    pthread_mutex_unlock(&pEntry->mDataMutex);
    
    return 0;
}

/***********************************************************************

 APIs for Object:

    PPP.Interface.{i}.PPPoE.

    *  PPPoE_GetParamBoolValue
    *  PPPoE_GetParamIntValue
    *  PPPoE_GetParamUlongValue
    *  PPPoE_GetParamStringValue
    *  PPPoE_SetParamBoolValue
    *  PPPoE_SetParamIntValue
    *  PPPoE_SetParamUlongValue
    *  PPPoE_SetParamStringValue
    *  PPPoE_Validate
    *  PPPoE_Commit
    *  PPPoE_Rollback

***********************************************************************/
/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        PPPoE_GetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL*                       pBool
            );

    description:

        This function is called to retrieve Boolean parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL*                       pBool
                The buffer of returned boolean value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
PPPoE_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    )
{
    /* check the parameter name and return the corresponding value */

    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        PPPoE_GetParamIntValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                int*                        pInt
            );

    description:

        This function is called to retrieve integer parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                int*                        pInt
                The buffer of returned integer value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
PPPoE_GetParamIntValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        int*                        pInt
    )
{
    /* check the parameter name and return the corresponding value */

    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        PPPoE_GetParamUlongValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG*                      puLong
            );

    description:

        This function is called to retrieve ULONG parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG*                      puLong
                The buffer of returned ULONG value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
PPPoE_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      puLong
    )
{
    PPPP_IF_LINK_OBJECT       pContextLinkObject      = (PPPP_IF_LINK_OBJECT)hInsContext;
    PDML_PPP_IF_FULL           pEntry                  = (PDML_PPP_IF_FULL)pContextLinkObject->hContext;
    BOOL retStatus = FALSE;

    pthread_mutex_lock(&pEntry->mDataMutex);
    /* check the parameter name and return the corresponding value */
    if( AnscEqualString(ParamName, "SessionID", TRUE))
    {
        /* collect value */
        PPPDmlGetIfInfo(pContextLinkObject->hContext, pEntry->Cfg.InstanceNumber, &pEntry->Info);

        *puLong = pEntry->Info.SessionID;

        retStatus = TRUE;

    }
    pthread_mutex_unlock(&pEntry->mDataMutex);

    return retStatus;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        PPPoE_GetParamStringValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                char*                       pValue,
                ULONG*                      pUlSize
            );

    description:

        This function is called to retrieve string parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                char*                       pValue,
                The string value buffer;

                ULONG*                      pUlSize
                The buffer of length of string value;
                Usually size of 1023 will be used.
                If it's not big enough, put required size here and return 1;

    return:     0 if succeeded;
                1 if short of buffer size; (*pUlSize = required size)
                -1 if not supported.

**********************************************************************/
ULONG
PPPoE_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    )
{
    PPPP_IF_LINK_OBJECT       pContextLinkObject      = (PPPP_IF_LINK_OBJECT)hInsContext;
    PDML_PPP_IF_FULL           pEntry                  = (PDML_PPP_IF_FULL)pContextLinkObject->hContext;
    uint32_t retSuccess = 0;

    pthread_mutex_lock(&pEntry->mDataMutex);
    /* check the parameter name and return the corresponding value */
    if( AnscEqualString(ParamName, "ACName", TRUE))
    {
        /* collect value */
        AnscCopyString(pValue, pEntry->Cfg.ACName);
    }

    if( AnscEqualString(ParamName, "ServiceName", TRUE))
    {
        /* collect value */
        AnscCopyString(pValue, pEntry->Cfg.ServiceName);
    }
    pthread_mutex_unlock(&pEntry->mDataMutex);

    return retSuccess;

}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        PPPoE_SetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL                        bValue
            );

    description:

        This function is called to set BOOL parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL                        bValue
                The updated BOOL value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
PPPoE_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    )
{
    /* check the parameter name and set the corresponding value */

    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        PPPoE_SetParamIntValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                int                         iValue
            );

    description:

        This function is called to set integer parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                int                         iValue
                The updated integer value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
PPPoE_SetParamIntValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        int                         iValue
    )
{
    /* check the parameter name and set the corresponding value */

    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        PPPoE_SetParamUlongValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG                       uValue
            );

    description:

        This function is called to set ULONG parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG                       uValue
                The updated ULONG value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
PPPoE_SetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG                       uValue
    )
{
    /* check the parameter name and set the corresponding value */

    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        PPPoE_SetParamStringValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                char*                       pString
            );

    description:

        This function is called to set string parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                char*                       pString
                The updated string value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
PPPoE_SetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pString
    )
{
    PPPP_IF_LINK_OBJECT       pContextLinkObject      = (PPPP_IF_LINK_OBJECT)hInsContext;
    PDML_PPP_IF_FULL           pEntry                  = (PDML_PPP_IF_FULL)pContextLinkObject->hContext;
    BOOL retStatus = FALSE;

    pthread_mutex_lock(&pEntry->mDataMutex);
    /* check the parameter name and set the corresponding value */
    if( AnscEqualString(ParamName, "ACName", TRUE))
    {
        /* save update to backup */
        AnscCopyString(pEntry->Cfg.ACName, pString);

        retStatus = TRUE;
    }

    if( AnscEqualString(ParamName, "ServiceName", TRUE))
    {
        /* save update to backup */
        AnscCopyString(pEntry->Cfg.ServiceName, pString);

        retStatus = TRUE;
    }
    pthread_mutex_unlock(&pEntry->mDataMutex);

    return retStatus;

}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        PPPoE_Validate
            (
                ANSC_HANDLE                 hInsContext,
                char*                       pReturnParamName,
                ULONG*                      puLength
            );

    description:

        This function is called to finally commit all the update.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       pReturnParamName,
                The buffer (128 bytes) of parameter name if there's a validation. 

                ULONG*                      puLength
                The output length of the param name. 

    return:     TRUE if there's no validation.

**********************************************************************/
BOOL
PPPoE_Validate
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pReturnParamName,
        ULONG*                      puLength
    )
{
    return TRUE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        PPPoE_Commit
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to finally commit all the update.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.

**********************************************************************/
ULONG
PPPoE_Commit
    (
        ANSC_HANDLE                 hInsContext
    )
{
    PDATAMODEL_PPP             pMyObject               = (PDATAMODEL_PPP      )g_pBEManager->hPPP;
    PPPP_IF_LINK_OBJECT       pContextLinkObject      = (PPPP_IF_LINK_OBJECT)hInsContext;
    PDML_PPP_IF_FULL           pEntry                  = (PDML_PPP_IF_FULL    )pContextLinkObject->hContext;

    pthread_mutex_lock(&pEntry->mDataMutex);

    if ( pContextLinkObject->bNew )
    {
        pContextLinkObject->bNew = FALSE;

        PppDmlAddIfEntry(NULL, pEntry);
        PPPIfRegDelInfo((ANSC_HANDLE)pMyObject, (ANSC_HANDLE)pContextLinkObject);
    }
    else
    {
        PppDmlSetIfCfg(NULL, &pEntry->Cfg);
    }
   
    pthread_mutex_unlock(&pEntry->mDataMutex); 
    return 0;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        PPPoE_Rollback
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to roll back the update whenever there's a 
        validation found.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.

**********************************************************************/
ULONG
PPPoE_Rollback
    (
        ANSC_HANDLE                 hInsContext
    )
{
    PPPP_IF_LINK_OBJECT       pContextLinkObject      = (PPPP_IF_LINK_OBJECT)hInsContext;
    PDML_PPP_IF_FULL           pEntry                  = (PDML_PPP_IF_FULL)pContextLinkObject->hContext;

    pthread_mutex_lock(&pEntry->mDataMutex);

    PppDmlGetIfCfg(NULL, &pEntry->Cfg);

    pthread_mutex_unlock(&pEntry->mDataMutex);
    
    return 0;
}

/***********************************************************************

 APIs for Object:

    PPP.Interface.{i}.IPCP.

    *  IPCP_GetParamBoolValue
    *  IPCP_GetParamIntValue
    *  IPCP_GetParamUlongValue
    *  IPCP_GetParamStringValue
    *  IPCP_SetParamBoolValue
    *  IPCP_SetParamIntValue
    *  IPCP_SetParamUlongValue
    *  IPCP_SetParamStringValue
    *  IPCP_Validate
    *  IPCP_Commit
    *  IPCP_Rollback

***********************************************************************/
/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        IPCP_GetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL*                       pBool
            );

    description:

        This function is called to retrieve Boolean parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL*                       pBool
                The buffer of returned boolean value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
IPCP_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    )
{
    PPPP_IF_LINK_OBJECT       pContextLinkObject      = (PPPP_IF_LINK_OBJECT)hInsContext;
    PDML_PPP_IF_FULL           pEntry                  = (PDML_PPP_IF_FULL)pContextLinkObject->hContext;

    pthread_mutex_lock(&pEntry->mDataMutex);
    /* check the parameter name and return the corresponding value */
    if( AnscEqualString(ParamName, "PassthroughEnable", TRUE))
    {
        /* collect value */
        *pBool = pEntry->Cfg.PassthroughEnable;

        pthread_mutex_unlock(&pEntry->mDataMutex);

        return TRUE;
    }
    pthread_mutex_unlock(&pEntry->mDataMutex);

    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        IPCP_GetParamIntValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                int*                        pInt
            );

    description:

        This function is called to retrieve integer parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                int*                        pInt
                The buffer of returned integer value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
IPCP_GetParamIntValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        int*                        pInt
    )
{
    /* check the parameter name and return the corresponding value */

    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        IPCP_GetParamUlongValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG*                      puLong
            );

    description:

        This function is called to retrieve ULONG parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG*                      puLong
                The buffer of returned ULONG value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
IPCP_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      puLong
    )
{
    /* check the parameter name and return the corresponding value */

    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        IPCP_GetParamStringValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                char*                       pValue,
                ULONG*                      pUlSize
            );

    description:

        This function is called to retrieve string parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                char*                       pValue,
                The string value buffer;

                ULONG*                      pUlSize
                The buffer of length of string value;
                Usually size of 1023 will be used.
                If it's not big enough, put required size here and return 1;

    return:     0 if succeeded;
                1 if short of buffer size; (*pUlSize = required size)
                -1 if not supported.

**********************************************************************/
ULONG
IPCP_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    )
{
    PPPP_IF_LINK_OBJECT       pContextLinkObject      = (PPPP_IF_LINK_OBJECT)hInsContext;
    PDML_PPP_IF_FULL           pEntry                  = (PDML_PPP_IF_FULL)pContextLinkObject->hContext;
    uint32_t retStatus = -1;

    pthread_mutex_lock(&pEntry->mDataMutex);

    PPPDmlGetIfInfo(pContextLinkObject->hContext, pEntry->Cfg.InstanceNumber, &pEntry->Info);
    /* check the parameter name and return the corresponding value */
    if( AnscEqualString(ParamName, "LocalIPAddress", TRUE))
    {
        /* collect value */
        sprintf(pValue,
                "%u.%u.%u.%u",
                pEntry->Info.LocalIPAddress.Dot[0],
                pEntry->Info.LocalIPAddress.Dot[1],
                pEntry->Info.LocalIPAddress.Dot[2],
                pEntry->Info.LocalIPAddress.Dot[3]
               );
        retStatus = 0;
    }

    if( AnscEqualString(ParamName, "RemoteIPAddress", TRUE))
    {
        /* collect value */
        sprintf(pValue,
                "%u.%u.%u.%u",
                pEntry->Info.RemoteIPAddress.Dot[0],
                pEntry->Info.RemoteIPAddress.Dot[1],
                pEntry->Info.RemoteIPAddress.Dot[2],
                pEntry->Info.RemoteIPAddress.Dot[3]
               );
        retStatus = 0;
    }

    if( AnscEqualString(ParamName, "DNSServers", TRUE))
    {
        /* collect value */
        if (!pEntry->Info.DNSServers[1].Value)
            sprintf(pValue,
                    "%u.%u.%u.%u",
                    pEntry->Info.DNSServers[0].Dot[0],
                    pEntry->Info.DNSServers[0].Dot[1],
                    pEntry->Info.DNSServers[0].Dot[2],
                    pEntry->Info.DNSServers[0].Dot[3]
                   );
        else
            sprintf(pValue,
                    "%u.%u.%u.%u,%u.%u.%u.%u",
                    pEntry->Info.DNSServers[0].Dot[0],
                    pEntry->Info.DNSServers[0].Dot[1],
                    pEntry->Info.DNSServers[0].Dot[2],
                    pEntry->Info.DNSServers[0].Dot[3],
                    pEntry->Info.DNSServers[1].Dot[0],
                    pEntry->Info.DNSServers[1].Dot[1],
                    pEntry->Info.DNSServers[1].Dot[2],
                    pEntry->Info.DNSServers[1].Dot[3]
                   );
        retStatus = 0;
    }

    if( AnscEqualString(ParamName, "PassthroughDHCPPool", TRUE))
    {
        /* collect value */
        AnscCopyString(pValue, pEntry->Cfg.PassthroughDHCPPool);

        retStatus = 0;
    }
    pthread_mutex_unlock(&pEntry->mDataMutex);

    return retStatus;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        IPCP_SetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL                        bValue
            );

    description:

        This function is called to set BOOL parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL                        bValue
                The updated BOOL value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
IPCP_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    )
{
    PPPP_IF_LINK_OBJECT       pContextLinkObject      = (PPPP_IF_LINK_OBJECT)hInsContext;
    PDML_PPP_IF_FULL           pEntry                  = (PDML_PPP_IF_FULL)pContextLinkObject->hContext;

    BOOL retStatus = FALSE;

    pthread_mutex_lock(&pEntry->mDataMutex);
    /* check the parameter name and set the corresponding value */
    if( AnscEqualString(ParamName, "PassthroughEnable", TRUE))
    {
        /* save update to backup */
#ifdef _COSA_DRG_CNS_
        /*not supported*/
        retStatus = FALSE;
#else
        pEntry->Cfg.PassthroughEnable = bValue;
    
        retStatus = TRUE;
#endif
    }

    pthread_mutex_unlock(&pEntry->mDataMutex);

    return retStatus;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        IPCP_SetParamIntValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                int                         iValue
            );

    description:

        This function is called to set integer parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                int                         iValue
                The updated integer value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
IPCP_SetParamIntValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        int                         iValue
    )
{
    /* check the parameter name and set the corresponding value */

    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        IPCP_SetParamUlongValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG                       uValue
            );

    description:

        This function is called to set ULONG parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG                       uValue
                The updated ULONG value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
IPCP_SetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG                       uValue
    )
{
    /* check the parameter name and set the corresponding value */

    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        IPCP_SetParamStringValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                char*                       pString
            );

    description:

        This function is called to set string parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                char*                       pString
                The updated string value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
IPCP_SetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pString
    )
{
    PPPP_IF_LINK_OBJECT       pContextLinkObject      = (PPPP_IF_LINK_OBJECT)hInsContext;
    PDML_PPP_IF_FULL           pEntry                  = (PDML_PPP_IF_FULL)pContextLinkObject->hContext;
    BOOL retStatus = FALSE;

    if(pEntry == NULL)
    {
        return FALSE;
    }

    pthread_mutex_lock(&pEntry->mDataMutex);
    /* check the parameter name and set the corresponding value */
    if( AnscEqualString(ParamName, "PassthroughDHCPPool", TRUE))
    {
        /* save update to backup */
#ifdef _COSA_DRG_CNS_
        /*not supported*/
        retStatus = FALSE;
#else
        AnscCopyString(pEntry->Cfg.PassthroughDHCPPool, pString);

        retStatus = TRUE;
#endif
    }

    pthread_mutex_unlock(&pEntry->mDataMutex);

    return retStatus;

}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        IPCP_Validate
            (
                ANSC_HANDLE                 hInsContext,
                char*                       pReturnParamName,
                ULONG*                      puLength
            );

    description:

        This function is called to finally commit all the update.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       pReturnParamName,
                The buffer (128 bytes) of parameter name if there's a validation. 

                ULONG*                      puLength
                The output length of the param name. 

    return:     TRUE if there's no validation.

**********************************************************************/
BOOL
IPCP_Validate
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pReturnParamName,
        ULONG*                      puLength
    )
{
    return TRUE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        IPCP_Commit
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to finally commit all the update.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.

**********************************************************************/
ULONG
IPCP_Commit
    (
        ANSC_HANDLE                 hInsContext
    )
{
    PDATAMODEL_PPP             pMyObject               = (PDATAMODEL_PPP      )g_pBEManager->hPPP;
    PPPP_IF_LINK_OBJECT       pContextLinkObject      = (PPPP_IF_LINK_OBJECT)hInsContext;
    PDML_PPP_IF_FULL           pEntry                  = (PDML_PPP_IF_FULL    )pContextLinkObject->hContext;

    pthread_mutex_lock(&pEntry->mDataMutex);

    if ( pContextLinkObject->bNew )
    {
        pContextLinkObject->bNew = FALSE;

        PppDmlAddIfEntry(NULL, pEntry);
        PPPIfRegDelInfo((ANSC_HANDLE)pMyObject, (ANSC_HANDLE)pContextLinkObject);
    }
    else
    {
        PppDmlSetIfCfg(NULL, &pEntry->Cfg);
    }
    pthread_mutex_unlock(&pEntry->mDataMutex);
    
    return 0;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        IPCP_Rollback
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to roll back the update whenever there's a 
        validation found.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.

**********************************************************************/
ULONG
IPCP_Rollback
    (
        ANSC_HANDLE                 hInsContext
    )
{
    PPPP_IF_LINK_OBJECT       pContextLinkObject      = (PPPP_IF_LINK_OBJECT)hInsContext;
    PDML_PPP_IF_FULL           pEntry                  = (PDML_PPP_IF_FULL)pContextLinkObject->hContext;

    pthread_mutex_lock(&pEntry->mDataMutex);

    PppDmlGetIfCfg(NULL, &pEntry->Cfg);

    pthread_mutex_unlock(&pEntry->mDataMutex);
    
    return 0;
}

/***********************************************************************

 APIs for Object:

    PPP.Interface.{i}.IPv6CP.

    * IPv6CP_GetParamStringValue 

***********************************************************************/
/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        IPv6CP_GetParamStringValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                char*                       pValue,
                ULONG*                      pUlSize
            );

    description:

        This function is called to retrieve string parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                char*                       pValue,
                The string value buffer;

                ULONG*                      pUlSize
                The buffer of length of string value;
                Usually size of 45 will be used.
                If it's not big enough, put required size here and return 1;

    return:     0 if succeeded;
                1 if short of buffer size; (*pUlSize = required size)
                -1 if not supported.

**********************************************************************/

ULONG
IPv6CP_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    )
{
    PPPP_IF_LINK_OBJECT       pContextLinkObject      = (PPPP_IF_LINK_OBJECT)hInsContext;
    PDML_PPP_IF_FULL           pEntry                  = (PDML_PPP_IF_FULL)pContextLinkObject->hContext;
    uint32_t retStatus = -1;
    
    pthread_mutex_lock(&pEntry->mDataMutex);

    PPPDmlGetIfInfo(pContextLinkObject->hContext, pEntry->Cfg.InstanceNumber, &pEntry->Info);
    /* check the parameter name and return the corresponding value */
    if( AnscEqualString(ParamName, "LocalInterfaceIdentifier", TRUE))
    {
        sprintf(pValue, pEntry->Info.Ip6LocalIfID);

        retStatus = 0;
    }
    else if ( AnscEqualString(ParamName, "RemoteInterfaceIdentifier", TRUE)) 
    {
        sprintf(pValue, pEntry->Info.Ip6RemoteIfID);

        retStatus = 0;
    }
    pthread_mutex_unlock(&pEntry->mDataMutex);

    return retStatus;
}


/***********************************************************************

 APIs for Object:

    PPP.Interface.{i}.Stats.

    *  Stats_GetParamUlongValue

***********************************************************************/
/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        Stats_GetParamUlongValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG*                      puLong
            );

    description:

        This function is called to retrieve ULONG parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG*                      puLong
                The buffer of returned ULONG value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
Stats_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      puLong
    )
{
    PPPP_IF_LINK_OBJECT       pContextLinkObject      = (PPPP_IF_LINK_OBJECT)hInsContext;
    PDML_PPP_IF_FULL           pEntry                  = (PDML_PPP_IF_FULL)pContextLinkObject->hContext;
    DML_IF_STATS               Stats = {0};
    BOOL retStatus = FALSE;

    PppDmlGetIfStats(NULL, pEntry->Cfg.InstanceNumber, &Stats, pEntry);

    pthread_mutex_lock(&pEntry->mDataMutex);
    /* check the parameter name and return the corresponding value */
    if( AnscEqualString(ParamName, "BytesSent", TRUE))
    {
        /* collect value */
        *puLong = Stats.BytesSent;

        retStatus = TRUE;
    }

    if( AnscEqualString(ParamName, "BytesReceived", TRUE))
    {
        /* collect value */
        *puLong = Stats.BytesReceived;

        retStatus = TRUE;
    }

    if( AnscEqualString(ParamName, "PacketsSent", TRUE))
    {
        /* collect value */
        *puLong = Stats.PacketsSent;

        retStatus = TRUE;
    }

    if( AnscEqualString(ParamName, "PacketsReceived", TRUE))
    {
        /* collect value */
        *puLong = Stats.PacketsReceived;

        retStatus = TRUE;
    }

    if( AnscEqualString(ParamName, "ErrorsSent", TRUE))
    {
        /* collect value */
        *puLong = Stats.ErrorsSent;

        retStatus = TRUE;
    }

    if( AnscEqualString(ParamName, "ErrorsReceived", TRUE))
    {
        /* collect value */
        *puLong = Stats.ErrorsReceived;

        retStatus = TRUE;
    }

    if( AnscEqualString(ParamName, "UnicastPacketsSent", TRUE))
    {
        /* collect value */
        *puLong = Stats.UnicastPacketsSent;

        retStatus = TRUE;
    }

    if( AnscEqualString(ParamName, "UnicastPacketsReceived", TRUE))
    {
        /* collect value */
        *puLong = Stats.UnicastPacketsReceived;

        retStatus = TRUE;
    }

    if( AnscEqualString(ParamName, "DiscardPacketsSent", TRUE))
    {
        /* collect value */
        *puLong = Stats.DiscardPacketsSent;

        retStatus = TRUE;
    }

    if( AnscEqualString(ParamName, "DiscardPacketsReceived", TRUE))
    {
        /* collect value */
        *puLong = Stats.DiscardPacketsReceived;

        retStatus = TRUE;
    }

    if( AnscEqualString(ParamName, "MulticastPacketsSent", TRUE))
    {
        /* collect value */
        *puLong = Stats.MulticastPacketsSent;

        retStatus = TRUE;
    }

    if( AnscEqualString(ParamName, "MulticastPacketsReceived", TRUE))
    {
        /* collect value */
        *puLong = Stats.MulticastPacketsReceived;

        retStatus = TRUE;
    }

    if( AnscEqualString(ParamName, "BroadcastPacketsSent", TRUE))
    {
        /* collect value */
        *puLong = Stats.BroadcastPacketsSent;

        retStatus = TRUE;
    }

    if( AnscEqualString(ParamName, "BroadcastPacketsReceived", TRUE))
    {
        /* collect value */
        *puLong = Stats.BroadcastPacketsReceived;

        retStatus = TRUE;
    }

    if( AnscEqualString(ParamName, "UnknownProtoPacketsReceived", TRUE))
    {
        /* collect value */
        *puLong = Stats.UnknownProtoPacketsReceived;

        retStatus = TRUE;
    }
    pthread_mutex_unlock(&pEntry->mDataMutex);

    return retStatus;

}

