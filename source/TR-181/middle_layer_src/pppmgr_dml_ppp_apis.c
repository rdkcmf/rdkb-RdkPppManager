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
#include "pppmgr_dml_ppp_apis.h"
#include "pppmgr_dml.h"
#include <regex.h>

#define NET_STATS_FILE "/proc/net/dev"
#define PPPoE_VLAN_IF_NAME  "vlan101"
#define GET_PPPID_ATTEMPT 5
#define PPP_LCPEcho 30
#define PPP_LCPEchoRetry 3

extern char g_Subsystem[32];
extern ANSC_HANDLE bus_handle;

extern PBACKEND_MANAGER_OBJECT               g_pBEManager;
static void* PppMgr_StartPppdDaemon( void *arg );
static void* PppMgr_ResetPppdDaemon( void *arg);

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

ANSC_STATUS GetNumOfInstance (int *count)
{

   int ret_val = ANSC_STATUS_SUCCESS;
   int retPsmGet = CCSP_SUCCESS;
   char* param_value = NULL;

   retPsmGet = PSM_Get_Record_Value2(bus_handle,g_Subsystem, PSM_PPPMANAGER_PPPIFCOUNT, NULL, &param_value);
   if (retPsmGet != CCSP_SUCCESS) { \
        AnscTraceFlow(("%s Error %d reading %s %s\n", __FUNCTION__, retPsmGet, PSM_PPPMANAGER_PPPIFCOUNT, param_value));
        ret_val = ANSC_STATUS_FAILURE;
   }
   else if(param_value != NULL) {
        sscanf(param_value, "%d", count);
        ((CCSP_MESSAGE_BUS_INFO *)bus_handle)->freefunc(param_value);
    }

   return ret_val;

}


ULONG DmlGetTotalNoOfPPPInterfaces
(
  ANSC_HANDLE                 hContext
)
{
    int ppp_if_count = 0 ;
    
    GetNumOfInstance(&ppp_if_count);

    return ppp_if_count;
}


ANSC_STATUS
PppDmlGetIfStats
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulPppIfInstanceNumber,
        PDML_IF_STATS          pStats,
        PDML_PPP_IF_FULL            pEntry
)
{
    char wan_interface[10] = {0};

    AnscCopyString( wan_interface, pEntry->Cfg.Alias);
    CosaUtilGetIfStats(wan_interface,pStats);
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
    //TODO Need to revisit
    /*not supported*/
    pInfo->EncryptionProtocol  =  DML_PPP_ENCRYPTION_None;
    pInfo->CompressionProtocol = DML_PPP_COMPRESSION_None;

    /*hardcoded by backend*/
    pInfo->LCPEchoRetry = PPP_LCPEchoRetry;
    pInfo->LCPEcho      = PPP_LCPEcho;

    pInfo->SessionID    = 0;
    get_session_id(&pInfo->SessionID, hContext);

    return ANSC_STATUS_SUCCESS;
}

BOOL
PppDmlIfEnable
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulInstanceNumber,
        PDML_PPP_IF_FULL            pEntry
    )
{

    char command[1024] = { 0 };
    char config_command[1024] = { 0 };
    char service_name[256] = { 0 };
    char auth_proto[8] = { 0 };
    pthread_t pppdThreadId;
    uint32_t getAttempts = 0;
    char buff[10] = { 0 };
    char vlan_id[10] = { 0 };
    char physical_interface[14]= { 0 };
    char VLANInterfaceName[32] = { 0 };
    int ret ;
    char acTmpQueryParam[256] = {0};

    if(pEntry->Cfg.bEnabled == true )
    {
        if(ANSC_STATUS_SUCCESS == PppMgr_checkPidExist(pEntry->Info.pppPid))
        {
            CcspTraceInfo(("pppd is already running \n"));

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
            if(pEntry->Cfg.LinkType == DML_PPPoA_LINK_TYPE)
            {
#ifdef USE_PPP_DAEMON
                 snprintf(command, sizeof(command), "pppd -6 -c %s -a %s -u %s -p %s -f %s &",
                     pEntry->Cfg.Alias, pEntry->Info.InterfaceServiceName, pEntry->Cfg.Username,
                     pEntry->Cfg.Password, auth_proto);
#else
                 /* Assume a default rp-pppoe config exist. Update rp-pppoe configuration */
                 ret =  snprintf(config_command, sizeof(config_command), "pppoe_config.sh %s %s %s %s PPPoA %d %d",
                     pEntry->Cfg.Username, pEntry->Cfg.Password, pEntry->Info.InterfaceServiceName, pEntry->Cfg.Alias, pEntry->Info.LCPEcho, pEntry->Info.LCPEchoRetry);
                 if(ret > 0 && ret <= sizeof(config_command))
		 {
                     system(config_command);
		 }
                 /* start rp-pppoe */
                 ret = snprintf(command, sizeof(command), "/usr/sbin/pppoe-start");
                 if(ret > 0 && ret <= sizeof(command))
                 {
		     CcspTraceInfo((" successfully started rp-pppoe \n"));
                 }
#endif
            }
            else if (pEntry->Cfg.LinkType == DML_PPPoE_LINK_TYPE)
            {
#ifdef USE_PPP_DAEMON
                 snprintf(command, sizeof(command), "pppd -6 -c %s -i %s -u %s -p %s -f %s &",
                    pEntry->Cfg.Alias, PPPoE_VLAN_IF_NAME, pEntry->Cfg.Username, pEntry->Cfg.Password, auth_proto);
#else
                 ret = snprintf(acTmpQueryParam, sizeof(acTmpQueryParam),"%s.%s",pEntry->Cfg.LowerLayers,"Name");
                 if(ret > 0 && ret <= sizeof(config_command))
                 {
                     if(ANSC_STATUS_FAILURE == DmlPppMgrGetParamValues(WAN_COMPONENT_NAME, WAN_DBUS_PATH, acTmpQueryParam, VLANInterfaceName))
                     {
                         CcspTraceError(("%s %d Failed to get param value\n", __FUNCTION__, __LINE__));
                         return ANSC_STATUS_FAILURE;
                     } 
                 }

                 CcspTraceInfo(("VLAN  %s - %s \n",acTmpQueryParam,VLANInterfaceName));
		 /* Assume a defule rp-pppoe config exist. Update rp-pppoe configuration */
		 ret = snprintf(config_command, sizeof(config_command), "pppoe_config.sh '%s' '%s' %s %s PPPoE %d %d %d ",
				 pEntry->Cfg.Username, pEntry->Cfg.Password, VLANInterfaceName, pEntry->Cfg.Alias, pEntry->Info.LCPEcho , pEntry->Info.LCPEchoRetry,pEntry->Cfg.MaxMRUSize);
                 if(ret > 0 && ret <= sizeof(config_command))
                 {
                     system(config_command);
                 }

		 /* start rp-pppoe */
                 ret = snprintf(command, sizeof(command), "/usr/sbin/pppoe-start");
                 if(ret > 0 && ret <= sizeof(command))
                 {
                     CcspTraceInfo((" successfully started rp-pppoe \n"));
                 }
#endif
            }
                CcspTraceInfo(("parameters were set\n"));
         }
	else
	{
		return FALSE;
	}
	CcspTraceInfo(("command to execute is  '%s'\n", command));
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

        pthread_mutex_unlock(&pEntry->mDataMutex);

	CcspTraceInfo(("pid table value  '%d'\n", pEntry->Info.pppPid));
    }
    else
    {
#ifdef USE_PPP_DAEMON
	PppMgr_stopPppProcess(pEntry->Info.pppPid);

	pEntry->Info.pppPid = 0;
#else
	PppMgr_stopPppoe();
#endif
    }

    return TRUE;
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

ANSC_STATUS
PppDmlIfReset
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulInstanceNumber,
        PDML_PPP_IF_FULL            pEntry
    )
{
    pthread_t pppdThreadId;
    PRESET_THREAD_ARGS pthread_args;
    pthread_args = malloc(sizeof(RESET_THREAD_ARGS) * 1);
    pthread_args->pEntry=pEntry;
    pthread_args->ulInstanceNumber = ulInstanceNumber;
    int iErrorCode = pthread_create( &pppdThreadId, NULL, &PppMgr_ResetPppdDaemon,pthread_args);
    if( 0 != iErrorCode )
    {
        CcspTraceInfo(("%s %d - Failed to start Pppmgr_ResetPppdDaemon  %d\n", __FUNCTION__, __LINE__,iErrorCode ));
    }

    return ANSC_STATUS_SUCCESS;
}

static void* PppMgr_ResetPppdDaemon( void *arg )
{
    //TODO : Need to Revisit
    PRESET_THREAD_ARGS pReset = arg;
    pReset->pEntry->Cfg.bEnabled = false;
    sleep(5);
    PppDmlIfEnable(NULL,pReset->ulInstanceNumber,pReset->pEntry);
    sleep(10);
    pReset->pEntry->Cfg.bEnabled = true;
    PppDmlIfEnable(NULL,pReset->ulInstanceNumber,pReset->pEntry);
    free(arg);
    pthread_exit(NULL);
    return NULL;
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

int validateUsername( char* pString)
{
    int ret=-1;
    regex_t reg;
    const char *Url_Pattern= "^[a-zA-Z0-9_#-.@]*$";
    regcomp(&reg ,Url_Pattern, REG_EXTENDED);
    ret = regexec(&reg, pString, 0, NULL, 0);
    if (ret == 0) {
        return 0;
    }
    else {
       CcspTraceWarning(("Invalid username '%s'\n", pString));
       return -1;
    }
}

int PppMgr_RdkBus_SetParamValuesToDB( char *pParamName, char *pParamVal )
{
    int     retPsmSet  = CCSP_SUCCESS;
    /* Input Validation */
    if( ( NULL == pParamName) || ( NULL == pParamVal ) )
    {
        CcspTraceError(("%s Invalid Input Parameters\n",__FUNCTION__));
        return CCSP_FAILURE;
    }

    retPsmSet = PSM_Set_Record_Value2(bus_handle,g_Subsystem, pParamName, ccsp_string, pParamVal);
    if (retPsmSet != CCSP_SUCCESS) {
        CcspTraceError(("%s Error %d writing %s\n", __FUNCTION__, retPsmSet, pParamName));
    }

    return retPsmSet;
}

static int PppManager_SetParamFromPSM(PDML_PPP_IF_FULL pEntry)
{
    int retPsmSet = CCSP_SUCCESS;
    char param_name[256] = {0};
    char param_value[256] = {0};
    int instancenum = 0;

    instancenum = pEntry->Cfg.InstanceNumber;

    CcspTraceWarning(("%s-%d:instancenum=%d \n",__FUNCTION__, __LINE__, instancenum));

    memset(param_value, 0, sizeof(param_value));
    memset(param_name, 0, sizeof(param_name));

    sprintf(param_value, "%d", pEntry->Cfg.IdleDisconnectTime);
    sprintf(param_name, PSM_PPP_IDLETIME, instancenum);
    PppMgr_RdkBus_SetParamValuesToDB(param_name,param_value);

    memset(param_value, 0, sizeof(param_value));
    memset(param_name, 0, sizeof(param_name));
	
    sprintf(param_value, "%d", pEntry->Cfg.MaxMRUSize);
    sprintf(param_name, PSM_PPP_MAXMRUSIZE, instancenum);
    PppMgr_RdkBus_SetParamValuesToDB(param_name,param_value);

    memset(param_value, 0, sizeof(param_value));
    memset(param_name, 0, sizeof(param_name));

    sprintf(param_value, "%s", pEntry->Cfg.Username);
    sprintf(param_name, PSM_PPP_USERNAME, instancenum);
    PppMgr_RdkBus_SetParamValuesToDB(param_name,param_value);

    memset(param_value, 0, sizeof(param_value));
    memset(param_name, 0, sizeof(param_name));

    sprintf(param_value, "%s", pEntry->Cfg.Password);
    sprintf(param_name, PSM_PPP_PASSWORD, instancenum);
    PppMgr_RdkBus_SetParamValuesToDB(param_name,param_value);

    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS
PppDmlSetIfCfg
    (
        ANSC_HANDLE                 hContext,
        PDML_PPP_IF_CFG        pCfg        /* Identified by InstanceNumber */
    )
{
     int ret_val = ANSC_STATUS_SUCCESS;
     ret_val = PppManager_SetParamFromPSM(pCfg);
     if(ret_val != ANSC_STATUS_SUCCESS)
     {
         CcspTraceError(("%s %d Failed \n", __FUNCTION__, __LINE__));
     }

     return ret_val;
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
PppDmlGetIfEntry
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulIndex,
        PDML_PPP_IF_FULL       pEntry
    )
{
    if (!pEntry)
    {
        return ANSC_STATUS_FAILURE;
    }

    PppDmlGetDefaultValues(hContext,ulIndex+1,pEntry);

    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS
PppDmlGetDefaultValues
      (
        ANSC_HANDLE hContext,
        ULONG  ulIndex,
        PDML_PPP_IF_FULL pEntry
      )
{
    int retPsmGet = CCSP_SUCCESS;
    char* param_value = NULL;
    char param_name[256]= {0};
    char buff[10];

    if (!pEntry)
    {
        return ANSC_STATUS_FAILURE;
    }

    AnscCopyString(pEntry->Cfg.Alias, "erouter0");

    /* Get service name */
    sprintf(param_name, PSM_PPP_IF_SERVICE_NAME,ulIndex);
    retPsmGet = PSM_Get_Record_Value2(bus_handle, g_Subsystem, param_name, NULL, &param_value);
    if (retPsmGet == CCSP_SUCCESS && param_value != NULL)
    {
         sscanf(param_value, "%s", pEntry->Info.InterfaceServiceName);
    }

    /* Get interface name */
    sprintf(param_name, PSM_PPP_IF_NAME,ulIndex);
    retPsmGet = PSM_Get_Record_Value2(bus_handle, g_Subsystem, param_name, NULL, &param_value);
    if (retPsmGet == CCSP_SUCCESS && param_value != NULL)
    {
         sscanf(param_value, "%s", pEntry->Info.Name);
    }

    /* Get default authentication protocol */
    sprintf(param_name, PSM_PPP_AUTH_PROTOCOL,ulIndex);
    retPsmGet = PSM_Get_Record_Value2(bus_handle, g_Subsystem, param_name, NULL, &param_value);
    if (retPsmGet == CCSP_SUCCESS && param_value != NULL)
    {
        if (strcmp(param_value, "DML_PPP_AUTH_CHAP") == 0)
        {
           pEntry->Info.AuthenticationProtocol = DML_PPP_AUTH_CHAP;
        }
    }

    /* Get last connection error */
    sprintf(param_name, PSM_PPP_LAST_COONECTION_ERROR,ulIndex);
    retPsmGet = PSM_Get_Record_Value2(bus_handle, g_Subsystem, param_name, NULL, &param_value);
    if (retPsmGet == CCSP_SUCCESS && param_value != NULL)
    {
        if(strcmp(param_value,"DML_PPP_CONN_ERROR_NONE") == 0)
        {
             pEntry->Info.LastConnectionError = DML_PPP_CONN_ERROR_NONE;
        }
    }

   /* Get idle time  */
   sprintf(param_name, PSM_PPP_IDLETIME, ulIndex);
   retPsmGet = PSM_Get_Record_Value2(bus_handle, g_Subsystem, param_name, NULL, &param_value);
   if (retPsmGet == CCSP_SUCCESS && param_value != NULL)
   {
         sscanf(param_value, "%s",buff);
         pEntry->Cfg.IdleDisconnectTime = atoi(buff);
   }

   /* Get max mru size  */
   sprintf(param_name, PSM_PPP_MAXMRUSIZE, ulIndex);
   retPsmGet = PSM_Get_Record_Value2(bus_handle, g_Subsystem, param_name, NULL, &param_value);
   if (retPsmGet == CCSP_SUCCESS && param_value != NULL)
   {
         sscanf(param_value, "%s",buff);
         pEntry->Cfg.MaxMRUSize = atoi(buff);
   }

   /* Get link type */
   sprintf(param_name,PSM_PPP_LINK_TYPE,ulIndex);
   retPsmGet = PSM_Get_Record_Value2(bus_handle, g_Subsystem, param_name, NULL, &param_value);
   if (retPsmGet == CCSP_SUCCESS && param_value != NULL)
   {
        if(strcmp(param_value,"PPPoA") == 0)
        {
            pEntry->Cfg.LinkType = DML_PPPoA_LINK_TYPE;
        }
        else if(strcmp(param_value,"PPPoE") == 0)
        {
	    pEntry->Cfg.LinkType = DML_PPPoE_LINK_TYPE;
        }
   }

   /*Get the Username */
   sprintf(param_name, PSM_PPP_USERNAME,ulIndex);
   retPsmGet = PSM_Get_Record_Value2(bus_handle, g_Subsystem, param_name, NULL, &param_value);
   if (retPsmGet == CCSP_SUCCESS && param_value != NULL)
   {
        sscanf(param_value, "%s", pEntry->Cfg.Username);
   }
   
   /* Get the Password */
   sprintf(param_name, PSM_PPP_PASSWORD,ulIndex);
   retPsmGet = PSM_Get_Record_Value2(bus_handle, g_Subsystem, param_name, NULL, &param_value);
   if (retPsmGet == CCSP_SUCCESS && param_value != NULL)
   {
        sscanf(param_value, "%s", pEntry->Cfg.Password);
   }

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

ANSC_STATUS PppMgr_stopPppoe(void)
{
    v_secure_system("/usr/sbin/pppoe-stop");

    return ANSC_STATUS_SUCCESS;
}

pid_t PppMgr_getPppPid()
{
    char line[64] = { 0 };
    FILE *command = NULL;
    pid_t pid = 0;

    command = popen("pidof pppd", "r");

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

ULONG GetUptimeinSeconds ()
{
    char acGetParamValue[DATAMODEL_PARAM_LENGTH] = { 0 };
    ULONG UpTime = 0;

    if(DmlPppMgrGetParamValues(PANDM_COMPONENT_NAME, PANDM_DBUS_PATH, UP_TIME_PARAM_NAME, acGetParamValue) != ANSC_STATUS_SUCCESS)
    {
        CcspTraceError(("%s %d Failed to get UpTime value\n", __FUNCTION__, __LINE__));
    }
    else
    {
        sscanf(acGetParamValue, "%lu", &UpTime);
    }

    return UpTime;
}

#define PPPOE_PROC_FILE "/proc/net/pppoe"
static int get_session_id_from_proc_entry(ULONG * p_id)
{
    FILE * fp;
    char buf[1024] = {0};
    if(fp = fopen(PPPOE_PROC_FILE, "r"))
    {
        /* Skip first line of /proc/net/pppoe */
        /* Id Address Device */
        fgets(buf, sizeof(buf)-1, fp);
        while(fgets(buf, sizeof(buf)-1, fp))
        {
            unsigned long id = 0L;
            if(sscanf(buf, "%08X", &id) == 1)
            {
                *p_id = ntohs(id);
                CcspTraceInfo(("PPP Session ID: %08X, %d \n", id, *p_id));
            }
        }
        fclose(fp);
    }
    return 0;
}

int CosaUtilGetIfStats(char *ifname, PDML_IF_STATS pStats)
{
    int    i;
    FILE * fp;
    char buf[1024] = {0} ;
    char * p;
    int    ret = 0;

    fp = fopen(NET_STATS_FILE, "r");

    if(fp)
    {
        i = 0;
        while(fgets(buf, sizeof(buf), fp))
        {
            if(++i <= 2)
                continue;
            if(p = strchr(buf, ':'))
            {
                if(strstr(buf, ifname))
                {
                    memset(pStats, 0, sizeof(*pStats));
                    if (sscanf(p+1, "%d %d %d %d %*d %*d %*d %*d %d %d %d %d %*d %*d %*d %*d",
                    &pStats->BytesReceived, &pStats->PacketsReceived, &pStats->ErrorsReceived,
                    &pStats->DiscardPacketsReceived,&pStats->BytesSent, &pStats->PacketsSent,
                    &pStats->ErrorsSent, &pStats->DiscardPacketsSent) == 8)
                    {
                        ret = 1;
                        break;
                    }
                }
            }
        }
    }

    fclose(fp);
    return ret;
}
