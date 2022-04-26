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

/* ---- Include Files ---------------------------------------- */
#include <sys/un.h>
#include <errno.h>
#include <regex.h>
#include "pppmgr_ssp_global.h"
#include "pppmgr_dml_plugin_main_apis.h"
#include "pppmgr_dml.h"
#include <ipc_msg.h> 
#include "pppmgr_dml_ppp_apis.h"

#define PPP_MGR_IPC_SERVER    1
#define GET_PPPID_ATTEMPT    5
#define DHCPV6_PATH           "/etc/dibbler/%s/"
#define DHCPV6_DUID_FILE      "client-duid"
#define PROC_UUID_PATH        "/proc/sys/kernel/random/uuid"
#define PHY_IF_MAC_PATH       "/sys/class/net/atm0/address"
#if defined (DUID_UUID_ENABLE)
#define DUID_TYPE "0004"  /* duid-type duid-uuid 4 */
#else
#define DUID_TYPE "00:03:"  /* duid-type duid-ll 3 */
#define HW_TYPE "00:01:"    /* hw type is always 1 */
#endif

/* pppd exit status */
#define PPP_EXIT_USER_REQUEST        5
#define PPP_EXIT_PEER_AUTH_FAILED    11
#define PPP_EXIT_IDLE_TIMEOUT        12
#define PPP_EXIT_HANGUP              16
#define PPP_EXIT_AUTH_TOPEER_FAILED  19

/* ---- private Functions ------------------------------------ */
static ANSC_STATUS PppMgr_createIpcSockFd( int32_t  *sockFd, uint32_t sockMode);
static ANSC_STATUS  PppMgr_bindIpcSocket( int32_t sockFd);
static void* PppMgr_IpcServerThread( void *arg );
static ANSC_STATUS PppMgr_IpcServerInit();
static PSINGLE_LINK_ENTRY PppMgr_DmlGetLinkEntry(pid_t pid, char *interface);
static ANSC_STATUS PppMgr_DmlSetIp4Param (char * ipbuff, char * ipCharArr);
static ANSC_STATUS PppMgr_ProcessStateChangedMsg(PDML_PPP_IF_FULL pNewEntry, ipc_ppp_event_msg_t pppEventMsg);
static ANSC_STATUS PppMgr_receiveIpcSocket(int32_t sockFd, char *msg, uint32_t *msgLen);
static ANSC_STATUS PppMgr_ProcessIpcpParams(PDML_PPP_IF_FULL pNewEntry, ipc_ppp_event_msg_t pppEventMsg);
static ANSC_STATUS PppMgr_ProcessIpv6cpParams(PDML_PPP_IF_FULL pNewEntry, ipc_ppp_event_msg_t pppEventMsg);
static ANSC_STATUS PppMgr_ProcessIpcMsg(ipc_msg_payload_t ipcMsg);

/* ------------------extern variables -------------------------*/
extern PBACKEND_MANAGER_OBJECT               g_pBEManager;
extern  ANSC_HANDLE bus_handle;

/*-------------------public functions---------------------------------------*/
ANSC_STATUS PppMgr_createIpcSocket(int32_t *sockFd, uint32_t sockMode);
ANSC_STATUS PppMgr_StartIpcServer();

/* ---- Private Variables ------------------------------------ */
static int   ipcListenFd;   /* Unix domain IPC listening socket fd */
static char *pppStateNames[] =
{
    [PPP_INTERFACE_UP] = "PPP_INTERFACE_UP",
    [PPP_INTERFACE_DOWN] = "PPP_INTERFACE_DOWN",
    [PPP_INTERFACE_UNCONFIGURED] = "PPP_INTERFACE_UNCONFIGURED",
    [PPP_INTERFACE_CONNECTING]= "PPP_INTERFACE_CONNECTING",
    [PPP_INTERFACE_AUTHENTICATING] = "[PPP_INTERFACE_AUTHENTICATING",
    [PPP_INTERFACE_PENDING_DISCONNET] = "PPP_INTERFACE_PENDING_DISCONNET",
    [PPP_INTERFACE_DISCONNECTING] = "PPP_INTERFACE_DISCONNECTING",
    [PPP_INTERFACE_DISCONNECTED] = "PPP_INTERFACE_DISCONNECTED",
    [PPP_INTERFACE_LCP_ECHO_FAILED] = "PPP_INTERFACE_LCP_ECHO_FAILED",
    [PPP_INTERFACE_AUTH_FAILED] = "PPP_INTERFACE_AUTH_FAILED",
    [PPP_IPCP_COMPLETED] = "PPP_IPCP_COMPLETED",
    [PPP_IPCP_FAILED] = "PPP_IPCP_FAILED",
    [PPP_IPV6CP_COMPLETED] = "PPP_IPV6CP_COMPLETED",
    [PPP_IPV6CP_FAILED] = "PPP_IPV6CP_FAILED",
    [PPP_LCP_AUTH_COMPLETED] = "PPP_LCP_AUTH_COMPLETED",
    [PPP_MAX_STATE] = "PPP_MAX_STATE"

};

struct UpdateWanManager_args{
    INT WANInstance;
    char LinkStatus[6];
};

/* ---------------------------------------------------------------------------
   This internal API will convert state to string
----------------------------------------------------------------------------*/
static char* pppStatetoString(uint8_t state)
{
    if(state < PPP_MAX_STATE)
    {
        return pppStateNames[state];
    }
    return pppStateNames[PPP_MAX_STATE];
}


/* ---------------------------------------------------------------------------
   This internal API will get the DUID and save it to a file
----------------------------------------------------------------------------*/
static void PppMgr_GenerateDuidFile (char *wanName)
{

    char buff[256] = {0};

    FILE *fd = NULL;

#if defined (DUID_UUID_ENABLE)
    memset(buff, 0, sizeof(buff));
    if (syscfg_get(NULL, "UUID", uuid, sizeof(uuid)) != ANSC_STATUS_SUCCESS)
    {
        snprintf(buff, sizeof(buff), "cat %s | tr -d -", PROC_UUID_PATH);

        fd = popen(buff, "r");
        if(fd == NULL)
        {
            CcspTraceError(("%s %d: Failed to ger uuid entry\n", __FUNCTION__, __LINE__));
            pclose(fd);
            return;
        }

        fgets(uuid, sizeof(uuid), fd);
        pclose(fd);

        syscfg_set(NULL, "UUID", uuid);
        syscfg_commit();
    }
#endif

    // get mac from physical interface
    char mac[64] = {0};

    memset(mac, 0, sizeof(mac));

    fd = fopen(PHY_IF_MAC_PATH, "r");
    if(fd == NULL)
    {
        CcspTraceError(("%s %d:Failed to open mac address table\n", __FUNCTION__, __LINE__));
        fclose(fd);
        return;
    }

    fread(mac, sizeof(mac), 1, fd);
    fclose(fd);

    CcspTraceInfo(("%s %d: MAC of phyical interface is %s \n", __FUNCTION__, __LINE__, mac));

    // get the dhcp config path

    char file_path[256] = {0};
    struct stat st = {0};

    memset(file_path, 0, sizeof(file_path));

    snprintf(file_path, sizeof(file_path), DHCPV6_PATH, wanName);

    if (stat(file_path, &st) == -1)
    {
        // directory does not exists, so create it
        mkdir(file_path, 0644);
        CcspTraceInfo(("%s %d: created directory %s\n", __FUNCTION__, __LINE__, file_path));
    }

    strcat (file_path, DHCPV6_DUID_FILE);

    // wite duid in duid-client file
    FILE * fp_duid = fopen(file_path, "w");
    if (fp_duid == NULL)
    {
        CcspTraceError(("%s %d: cannot open file:%s due to %s\n", __FUNCTION__, __LINE__, file_path, strerror(errno)))
        return;
    }

    memset(buff, 0, sizeof(buff));

    sprintf(buff, DUID_TYPE);
#if defined (DUID_UUID_ENABLE)
    sprintf(buff+4, uuid);
#else
    sprintf(buff+6, HW_TYPE);
    sprintf(buff+12, mac);
#endif
    fprintf(fp_duid, "%s", buff);
    fclose(fp_duid);

}

static void PppMgr_RemoveDuidFile (char *wanName)
{

    struct stat st = {0};
    char file_path[256] = {0};


    memset(file_path, 0, sizeof(file_path));

    snprintf(file_path, sizeof(file_path), DHCPV6_PATH DHCPV6_DUID_FILE, wanName);

    if (stat(file_path, &st) != -1)
    {
        // directory does not exists, so create it
        CcspTraceInfo(("%s %d: deleting  %s\n", __FUNCTION__, __LINE__, file_path));
        remove(file_path);
    }

}

/* ---------------------------------------------------------------------------
   This internal API creates a socket descriptor based on mode. If mode is server,
   it used the NN_PUSH for NM socket . If mode is client it use the NN_PULL
----------------------------------------------------------------------------*/
static ANSC_STATUS PppMgr_createIpcSockFd( int32_t  *sockFd, uint32_t sockMode )
{
#if defined(_USE_NM_MSG_SOCK)
    if(sockMode == PPP_MGR_IPC_SERVER)
    {
        *sockFd = nn_socket (AF_SP, NN_PULL);
    }
    else
    {
        *sockFd = nn_socket (AF_SP, NN_PUSH);
    }
#else
    //use normal TCP socket API to create server/client socket
#endif

    return (*sockFd >= 0 ? ANSC_STATUS_SUCCESS: ANSC_STATUS_FAILURE);
}

/* ------------------------------------------------------------
   This internal API bind the socket descriptot with a port number
   -------------------------------------------------------------*/
static ANSC_STATUS  PppMgr_bindIpcSocket( int32_t sockFd)
{

    char sockPort[BUFLEN_256] = { 0 };

    snprintf(sockPort, sizeof(sockPort), PPP_MANAGER_ADDR);

#if defined( _USE_NM_MSG_SOCK)
    if(nn_bind (sockFd, sockPort)  < 0)
    {
        CcspTraceError(("Error: nn_bind failed[%s] \n",nn_strerror(nn_errno ())));
        nn_close(sockFd);
        return ANSC_STATUS_FAILURE;
    }
    return ANSC_STATUS_SUCCESS;
#else
    return ANSC_STATUS_FAILURE;
#endif
}

/* --------------------------------------------------------------------
Function : PppMgr_createIpcSocket

Decription: This API creates a server or client socket based on mode.
If mode is server, it will create the socket bind to the the port number
If mode os client it will create the socket and connected to port number

-----------------------------------------------------------------------*/
extern ANSC_STATUS PppMgr_createIpcSocket(int32_t *sockFd, uint32_t sockMode)
{
    PppMgr_createIpcSockFd(sockFd, sockMode);

    if(sockMode == PPP_MGR_IPC_SERVER)
    {
        return PppMgr_bindIpcSocket(*sockFd);

    }
    return ANSC_STATUS_FAILURE;
}

/* --------------------------------------------------------------------
Function : PppMgr_receiveIpcSocket

Decription: This API receives message from scoket. Received message will be
copied to "msg" output varaible and the message length will be copied to
"msgLen" output variable

-----------------------------------------------------------------------*/
static ANSC_STATUS PppMgr_receiveIpcSocket(int32_t sockFd, char *msg, uint32_t *msgLen)
{
    if(sockFd < 0 || msg == NULL)
    {
        return ANSC_STATUS_FAILURE;
    }

#ifdef _USE_NM_MSG_SOCK

    void *ipcBuff = NULL;
    *msgLen = nn_recv (sockFd, &ipcBuff, NN_MSG, 0);

    if(ipcBuff == NULL)
    {
        return ANSC_STATUS_FAILURE;
    }

    if( *msgLen > 0)
    {
        memcpy(msg, ipcBuff, *msgLen);
    }
    nn_freemsg (ipcBuff);
#endif

    return( *msgLen > 0 ? ANSC_STATUS_SUCCESS : ANSC_STATUS_FAILURE) ;
}

/* --------------------------------------------------------------------
Function : PppMgr_closeIpcSocket

Decription: This API will close the socket
-----------------------------------------------------------------------*/
extern ANSC_STATUS PppMgr_closeIpcSocket(int32_t sockFd)
{
#if defined(_USE_NM_MSG_SOCK)
    if(nn_shutdown (sockFd, 0) < 0)
    {
        return ANSC_STATUS_FAILURE;

    }
    return ANSC_STATUS_SUCCESS;
#else
    return ANSC_STATUS_FAILURE;
#endif
}

static void* PppMgr_SetErrorStatus_Thread(void *arg)
{
    INT iWANInstance = (INT *) arg;
    char acSetParamName[DATAMODEL_PARAM_LENGTH] = { 0 };
    char acSetParamValue[DATAMODEL_PARAM_LENGTH] = { 0 };

    pthread_detach(pthread_self());

    if(iWANInstance <= 0)
    {
        return ANSC_STATUS_FAILURE;
    }

    snprintf(acSetParamName, DATAMODEL_PARAM_LENGTH, PPP_IPCP_STATUS_PARAM_NAME, iWANInstance);
    snprintf(acSetParamValue, DATAMODEL_PARAM_LENGTH, "Down");

    if(DmlWanmanagerSetParamValues(WAN_COMPONENT_NAME, WAN_DBUS_PATH, acSetParamName,
                acSetParamValue, ccsp_string, TRUE ) == ANSC_STATUS_SUCCESS)
    {
        CcspTraceInfo(("Successfully set %s with value %s\n", acSetParamName, acSetParamValue));
    }

    pthread_exit(NULL);
    return NULL;
}

/* --------------------------------------------------------------------
Function : PppMgr_SetErrorStatus

Decription: This API will set down state to wan manager IPCP status
-----------------------------------------------------------------------*/
static ANSC_STATUS PppMgr_SetErrorStatus(INT iWANInstance)
{
    pthread_t threadId;
    INT iErrorCode;

    /* Updating WanManager DM with PPP DML mutex lock creats mutex deadlock with WanManager DM mutex. Moving 
       DM set to thread to avoid mutex deadlock */ 
    iErrorCode = pthread_create( &threadId, NULL, &PppMgr_SetErrorStatus_Thread, (void*)iWANInstance );
    if( 0 != iErrorCode )
    {
        CcspTraceInfo(("%s %d - Failed to start PppMgr_SetErrorStatus_Thread  EC:%d\n", __FUNCTION__, __LINE__, iErrorCode ));
        return ANSC_STATUS_FAILURE;
    }
    return ANSC_STATUS_SUCCESS;
}

static void* PppMgr_SetIpv6ErrorStatus_Thread(void *arg)
{
    INT iWANInstance = (INT *) arg;
    char acSetParamName[DATAMODEL_PARAM_LENGTH] = { 0 };
    char acSetParamValue[DATAMODEL_PARAM_LENGTH] = { 0 };

    pthread_detach(pthread_self());

    if(iWANInstance <= 0)
    {
        return ANSC_STATUS_FAILURE;
    }

    snprintf(acSetParamName, DATAMODEL_PARAM_LENGTH, PPP_IPV6CP_STATUS_PARAM_NAME, iWANInstance);
    snprintf(acSetParamValue, DATAMODEL_PARAM_LENGTH, "Down");

    if(DmlWanmanagerSetParamValues(WAN_COMPONENT_NAME, WAN_DBUS_PATH, acSetParamName,
                acSetParamValue, ccsp_string, TRUE ) == ANSC_STATUS_SUCCESS)
    {
        CcspTraceInfo(("Successfully set %s with value %s\n", acSetParamName, acSetParamValue));
    }
    pthread_exit(NULL);
    return NULL;
}

/* --------------------------------------------------------------------
Function : PppMgr_SetIpv6ErrorStatus

Decription: This API will set down state to wan manager IPV6CP 
-----------------------------------------------------------------------*/
static ANSC_STATUS PppMgr_SetIpv6ErrorStatus(INT iWANInstance)
{
    pthread_t threadId;
    INT iErrorCode;

    /* Updating WanManager DM with PPP DML mutex lock creats mutex deadlock with WanManager DM mutex. Moving 
       DM set to thread to avoid mutex deadlock */ 
    iErrorCode = pthread_create( &threadId, NULL, &PppMgr_SetIpv6ErrorStatus_Thread, (void*)iWANInstance );

    if( 0 != iErrorCode )
    {
        CcspTraceInfo(("%s %d - Failed to start PppMgr_SetIpv6ErrorStatus_Thread  EC:%d\n", __FUNCTION__, __LINE__, iErrorCode ));
        return ANSC_STATUS_FAILURE;
    }
    return ANSC_STATUS_SUCCESS;
}

/* --------------------------------------------------------------------
Function : PppMgr_StartIpcServer

Decription: This API will start the IPC server
-----------------------------------------------------------------------*/
extern ANSC_STATUS PppMgr_StartIpcServer()
{
    pthread_t ipcThreadId;
    int ret = 0;

    if(PppMgr_IpcServerInit() != ANSC_STATUS_SUCCESS)
    {
        CcspTraceInfo(("Failed to initialise IPC messaging"));

        return ANSC_STATUS_FAILURE;
    }

    ret = pthread_create( &ipcThreadId, NULL, &PppMgr_IpcServerThread, NULL );

    if( 0 != ret )
    {
        CcspTraceInfo(("%s %d - Failed to start IPC Thread Error:%d\n", __FUNCTION__, __LINE__, ret));

        return ANSC_STATUS_FAILURE;
    }
    CcspTraceInfo(("%s %d - IPC Thread Started Successfully\n", __FUNCTION__, __LINE__));

    return ANSC_STATUS_SUCCESS ;
}

/* --------------------------------------------------------------------
Function : PppMgr_DmlSetIp4Param

Decription: This API will set IP parameters to data model
-----------------------------------------------------------------------*/
static ANSC_STATUS PppMgr_DmlSetIp4Param (char * ipbuff, char * ipCharArr)
{
    char * s1 = NULL;
    char * s2 = NULL;
    int i = 0;

    s1 = ipbuff;

    while ((s2 = strtok(s1, ".")) != NULL)
    {
        if (i == IPV4_ADDRESS_SIZE)
        {
            printf("Incorrect IP\n");
            return ANSC_STATUS_FAILURE;
        }
        ipCharArr[i++] = atoi(s2);
        s1 = NULL;
    }

    return ANSC_STATUS_SUCCESS;
}

/* --------------------------------------------------------------------
Function : PppMgr_DmlSetVendorParams

Decription: This API will set vendor parameters to data model
-----------------------------------------------------------------------*/

static ANSC_STATUS PppMgr_DmlSetVendorParams(char *invendormsg , int *SRU , int *SRD)
{
    char * source = NULL;
    source = invendormsg;
    char * regexString = "([A-Z]+)=([0-9]+)";
    size_t maxMatches = 2; // No. of Strings matching pattern to extract
    size_t maxGroups = 1;

    regex_t regexCompiled;
    regmatch_t groupArray[maxGroups];
    unsigned int m;
    char * cursor;

    if(regcomp(&regexCompiled, regexString, REG_EXTENDED))
    {
        CcspTraceInfo(("%s %d Could not compile regex \n", __FUNCTION__, __LINE__));
        return ANSC_STATUS_FAILURE;
    }

    m = 0;
    cursor = source; // pointing to beginning of string
    for(m = 0; m < maxMatches; m ++)
    {
        if(regexec(&regexCompiled, cursor, maxGroups, groupArray, 0))
            break;  // No more matches

        unsigned int g = 0;
        unsigned int offset = 0;
        for(g = 0; g < maxGroups; g++)
        {
            if(groupArray[g].rm_so == (size_t)-1)
                break;  // No more groups

            if(g == 0)
                offset = groupArray[g].rm_eo;

            char cursorCopy[strlen(cursor) + 1];
            strcpy(cursorCopy, cursor);
            cursorCopy[groupArray[g].rm_eo] = 0;
            char *ret;
            if(ret = strstr(cursorCopy + groupArray[g].rm_so, "SRU="))
            {
                *SRU = atoi(ret+4);
            }
            else if(ret = strstr(cursorCopy + groupArray[g].rm_so, "SRD="))
            {
                *SRD = atoi(ret+4);
            }
        }
        cursor += offset;
    }
    regfree(&regexCompiled);

    return ANSC_STATUS_SUCCESS;
}

static void* UpdateWanManagerThread(void *arg )
{
    struct UpdateWanManager_args *args = (struct UpdateWanManager_args *) arg;
    char acSetParamName[DATAMODEL_PARAM_LENGTH] = { 0 };
    char acSetParamValue[DATAMODEL_PARAM_LENGTH] = { 0 };

    pthread_detach(pthread_self());

    snprintf(acSetParamName, DATAMODEL_PARAM_LENGTH, PPP_LCP_STATUS_PARAM_NAME, args->WANInstance);
    snprintf(acSetParamValue, DATAMODEL_PARAM_LENGTH, "%s", args->LinkStatus);

    if(DmlWanmanagerSetParamValues(WAN_COMPONENT_NAME, WAN_DBUS_PATH, acSetParamName,
                acSetParamValue, ccsp_string, TRUE ) != ANSC_STATUS_SUCCESS)
    {
        CcspTraceInfo(("Failed set %s with value %s\n", acSetParamName, acSetParamValue));
        return ANSC_STATUS_FAILURE;
    }
    CcspTraceInfo(("Successfully set %s with value %s\n", acSetParamName, acSetParamValue));

    snprintf(acSetParamName, DATAMODEL_PARAM_LENGTH, PPP_LINK_STATUS_PARAM_NAME, args->WANInstance);
    snprintf(acSetParamValue, DATAMODEL_PARAM_LENGTH, "%s", args->LinkStatus);

    if(DmlWanmanagerSetParamValues(WAN_COMPONENT_NAME, WAN_DBUS_PATH, acSetParamName,
                acSetParamValue, ccsp_string, TRUE ) != ANSC_STATUS_SUCCESS)
    {
        CcspTraceInfo(("Failed set %s with value %s\n", acSetParamName, acSetParamValue));
        return ANSC_STATUS_FAILURE;
    }
    CcspTraceInfo(("Successfully set %s with value %s\n", acSetParamName, acSetParamValue));

    free(args);
    pthread_exit(NULL);
    return NULL;
}

/* --------------------------------------------------------------------
Function : PppMgr_ProcessStateChangedMsg

Decription: This API will set ppp state when LCP state change message is received
-----------------------------------------------------------------------*/
static ANSC_STATUS PppMgr_ProcessStateChangedMsg(PDML_PPP_IF_FULL pNewEntry, ipc_ppp_event_msg_t pppEventMsg)
{
    char WanPppLinkStatus[64] = { 0 };
    char acSetParamName[DATAMODEL_PARAM_LENGTH] = { 0 };
    char acSetParamValue[DATAMODEL_PARAM_LENGTH] = { 0 } ;
    INT instance_num = 0;
    INT iWANInstance = -1;
    uint32_t updatedParam = 0;
    int ret = 0;

    CcspTraceInfo(("[%s-%d] - PID received %d\n", __FUNCTION__, __LINE__, pppEventMsg.pid));

    instance_num= pNewEntry->Cfg.InstanceNumber;

    CcspTraceInfo(("[%s-%d] - instance number %d\n", __FUNCTION__, __LINE__, instance_num));

    if(instance_num <= 0 )
    {
        CcspTraceInfo(("[%s-%d] - Invalid instance number %d for pid %d\n", __FUNCTION__,
                    __LINE__, instance_num, pppEventMsg.pid));

        return ANSC_STATUS_FAILURE;
    }
    CcspTraceInfo(("[%s-%d] - ipcp state for pid %d is %s\n", __FUNCTION__, __LINE__,
                pppEventMsg.pid, pppStatetoString(pppEventMsg.pppState)));

    iWANInstance = pNewEntry->Cfg.WanInstanceNumber; 

    CcspTraceInfo(("%s %d WAN Instance:%d\n", __FUNCTION__, __LINE__, iWANInstance));

    switch(pppEventMsg.pppState)
    {

        case PPP_INTERFACE_UNCONFIGURED:
            pNewEntry->Info.Status = DML_IF_STATUS_Error;
            pNewEntry->Info.ConnectionStatus = DML_PPP_CONN_STATUS_Unconfigured;
            snprintf(WanPppLinkStatus, sizeof(WanPppLinkStatus), "Down");
            updatedParam = 1;
            pNewEntry->Info.LastChange = GetUptimeinSeconds();
            break;

        case PPP_INTERFACE_CONNECTING:
            pNewEntry->Info.Status = DML_IF_STATUS_Down;
            pNewEntry->Info.ConnectionStatus = DML_PPP_CONN_STATUS_Connecting;
            pNewEntry->Info.LastChange = GetUptimeinSeconds();
            strncpy(pNewEntry->Cfg.ACName,pppEventMsg.event.pppLcpMsg.acname,sizeof(pNewEntry->Cfg.ACName));
            break;

        case PPP_INTERFACE_AUTHENTICATING:
            pNewEntry->Info.Status = DML_IF_STATUS_Down;
            pNewEntry->Info.ConnectionStatus = DML_PPP_CONN_STATUS_Authenticating;
            pNewEntry->Info.LastChange = GetUptimeinSeconds();
            break;

        case PPP_INTERFACE_UP:
            pNewEntry->Info.Status = DML_IF_STATUS_Up;
            pNewEntry->Info.ConnectionStatus = DML_PPP_CONN_STATUS_Connected;
            pNewEntry->Info.LastConnectionError = DML_PPP_CONN_ERROR_NONE;
            snprintf(WanPppLinkStatus, sizeof(WanPppLinkStatus), "Up");
            updatedParam = 1;
            pNewEntry->Info.LastChange = GetUptimeinSeconds();
            break;

        case PPP_INTERFACE_DISCONNECTING:
            pNewEntry->Info.Status = DML_IF_STATUS_Down;
            pNewEntry->Info.ConnectionStatus = DML_PPP_CONN_STATUS_Disconnecting;
            pNewEntry->Info.LastChange = GetUptimeinSeconds();
            break;

        case PPP_INTERFACE_DISCONNECTED:
        case PPP_INTERFACE_DOWN:
            pNewEntry->Info.SRU = 0;
            pNewEntry->Info.SRD = 0;
            pNewEntry->Info.Status = DML_IF_STATUS_Down;
            pNewEntry->Info.ConnectionStatus = DML_PPP_CONN_STATUS_Disconnected;
            snprintf(WanPppLinkStatus, sizeof(WanPppLinkStatus), "Down");
            updatedParam = 1;
            pNewEntry->Info.LastChange = GetUptimeinSeconds();

            switch(pppEventMsg.event.pppLcpMsg.exitStatus)
            {
                case PPP_EXIT_USER_REQUEST:
                    pNewEntry->Info.LastConnectionError = DML_PPP_CONN_ERROR_USER_DISCONNECT;
                    break;
                case PPP_EXIT_PEER_AUTH_FAILED:
                case PPP_EXIT_AUTH_TOPEER_FAILED:
                    pNewEntry->Info.LastConnectionError = DML_PPP_CONN_ERROR_AUTHENTICATION_FAILURE;
                    break;
                case PPP_EXIT_HANGUP:
                    pNewEntry->Info.LastConnectionError = DML_PPP_CONN_ERROR_ISP_TIME_OUT;
                    break;
                default:
                    pNewEntry->Info.LastConnectionError = DML_PPP_CONN_ERROR_UNKNOWN;
                    break;
            }

            break;

	    case PPP_LCP_AUTH_COMPLETED:
            pNewEntry->Info.SRU = 0;
            pNewEntry->Info.SRD = 0;

            if(strlen(pppEventMsg.event.pppLcpMsg.vendormsg) > 0)
            {
                ret = PppMgr_DmlSetVendorParams(pppEventMsg.event.pppLcpMsg.vendormsg,
                (int *)&pNewEntry->Info.SRU, (int *)&pNewEntry->Info.SRD);

                if(ret == ANSC_STATUS_FAILURE)
                {
                    CcspTraceInfo(("[%s-%d] Setting Vendor Params Falure%s\n", __FUNCTION__, __LINE__,
                    pppEventMsg.event.pppLcpMsg.vendormsg));
                }
            }

            if(strlen(pppEventMsg.event.pppLcpMsg.authproto) > 0)
            {
                CcspTraceInfo(("PPP Authentication Protocol: %s ", pppEventMsg.event.pppLcpMsg.authproto));
                if(strcmp(pppEventMsg.event.pppLcpMsg.authproto, "PAP") == 0)
                    pNewEntry->Info.AuthenticationProtocol = DML_PPP_AUTH_PAP;
                else
                    pNewEntry->Info.AuthenticationProtocol = DML_PPP_AUTH_CHAP;
            }

            break;

        default:
            pNewEntry->Info.Status = DML_IF_STATUS_Down;
            pNewEntry->Info.ConnectionStatus = DML_PPP_CONN_STATUS_Disconnected;
            snprintf(WanPppLinkStatus, sizeof(WanPppLinkStatus), "Down");
            updatedParam = 1;
            pNewEntry->Info.LastChange = GetUptimeinSeconds();
            break;
    }
    /* We updated params in ppp data model . Update wan data model */
    if(!updatedParam)
    {
        /* We don't have an up/down status to update wan mananager */
        return ANSC_STATUS_SUCCESS;
    }
    /* Updating WanManager DM with PPP DML mutex lock creats mutex deadlock with WanManager DM mutex. Moving 
       DM set to thread to avoid mutex deadlock */ 

    pthread_t threadId;
    INT iErrorCode;
    struct UpdateWanManager_args *args = malloc(sizeof(struct UpdateWanManager_args));
    args->WANInstance = iWANInstance;
    strncpy(args->LinkStatus, WanPppLinkStatus, strlen(WanPppLinkStatus)+1);

    iErrorCode = pthread_create( &threadId, NULL, &UpdateWanManagerThread, (void*)args );
    if( 0 != iErrorCode )
    {
        CcspTraceInfo(("%s %d - Failed to start UpdateWanManagerThread  EC:%d\n", __FUNCTION__, __LINE__, iErrorCode ));
        return ANSC_STATUS_FAILURE;
    }
    return ANSC_STATUS_SUCCESS;
}

/* --------------------------------------------------------------------
Function : ProcessIpcpParams

Decription: This API will set IPV4 parameters to PPP data model 
-----------------------------------------------------------------------*/
static ANSC_STATUS PppMgr_ProcessIpcpParams(PDML_PPP_IF_FULL pNewEntry, ipc_ppp_event_msg_t pppEventMsg)
{

    int instance_num = 0;
    int ret = 0;
    char *s1 = NULL;
    char *s2 = NULL;
    int i = 0;
    char acSetParamName[DATAMODEL_PARAM_LENGTH] = { 0 };
    char acSetParamValue[DATAMODEL_PARAM_LENGTH] = { 0 };
    char WanPppIpcpStatus[64] = { 0 };
    INT iWANInstance = -1;
    uint32_t updatedParams = 0;
    char dns1[32] = { 0 };
    char dns2[32] = { 0 };
    int dnsCount = 0;

    CcspTraceInfo(("[%s-%d] - PID received %d\n", __FUNCTION__, __LINE__, pppEventMsg.pid));

    instance_num= pNewEntry->Cfg.InstanceNumber;

    CcspTraceInfo(("[%s-%d] - instance number %d\n", __FUNCTION__, __LINE__, instance_num));

    if(instance_num <= 0 )
    {
        CcspTraceInfo(("[%s-%d] - Invalid instance number %d for pid %d\n", __FUNCTION__,
                    __LINE__, instance_num, pppEventMsg.pid));

        return ANSC_STATUS_FAILURE;
    }
    CcspTraceInfo(("[%s-%d] - ipcp state for pid %d is %s\n", __FUNCTION__, __LINE__,
                pppEventMsg.pid, pppStatetoString(pppEventMsg.pppState)));
    
    /* Clear current data model values */
    memset (&pNewEntry->Info.LocalIPAddress, 0, sizeof(pNewEntry->Info.LocalIPAddress));

    memset (&pNewEntry->Info.RemoteIPAddress, 0, sizeof(pNewEntry->Info.RemoteIPAddress));

    memset (&pNewEntry->Info.DNSServers, 0, sizeof(pNewEntry->Info.DNSServers)); 

    iWANInstance = pNewEntry->Cfg.WanInstanceNumber; 
    /* Populate the data model only if we have all network configuration parameters */
    if( (strcmp(pppEventMsg.event.pppIpcpMsg.ip, "") == 0 || 
                strcmp(pppEventMsg.event.pppIpcpMsg.gateway, "") == 0 ||
                strcmp(pppEventMsg.event.pppIpcpMsg.nameserver, "") == 0) )
    {
        CcspTraceInfo(("[%s-%d] Network parameters are missing from client message\n", __FUNCTION__, __LINE__));

        PppMgr_SetErrorStatus(iWANInstance);

        return ANSC_STATUS_FAILURE;
    }
    if (pppEventMsg.pppState == PPP_IPCP_COMPLETED)
    {
        ret = PppMgr_DmlSetIp4Param(pppEventMsg.event.pppIpcpMsg.ip, (char*)&pNewEntry->Info.LocalIPAddress);
        if (ret == ANSC_STATUS_FAILURE)
        {
            CcspTraceInfo(("[%s-%d] Setting Local IP Falure%s\n", __FUNCTION__, 
                        __LINE__, pppEventMsg.event.pppIpcpMsg.ip));

            PppMgr_SetErrorStatus(iWANInstance);

            return ANSC_STATUS_FAILURE;
        }
        ret = PppMgr_DmlSetIp4Param(pppEventMsg.event.pppIpcpMsg.gateway, (char*)&pNewEntry->Info.RemoteIPAddress);

        if (ret == ANSC_STATUS_FAILURE)
        {
            CcspTraceInfo(("[%s-%d] Setting Remote IP Falure%s\n", __FUNCTION__, __LINE__,
                        pppEventMsg.event.pppIpcpMsg.gateway));

            PppMgr_SetErrorStatus(iWANInstance);

            return ANSC_STATUS_FAILURE;
        }
        CcspTraceInfo(("[%s-%d] DNS received %s\n", __FUNCTION__, __LINE__, pppEventMsg.event.pppIpcpMsg.nameserver));

        s1 = pppEventMsg.event.pppIpcpMsg.nameserver;
        /* Parse DNS servers from message */
        for (i = 1, s1 = strtok(s1, ","); s1 != NULL; s1 = strtok(NULL, ","), i++)
        {
            dnsCount++;

            if(i > 1)
            {
                strncpy(dns2, s1, sizeof(dns2)-1);
                break;
            }
            strncpy(dns1, s1, sizeof(dns1)-1);
        }
        if(!dnsCount || dnsCount > 2)
        {
            CcspTraceInfo((" DNS parsing failed in received message\n"));

            PppMgr_SetErrorStatus(iWANInstance);

            return ANSC_STATUS_FAILURE;
        }
        /* Use a separate loop, otherwise strtok might fail */
        for(i = 1; i <= dnsCount ; i++)
        {
            CcspTraceInfo((" Updating DNS %d in data model\n", i ));

            if( i > 1)
            {
                PppMgr_DmlSetIp4Param(dns2, (char*)&pNewEntry->Info.DNSServers[i-1]);
                break;
            }
            PppMgr_DmlSetIp4Param(dns1, (char*)&pNewEntry->Info.DNSServers[i-1]);
        }

        CcspTraceInfo(("%s %d WAN Instance:%d\n", __FUNCTION__, __LINE__, iWANInstance));

        snprintf(WanPppIpcpStatus, sizeof(WanPppIpcpStatus), "Up");

        snprintf(acSetParamName, DATAMODEL_PARAM_LENGTH, PPP_IPCP_STATUS_PARAM_NAME, iWANInstance);

        snprintf(acSetParamValue, DATAMODEL_PARAM_LENGTH, "%s", WanPppIpcpStatus);

        if(DmlWanmanagerSetParamValues(WAN_COMPONENT_NAME, WAN_DBUS_PATH, acSetParamName, 
                    acSetParamValue, ccsp_string, TRUE ) == ANSC_STATUS_SUCCESS)
        {
            CcspTraceInfo(("Successfully set %s with value %s\n", acSetParamName, acSetParamValue));
        }
    }
    else
    {
        PppMgr_SetErrorStatus(iWANInstance);
    }

    return ANSC_STATUS_SUCCESS;
}
/* --------------------------------------------------------------------
Function : ProcessIpv6cpParams

Decription: This API will set IPV6 parameters to PPP data model 
-----------------------------------------------------------------------*/
static ANSC_STATUS PppMgr_ProcessIpv6cpParams(PDML_PPP_IF_FULL pNewEntry, ipc_ppp_event_msg_t pppEventMsg)
{
    int instance_num = 0;
    char acSetParamName[DATAMODEL_PARAM_LENGTH] = { 0 };
    char acSetParamValue[DATAMODEL_PARAM_LENGTH] = { 0 };
    char WanPppIpv6cpStatus[64] = { 0 };
    INT iWANInstance = -1;
    uint32_t updated_params = 0;

    CcspTraceInfo(("[%s-%d] - PID received %d\n", __FUNCTION__, __LINE__, pppEventMsg.pid));

    instance_num = pNewEntry->Cfg.InstanceNumber;

    CcspTraceInfo(("[%s-%d] - instance number %d\n", __FUNCTION__, __LINE__, instance_num));

    if(instance_num <= 0 )
    {
        CcspTraceInfo(("[%s-%d] - Invalid instance number %d for pid %d\n", __FUNCTION__,
                    __LINE__, instance_num, pppEventMsg.pid));

        return ANSC_STATUS_FAILURE;
    }

    CcspTraceInfo(("[%s-%d] - ipcp state for pid %d is %s\n", __FUNCTION__, __LINE__,
                pppEventMsg.pid, pppStatetoString(pppEventMsg.pppState)));

    if (pppEventMsg.pppState == PPP_IPV6CP_COMPLETED)
    {
        if(strcmp(pppEventMsg.event.pppIpv6cpMsg.localIntfId , "") != 0)
        {
            memset(pNewEntry->Info.Ip6LocalIfID,0,sizeof(pNewEntry->Info.Ip6LocalIfID));		
            strncpy(pNewEntry->Info.Ip6LocalIfID, pppEventMsg.event.pppIpv6cpMsg.localIntfId, 
                    (sizeof(pNewEntry->Info.Ip6LocalIfID)-1));
        }

        if(strcmp(pppEventMsg.event.pppIpv6cpMsg.remoteIntfId , "") != 0)
        {
            memset(pNewEntry->Info.Ip6RemoteIfID,0,sizeof(pNewEntry->Info.Ip6RemoteIfID));
            strncpy(pNewEntry->Info.Ip6RemoteIfID,pppEventMsg.event.pppIpv6cpMsg.remoteIntfId, 
                    (sizeof(pNewEntry->Info.Ip6LocalIfID)-1));
        }

        /* set wan ipv6cp status */
        iWANInstance = pNewEntry->Cfg.WanInstanceNumber;

        PppMgr_GenerateDuidFile(pNewEntry->Cfg.Alias);

        CcspTraceInfo(("%s %d WAN Instance:%d\n", __FUNCTION__, __LINE__, iWANInstance));

        snprintf(WanPppIpv6cpStatus, sizeof(WanPppIpv6cpStatus), "Up");

        snprintf(acSetParamName, DATAMODEL_PARAM_LENGTH, PPP_IPV6CP_STATUS_PARAM_NAME, iWANInstance);

        snprintf(acSetParamValue, DATAMODEL_PARAM_LENGTH, "%s", WanPppIpv6cpStatus);

        if(DmlWanmanagerSetParamValues(WAN_COMPONENT_NAME, WAN_DBUS_PATH, 
                    acSetParamName, acSetParamValue, ccsp_string, TRUE) == ANSC_STATUS_SUCCESS)
        {
            CcspTraceInfo(("Succefully set %s with value %s\n", acSetParamName, acSetParamValue));
        }
        // After ipv6cp dbus set is called, allow some seconds for wan manager to set ipv6 config variables  
        // to avoid any race condition caused by next immediate dbus call for ipv4 status 
        // Race condition will cause dibbler client to restart multiple times
        // or causes stopping the dibbler client permanently due to misconfigured or overwritten ipv6 variables
        sleep(5);
    }
    else
    {
        iWANInstance = pNewEntry->Cfg.WanInstanceNumber;
        PppMgr_RemoveDuidFile(pNewEntry->Cfg.Alias);
        PppMgr_SetIpv6ErrorStatus(iWANInstance);    
    }

    return ANSC_STATUS_SUCCESS;
}

/* --------------------------------------------------------------------
Function : ProcessIpcMsg

Decription: This API will process the message received from ppp client 
-----------------------------------------------------------------------*/
static ANSC_STATUS PppMgr_ProcessIpcMsg(ipc_msg_payload_t ipcMsg)
{
    PSINGLE_LINK_ENTRY         pSLinkEntry             = NULL;
    PDATAMODEL_PPP             pMyObject               = (PDATAMODEL_PPP      )g_pBEManager->hPPP;
    PPPP_IF_LINK_OBJECT        pLinkContext2           = (PPPP_IF_LINK_OBJECT)NULL;
    PDML_PPP_IF_FULL           pEntry               = (PDML_PPP_IF_FULL    )NULL;
    ANSC_STATUS retStatus = ANSC_STATUS_SUCCESS;
    uint32_t getAttempt = 0;

    if( ipcMsg.msg_type != IPC_MSG_PPP_STATE_CHANGE )
    {
        return ANSC_STATUS_FAILURE;
    }
    // we should try atleast six attempts as pppmanager may not update pppd pid immediately
    do
    {
        if(getAttempt)
        {
            sleep(1);
        }
        pSLinkEntry = PppMgr_DmlGetLinkEntry(ipcMsg.data.pppEventMsg.pid, ipcMsg.data.pppEventMsg.interface);
    
        getAttempt++;

    }while(pSLinkEntry == NULL && getAttempt < GET_PPPID_ATTEMPT);

    if(pSLinkEntry == NULL)
    {
        CcspTraceInfo(("[%s-%d] - instance number not found \n", __FUNCTION__, __LINE__));

        return ANSC_STATUS_FAILURE;
    }

    pLinkContext2 = ACCESS_PPP_IF_LINK_OBJECT(pSLinkEntry);

    if(pLinkContext2 == NULL)
    {
        CcspTraceInfo(("[%s-%d] - cannot find  pLinkContext2\n  ", __FUNCTION__, __LINE__));

        return ANSC_STATUS_FAILURE;
    }

    pEntry = (PDML_PPP_IF_FULL)pLinkContext2->hContext;

    if(pEntry == NULL)
    {
        CcspTraceInfo(("[%s-%d] - cannot find pEntry \n", __FUNCTION__, __LINE__));

        return ANSC_STATUS_FAILURE;
    }

    pthread_mutex_lock(&pEntry->mDataMutex);

    switch(ipcMsg.data.pppEventMsg.pppState)
    {
        case    PPP_INTERFACE_UP:
        case    PPP_INTERFACE_DOWN:
        case    PPP_INTERFACE_UNCONFIGURED:
        case    PPP_INTERFACE_CONNECTING:
        case    PPP_INTERFACE_AUTHENTICATING:
        case    PPP_INTERFACE_PENDING_DISCONNET:
        case    PPP_INTERFACE_DISCONNECTING:
        case    PPP_INTERFACE_DISCONNECTED:
        case    PPP_INTERFACE_LCP_ECHO_FAILED:
        case    PPP_INTERFACE_AUTH_FAILED:
        case    PPP_LCP_AUTH_COMPLETED:

            CcspTraceInfo(("[%s-%d] PPP_LCP_STATE_CHANGED message received\n", __FUNCTION__, __LINE__));

            if (PppMgr_ProcessStateChangedMsg(pEntry, ipcMsg.data.pppEventMsg) == ANSC_STATUS_FAILURE)
            {
                CcspTraceError(("[%s-%d] Failed to proccess PPP_LCP_STATE_CHANGED  message \n",
                         __FUNCTION__, __LINE__));

                retStatus = ANSC_STATUS_FAILURE;
            } 
            break;
        case PPP_IPCP_COMPLETED:
        case PPP_IPCP_FAILED:

            CcspTraceInfo(("[%s-%d] PPP_NCP_IPCP_PARAM message received\n", __FUNCTION__, __LINE__));

            if(PppMgr_ProcessIpcpParams(pEntry, ipcMsg.data.pppEventMsg) == ANSC_STATUS_FAILURE)
            {
                CcspTraceError(("[%s-%d] Failed to proccess PPP_NCP_IPCP_PARAM  message \n",
                         __FUNCTION__, __LINE__));

                retStatus = ANSC_STATUS_FAILURE;
            }
            break;
        case PPP_IPV6CP_COMPLETED:
        case PPP_IPV6CP_FAILED:

            CcspTraceInfo(("[%s-%d] PPP_NCP_IPCP6_PARAM message received\n", __FUNCTION__, __LINE__));

            if(PppMgr_ProcessIpv6cpParams(pEntry, ipcMsg.data.pppEventMsg) == ANSC_STATUS_FAILURE)
            {
                CcspTraceError(("[%s-%d] Failed to proccess PPP_NCP_IPCP_PARAM  message \n",
                         __FUNCTION__, __LINE__));

                retStatus = ANSC_STATUS_FAILURE;
            }
            break;
        default:

            CcspTraceInfo(("[%s-%d] Unknow message type %d received", __FUNCTION__, __LINE__, ipcMsg.msg_type));

            retStatus = ANSC_STATUS_FAILURE;
            
            break;
    } 
    pthread_mutex_unlock(&pEntry->mDataMutex);

    return retStatus;
}

/* --------------------------------------------------------------------
Function : PppMgr_IpcServerThread

Decription: IPC thread function
-----------------------------------------------------------------------*/
static void* PppMgr_IpcServerThread( void *arg )
{

    //detach thread from caller stack
    pthread_detach(pthread_self());

    // local variables
    BOOL bRunning = TRUE;

    int bytesReceived = 0;
    ipc_msg_payload_t sockMsg;
    uint32_t msgSize = 0;; 

    memset (&sockMsg, 0, sizeof(ipc_msg_payload_t));

    while (bRunning)
    {
        if(PppMgr_receiveIpcSocket(ipcListenFd, (char*)&sockMsg, &msgSize) == ANSC_STATUS_FAILURE)
        {
            continue;
        }
        CcspTraceInfo(("[%s-%d] Message received  with size %d\n", __FUNCTION__, __LINE__, msgSize));

        if(msgSize > 0)
        {
            PppMgr_ProcessIpcMsg(sockMsg);
        }
    }
    PppMgr_closeIpcSocket(ipcListenFd);

    pthread_exit(NULL);
}

/* --------------------------------------------------------------------
Function : PppMgr_IpcServerInit

Decription: This API will create and bind the IPC socket
-----------------------------------------------------------------------*/
static ANSC_STATUS PppMgr_IpcServerInit()
{
    ANSC_STATUS ret = ANSC_STATUS_SUCCESS;
    uint32_t i;

    //create and bind the socket if this is server
    if(ANSC_STATUS_FAILURE == PppMgr_createIpcSocket(&ipcListenFd, PPP_MGR_IPC_SERVER))
    {
        return ANSC_STATUS_FAILURE;

    }

    return ANSC_STATUS_SUCCESS;
}

/* --------------------------------------------------------------------
Function : PppGetInstanceNumber

Decription: This API will return data model entry associated with ppp client pid value
-----------------------------------------------------------------------*/
static PSINGLE_LINK_ENTRY PppMgr_DmlGetLinkEntry(pid_t pid, char *interface)
{

    PSINGLE_LINK_ENTRY         pSLinkEntry             = NULL;
    PDATAMODEL_PPP             pMyObject               = (PDATAMODEL_PPP      )g_pBEManager->hPPP;
    PPPP_IF_LINK_OBJECT       pLinkContext2           = (PPPP_IF_LINK_OBJECT)NULL;
    PDML_PPP_IF_FULL           pNewEntry               = (PDML_PPP_IF_FULL    )NULL;
    int i = 0;

    if(!pid)
    {
        CcspTraceInfo(("[%s-%d] pid is zero", __FUNCTION__, __LINE__));
        return NULL;
    }
    pSLinkEntry = AnscSListGetFirstEntry(&pMyObject->IfList);

    while ( pSLinkEntry )
    {
        pLinkContext2 = ACCESS_PPP_IF_LINK_OBJECT(pSLinkEntry);

        pNewEntry = (PDML_PPP_IF_FULL)pLinkContext2->hContext;

        if(pNewEntry)
        {
            pthread_mutex_lock(&pNewEntry->mDataMutex);

            if ( pNewEntry->Info.pppPid == pid )
            {
                pthread_mutex_unlock(&pNewEntry->mDataMutex);

                return pSLinkEntry;
            }
            else if (strncmp(pNewEntry->Cfg.Alias, interface, sizeof(pNewEntry->Cfg.Alias)) == 0)
            {
                /* The mapping using PID may not work in some cases. For eg, if pppd
                restarts due to CHAP authentication failure etc. In this case, we should
                try to map with interface name and update the PID information */
                pNewEntry->Info.pppPid = PppMgr_getPppPid();
                CcspTraceInfo(("[%s-%d] ppp daemon on %s interface may be restarted and updating new pid %d", __FUNCTION__, __LINE__, pNewEntry->Cfg.Alias, pNewEntry->Info.pppPid));
                pthread_mutex_unlock(&pNewEntry->mDataMutex);
                return pSLinkEntry;
            }
            pthread_mutex_unlock(&pNewEntry->mDataMutex);
        }
        pSLinkEntry   = AnscSListGetNextEntry(pSLinkEntry);
    }

    return NULL;

}
