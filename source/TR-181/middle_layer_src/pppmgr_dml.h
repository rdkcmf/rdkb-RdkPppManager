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

#ifndef  _PPPMGR_DML_H_
#define  _PPPMGR_DML_H_

#define DML_PPP_SUPPORTED_NCP_ATCP   0x01
#define DML_PPP_SUPPORTED_NCP_IPCP   0x02
#define DML_PPP_SUPPORTED_NCP_IPXCP  0x04
#define DML_PPP_SUPPORTED_NCP_NBFCP  0x08
#define DML_PPP_SUPPORTED_NCP_IPv6CP 0x10

#define  ACCESS_PPP_IF_LINK_OBJECT(p)              \
    ACCESS_CONTAINER(p, PPP_IF_LINK_OBJECT, Linkage)

typedef  struct
_DML_IF_STATS
{
    ULONG                           BytesSent;
    ULONG                           BytesReceived;
    ULONG                           PacketsSent;
    ULONG                           PacketsReceived;
    ULONG                           ErrorsSent;
    ULONG                           ErrorsReceived;
    ULONG                           UnicastPacketsSent;
    ULONG                           UnicastPacketsReceived;
    ULONG                           DiscardPacketsSent;
    ULONG                           DiscardPacketsReceived;
    ULONG                           MulticastPacketsSent;
    ULONG                           MulticastPacketsReceived;
    ULONG                           BroadcastPacketsSent;
    ULONG                           BroadcastPacketsReceived;
    ULONG                           UnknownProtoPacketsReceived;
}
DML_IF_STATS, *PDML_IF_STATS;

typedef  enum _PPP_DML_LINK_TYPE
{
    DML_PPPoA_LINK_TYPE       = 1,
    DML_PPPoE_LINK_TYPE
}
PPP_DML_LINK_TYPE, *PPPP_DML_LINK_TYPE;

typedef  enum _PPP_DML_CONN_TRIGGER
{
    DML_PPP_CONN_TRIGGER_OnDemand              = 1,
    DML_PPP_CONN_TRIGGER_AlwaysOn,
    DML_PPP_CONN_TRIGGER_Manual
}
PPP_DML_CONN_TRIGGER, *PPPP_DML_CONN_TRIGGER;



/*
 *  Structure definitions for PPP Interface
 */

typedef  enum _DML_PPP_CONN_STATUS
{
    DML_PPP_CONN_STATUS_Unconfigured           = 1,
    DML_PPP_CONN_STATUS_Connecting,
    DML_PPP_CONN_STATUS_Authenticating,
    DML_PPP_CONN_STATUS_Connected,
    DML_PPP_CONN_STATUS_PendingDisconnect,
    DML_PPP_CONN_STATUS_Disconnecting,
    DML_PPP_CONN_STATUS_Disconnected
}
DML_PPP_CONN_STATUS, *PDML_PPP_CONN_STATUS;

typedef  struct _DML_PPP_IF_CFG
{
    ULONG                           InstanceNumber;
    char                            Alias[DML_IF_NAME_LENGTH];

    BOOLEAN                         bEnabled;
    BOOLEAN                         bIPCPEnabled;
    BOOLEAN                         bIPV6CPEnabled;
    PPP_DML_LINK_TYPE               LinkType;
    char                            LowerLayers[256];
    char                            LinkName[DML_IF_NAME_LENGTH];
    ULONG                           AutoDisconnectTime;
    ULONG                           IdleDisconnectTime;
    ULONG                           WarnDisconnectDelay;
    char                            Username[65];
    char                            Password[65];
    USHORT                          MaxMRUSize;
    PPP_DML_CONN_TRIGGER       ConnectionTrigger;
    /*
     *  PPPoE
     */
    char                            ACName[257];
    char                            ServiceName[257];
    /*
     *  IPCP
     */
    BOOLEAN                         PassthroughEnable;
    char                            PassthroughDHCPPool[DML_IF_NAME_LENGTH];   /* Alias of the DHCP pool */
	int                             WanInstanceNumber; 
}
DML_PPP_IF_CFG,  *PDML_PPP_IF_CFG;

typedef  enum _DML_IF_STATUS
{
    DML_IF_STATUS_Up               = 1,
    DML_IF_STATUS_Down,
    DML_IF_STATUS_Unknown,
    DML_IF_STATUS_Dormant,
    DML_IF_STATUS_NotPresent,
    DML_IF_STATUS_LowerLayerDown,
    DML_IF_STATUS_Error
}
DML_IF_STATUS, *PDML_IF_STATUS;

typedef  enum _DML_PPP_CONN_ERROR
{
    DML_PPP_CONN_ERROR_NONE                    = 1,
    DML_PPP_CONN_ERROR_ISP_TIME_OUT,
    DML_PPP_CONN_ERROR_COMMAND_ABORTED,
    DML_PPP_CONN_ERROR_NOT_ENABLED_FOR_INTERNET,
    DML_PPP_CONN_ERROR_BAD_PHONE_NUMBER,
    DML_PPP_CONN_ERROR_USER_DISCONNECT,
    DML_PPP_CONN_ERROR_ISP_DISCONNECT,
    DML_PPP_CONN_ERROR_IDLE_DISCONNECT,
    DML_PPP_CONN_ERROR_FORCED_DISCONNECT,
    DML_PPP_CONN_ERROR_SERVER_OUT_OF_RESOURCES,
    DML_PPP_CONN_ERROR_RESTRICTED_LOGON_HOURS,
    DML_PPP_CONN_ERROR_ACCOUNT_DISABLED,
    DML_PPP_CONN_ERROR_ACCOUNT_EXPIRED,
    DML_PPP_CONN_ERROR_PASSWORD_EXPIRED,
    DML_PPP_CONN_ERROR_AUTHENTICATION_FAILURE,
    DML_PPP_CONN_ERROR_NO_DIALTONE,
    DML_PPP_CONN_ERROR_NO_CARRIER,
    DML_PPP_CONN_ERROR_NO_ANSWER,
    DML_PPP_CONN_ERROR_LINE_BUSY,
    DML_PPP_CONN_ERROR_UNSUPPORTED_BITSPERSECOND,
    DML_PPP_CONN_ERROR_TOO_MANY_LINE_ERRORS,
    DML_PPP_CONN_ERROR_IP_CONFIGURATION,
    DML_PPP_CONN_ERROR_UNKNOWN
}
DML_PPP_CONN_ERROR, *PDML_PPP_CONN_ERROR;

typedef  enum _DML_PPP_ENCRYPTION
{
    DML_PPP_ENCRYPTION_None                    = 1,
    DML_PPP_ENCRYPTION_MPPE
}
DML_PPP_ENCRYPTION, *PDML_PPP_ENCRYPTION;


typedef  enum _DML_PPP_COMPRESSION
{
    DML_PPP_COMPRESSION_None                   = 1,
    DML_PPP_COMPRESSION_VanJacobson            ,
    DML_PPP_COMPRESSION_Lzs
}
DML_PPP_COMPRESSION, *PDML_PPP_COMPRESSION;

typedef  enum _DML_PPP_AUTH
{
    DML_PPP_AUTH_PAP                           = 1,
    DML_PPP_AUTH_CHAP,
    DML_PPP_AUTH_MS_CHAP
}
DML_PPP_AUTH, *PDML_PPP_AUTH;

typedef  struct _DML_PPP_IF_INFO
{
    DML_IF_STATUS              Status;
    char                            Name[64];       /* netdev name in Linux */
    ULONG                           LastChange;
    DML_PPP_CONN_STATUS        ConnectionStatus;
    DML_PPP_CONN_ERROR         LastConnectionError;
    DML_PPP_ENCRYPTION         EncryptionProtocol;
    DML_PPP_COMPRESSION        CompressionProtocol;
    char                       InterfaceServiceName[DML_IF_NAME_LENGTH];
    DML_PPP_AUTH               AuthenticationProtocol;
    pid_t                      pppPid;
    USHORT                          CurrentMRUSize;
    ULONG                           LCPEcho;
    ULONG                           LCPEchoRetry;
    /*
     *  PPPoE
     */
    ULONG                           SessionID;
    /*
     *  IPCP
     */
    ANSC_IPV4_ADDRESS               LocalIPAddress;
    ANSC_IPV4_ADDRESS               RemoteIPAddress;
    ANSC_IPV4_ADDRESS               DNSServers[2];
    char                            Ip6LocalIfID[46];
    char                            Ip6RemoteIfID[46];
}
DML_PPP_IF_INFO,  *PDML_PPP_IF_INFO;


typedef  struct _DML_PPP_IF_FULL
{
    DML_PPP_IF_CFG             Cfg;
    DML_PPP_IF_INFO            Info;
    pthread_mutex_t            mDataMutex;
}
DML_PPP_IF_FULL, *PDML_PPP_IF_FULL;

typedef  struct _DATAMODEL_PPP
{
    SLIST_HEADER                        IfList;                             
    ULONG                               ulIfNextInstance;                   
    ANSC_HANDLE                         hIrepFolderCOSA;                    
    ANSC_HANDLE                         hIrepFolderPPPIf;                   
}
DATAMODEL_PPP,  *PDATAMODEL_PPP;

#endif
