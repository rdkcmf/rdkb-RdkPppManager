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

#ifndef  _PPPMGR_DML_PPP_APIS_H_
#define  _PPPMGR_DML_PPP_APIS_H_

#include "pppmgr_dml.h"
#include "utctx_api.h"
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/ioctl.h>
#include <utapi_util.h>

#define MAXINSTANCE    128
#define DNS_FILE "/var/run/ppp/resolv.conf"
#define LOG_FILE "/var/log/messages"

#define  IREP_FOLDER_NAME_PPPIF             "PPPIf"
#define  DML_RR_NAME_PPPIFAlias             "Alias"
#define  DML_RR_NAME_PPPIFInsNum            "InstanceNumber"
#define  DML_RR_NAME_PPPIFNextInsNunmber    "NextInstanceNumber"
#define  DML_RR_NAME_PPPIFNewlyAdded        "NewlyAdded"

#define DATAMODEL_PARAM_LENGTH    256

#define PANDM_COMPONENT_NAME  "eRT.com.cisco.spvtg.ccsp.pam"
#define PANDM_DBUS_PATH       "/com/cisco/spvtg/ccsp/pam"

/* DeviceInfo Params */
#define UP_TIME_PARAM_NAME        "Device.DeviceInfo.UpTime"

#if defined(_COSA_BCM_MIPS_) || defined(_ENABLE_DSL_SUPPORT_)
#define INTERFACE "erouter0"
#else
#define INTERFACE "wan0"
#endif

ANSC_STATUS PppSListPushEntryByInsNum( PSLIST_HEADER pListHead, PPPP_IF_LINK_OBJECT pContext );

ANSC_STATUS PppDmlAddIfEntry( ANSC_HANDLE hContext, PDML_PPP_IF_FULL pEntry );

ANSC_STATUS PppDmlGetIfEntry( ANSC_HANDLE hContext, ULONG ulIndex, PDML_PPP_IF_FULL pEntry );

ANSC_STATUS PppDmlGetDefaultValues( ANSC_HANDLE hContext, ULONG  ulIndex, PDML_PPP_IF_FULL pEntry );

ANSC_STATUS PppDmlSetIfValues ( ANSC_HANDLE hContext, ULONG ulIndex, ULONG ulInstanceNumber, char* pAlias );

ANSC_STATUS PPPDmlGetIfInfo( ANSC_HANDLE hContext, ULONG ulInstanceNumber, PDML_PPP_IF_INFO pInfo );

ANSC_STATUS PppDmlDelIfEntry( ANSC_HANDLE hContext, ULONG ulInstanceNumber );

ANSC_STATUS PppDmlSetIfCfg    ( ANSC_HANDLE hContext, PDML_PPP_IF_CFG pCfg );

ANSC_STATUS PppDmlGetIfStats ( ANSC_HANDLE hContext, ULONG ulPppIfInstanceNumber, PDML_IF_STATS pStats, PDML_PPP_IF_FULL pEntry );

BOOL PppDmlIfEnable( ANSC_HANDLE hContext, ULONG ulInstanceNumber, PDML_PPP_IF_FULL pEntry);

ANSC_STATUS PppDmlIfReset( ANSC_HANDLE hContext, ULONG ulInstanceNumber , PDML_PPP_IF_FULL pEntry);

ULONG PppGetIfAddr( char* netdev );

ANSC_STATUS PPPIfRegAddInfo( ANSC_HANDLE hThisObject, ANSC_HANDLE hContext );

ANSC_STATUS PPPIfRegGetInfo( ANSC_HANDLE hThisObject );

ANSC_STATUS PPPIfRegDelInfo( ANSC_HANDLE hThisObject, ANSC_HANDLE hContext );

ANSC_STATUS  PppMgr_checkPidExist( pid_t pppPid );

ANSC_STATUS PppMgr_stopPppProcess( pid_t pid );

ANSC_STATUS PppMgr_stopPppoe(void);

ANSC_STATUS DmlWanmanagerSetParamValues( const char *pComponent, const char *pBus,
        const char *pParamName, const char *pParamVal, enum dataType_e type, unsigned int bCommitFlag );

ANSC_STATUS DmlPppMgrGetWanMgrInstanceNumber(char *pLowerLayers, INT *piInstanceNumber);

static ANSC_STATUS DmlPppMgrGetParamValues(char *pComponent, char *pBus, char *pParamName, char *pReturnVal);

ULONG GetUptimeinSeconds ();

int PppMgr_RdkBus_SetParamValuesToDB( char *pParamName, char *pParamVal );

int validateUsername( char* pString);
#endif
