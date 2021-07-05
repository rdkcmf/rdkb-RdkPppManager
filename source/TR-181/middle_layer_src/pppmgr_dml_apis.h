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

#ifndef  _PPPMGR_DML_APIS_H_
#define  _PPPMGR_DML_APIS_H_

BOOL
PPP_GetParamBoolValue
(
 ANSC_HANDLE                 hInsContext,
 char*                       ParamName,
 BOOL*                       pBool
 );

BOOL
PPP_GetParamIntValue
(
 ANSC_HANDLE                 hInsContext,
 char*                       ParamName,
 int*                        pInt
 );

BOOL
PPP_GetParamUlongValue
(
 ANSC_HANDLE                 hInsContext,
 char*                       ParamName,
 ULONG*                      pUlong
 );

ULONG
PPP_GetParamStringValue
(
 ANSC_HANDLE                 hInsContext,
 char*                       ParamName,
 char*                       pValue,
 ULONG*                      pUlSize
 );

/***********************************************************************

  APIs for Object:

  PPP.Interface.{i}.

 *  Interface_GetEntryCount
 *  Interface_GetEntry
 *  Interface_AddEntry
 *  Interface_DelEntry
 *  Interface_GetParamBoolValue
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
ULONG
Interface_GetEntryCount
(
 ANSC_HANDLE
 );

ANSC_HANDLE
Interface_GetEntry
(
 ANSC_HANDLE                 hInsContext,
 ULONG                       nIndex,
 ULONG*                      pInsNumber
 );

ANSC_HANDLE
Interface_AddEntry
(
 ANSC_HANDLE                 hInsContext,
 ULONG*                      pInsNumber
 );

ULONG
Interface_DelEntry
(
 ANSC_HANDLE                 hInsContext,
 ANSC_HANDLE                 hInstance
 );

BOOL
Interface_GetParamBoolValue
(
 ANSC_HANDLE                 hInsContext,
 char*                       ParamName,
 BOOL*                       pBool
 );

BOOL
Interface_GetParamUlongValue
(
 ANSC_HANDLE                 hInsContext,
 char*                       ParamName,
 ULONG*                      pUlong
 );

ULONG
Interface_GetParamStringValue
(
 ANSC_HANDLE                 hInsContext,
 char*                       ParamName,
 char*                       pValue,
 ULONG*                      pUlSize
 );

BOOL
Interface_SetParamBoolValue
(
 ANSC_HANDLE                 hInsContext,
 char*                       ParamName,
 BOOL                        bValue
 );

BOOL
Interface_SetParamIntValue
(
 ANSC_HANDLE                 hInsContext,
 char*                       ParamName,
 int                         value
 );

BOOL
Interface_SetParamUlongValue
(
 ANSC_HANDLE                 hInsContext,
 char*                       ParamName,
 ULONG                       uValuepUlong
 );

BOOL
Interface_SetParamStringValue
(
 ANSC_HANDLE                 hInsContext,
 char*                       ParamName,
 char*                       strValue
 );

BOOL
Interface_Validate
(
 ANSC_HANDLE                 hInsContext,
 char*                       pReturnParamName,
 ULONG*                      puLength
 );

ULONG
Interface_Commit
(
 ANSC_HANDLE                 hInsContext
 );

ULONG
Interface_Rollback
(
 ANSC_HANDLE                 hInsContext
 );

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
BOOL
PPPoE_GetParamBoolValue
(
 ANSC_HANDLE                 hInsContext,
 char*                       ParamName,
 BOOL*                       pBool
 );

BOOL
PPPoE_GetParamIntValue
(
 ANSC_HANDLE                 hInsContext,
 char*                       ParamName,
 int*                        pInt
 );

BOOL
PPPoE_GetParamUlongValue
(
 ANSC_HANDLE                 hInsContext,
 char*                       ParamName,
 ULONG*                      pUlong
 );

ULONG
PPPoE_GetParamStringValue
(
 ANSC_HANDLE                 hInsContext,
 char*                       ParamName,
 char*                       pValue,
 ULONG*                      pUlSize
 );

BOOL
PPPoE_SetParamBoolValue
(
 ANSC_HANDLE                 hInsContext,
 char*                       ParamName,
 BOOL                        bValue
 );

BOOL
PPPoE_SetParamIntValue
(
 ANSC_HANDLE                 hInsContext,
 char*                       ParamName,
 int                         value
 );

BOOL
PPPoE_SetParamUlongValue
(
 ANSC_HANDLE                 hInsContext,
 char*                       ParamName,
 ULONG                       uValuepUlong
 );

BOOL
PPPoE_SetParamStringValue
(
 ANSC_HANDLE                 hInsContext,
 char*                       ParamName,
 char*                       strValue
 );

BOOL
PPPoE_Validate
(
 ANSC_HANDLE                 hInsContext,
 char*                       pReturnParamName,
 ULONG*                      puLength
 );

ULONG
PPPoE_Commit
(
 ANSC_HANDLE                 hInsContext
 );

ULONG
PPPoE_Rollback
(
 ANSC_HANDLE                 hInsContext
 );

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
BOOL
IPCP_GetParamBoolValue
(
 ANSC_HANDLE                 hInsContext,
 char*                       ParamName,
 BOOL*                       pBool
 );

BOOL
IPCP_GetParamIntValue
(
 ANSC_HANDLE                 hInsContext,
 char*                       ParamName,
 int*                        pInt
 );

BOOL
IPCP_GetParamUlongValue
(
 ANSC_HANDLE                 hInsContext,
 char*                       ParamName,
 ULONG*                      pUlong
 );

ULONG
IPCP_GetParamStringValue
(
 ANSC_HANDLE                 hInsContext,
 char*                       ParamName,
 char*                       pValue,
 ULONG*                      pUlSize
 );

BOOL
IPCP_SetParamBoolValue
(
 ANSC_HANDLE                 hInsContext,
 char*                       ParamName,
 BOOL                        bValue
 );

BOOL
IPCP_SetParamIntValue
(
 ANSC_HANDLE                 hInsContext,
 char*                       ParamName,
 int                         value
 );

BOOL
IPCP_SetParamUlongValue
(
 ANSC_HANDLE                 hInsContext,
 char*                       ParamName,
 ULONG                       uValuepUlong
 );

BOOL
IPCP_SetParamStringValue
(
 ANSC_HANDLE                 hInsContext,
 char*                       ParamName,
 char*                       strValue
 );

BOOL
IPCP_Validate
(
 ANSC_HANDLE                 hInsContext,
 char*                       pReturnParamName,
 ULONG*                      puLength
 );

ULONG
IPCP_Commit
(
 ANSC_HANDLE                 hInsContext
 );

ULONG
IPCP_Rollback
(
 ANSC_HANDLE                 hInsContext
 );

/***********************************************************************

  APIs for Object:

  PPP.Interface.{i}.IPv6CP.

 * IPv6CP_GetParamStringValue 

 ***********************************************************************/

ULONG
IPv6CP_GetParamStringValue
(
 ANSC_HANDLE                 hInsContext,
 char*                       ParamName,
 char*                       pValue,
 ULONG*                      pUlSize
 );


/***********************************************************************

  APIs for Object:

  PPP.Interface.{i}.Stats.

 *  Stats_GetParamUlongValue

 ***********************************************************************/

BOOL
Stats_GetParamUlongValue
(
 ANSC_HANDLE                 hInsContext,
 char*                       ParamName,
 ULONG*                      pUlong
 );

#endif
