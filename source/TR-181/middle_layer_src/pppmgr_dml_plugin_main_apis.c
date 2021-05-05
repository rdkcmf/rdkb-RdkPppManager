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

#include "pppmgr_dml_plugin_main_apis.h"
#include "pppmgr_dml_ppp_apis.h"
#include "pppmgr_ssp_global.h"
#include "pppmgr_dml.h"

extern void * g_pDslhDmlAgent;

/**********************************************************************

    caller:     owner of the object

    prototype:

        ANSC_HANDLE
        BackEndManagerCreate
            (
            );

    description:

        This function constructs datamodel object and return handle.

    argument:

    return:     newly created qos object.

**********************************************************************/

ANSC_HANDLE
BackEndManagerCreate
    (
        VOID
    )
{
    ANSC_STATUS                returnStatus = ANSC_STATUS_SUCCESS;
    PBACKEND_MANAGER_OBJECT    pMyObject    = (PBACKEND_MANAGER_OBJECT)NULL;

    /*
        * We create object by first allocating memory for holding the variables and member functions.
        */
    pMyObject = (PBACKEND_MANAGER_OBJECT) AnscAllocateMemory(sizeof(BACKEND_MANAGER_OBJECT));

    if (!pMyObject)
    {
        return  (ANSC_HANDLE)NULL;
    }
    pMyObject->hPPP = (PDATAMODEL_PPP) AnscAllocateMemory(sizeof(DATAMODEL_PPP));

    /*
     * Initialize the common variables and functions for a container object.
     */
    pMyObject->Oid               = DATAMODEL_BASE_OID;
    pMyObject->Create            = BackEndManagerCreate;
    pMyObject->Remove            = BackEndManagerRemove;
    pMyObject->Initialize        = BackEndManagerInitialize;

    return  (ANSC_HANDLE)pMyObject;
}

/**********************************************************************

    caller:     self

    prototype:

        ANSC_STATUS
        BackEndManagerRemove
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function remove manager object and return handle.

    argument:   ANSC_HANDLE                 hThisObject
            This handle is actually the pointer of this object
            itself.

    return:     operation status.

**********************************************************************/

ANSC_STATUS
BackEndManagerRemove
    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PBACKEND_MANAGER_OBJECT         pMyObject    = (PBACKEND_MANAGER_OBJECT)hThisObject;

    if (pMyObject == NULL)
    {
        AnscTraceError(("%s:%d:: Pointer is null!!\n", __FUNCTION__, __LINE__));
        return ANSC_STATUS_FAILURE;
    }

    AnscFreeMemory((ANSC_HANDLE)pMyObject->hPPP);

    /* Remove self */
    AnscFreeMemory((ANSC_HANDLE)pMyObject);

    return returnStatus;
}

/**********************************************************************

    caller:     self

    prototype:

        ANSC_STATUS
        BackEndManagerInitialize
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function initiate manager object and return handle.

    argument:   ANSC_HANDLE                 hThisObject
            This handle is actually the pointer of this object
            itself.

    return:     operation status.

**********************************************************************/

ANSC_STATUS
BackEndManagerInitialize
    (
        ANSC_HANDLE                 hThisObject
    )
{

    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PBACKEND_MANAGER_OBJECT  pMyObject    = (PBACKEND_MANAGER_OBJECT)hThisObject;
    PPOAM_IREP_FOLDER_OBJECT        pPoamIrepFoDml     = (PPOAM_IREP_FOLDER_OBJECT)NULL;
    PPOAM_IREP_FOLDER_OBJECT        pPoamIrepFoPPPIf    = (PPOAM_IREP_FOLDER_OBJECT)NULL;
    PSLAP_VARIABLE                  pSlapVariable       = (PSLAP_VARIABLE          )NULL;
    PDML_PPP_IF_FULL           pEntry              = (PDML_PPP_IF_FULL   )NULL;
    PPPP_IF_LINK_OBJECT       pLinkObj        = (PPPP_IF_LINK_OBJECT)NULL;
    ULONG                           ulEntryCount        = 0;
    ULONG                           ulIndex             = 0;
    ULONG                           ulNextInsNum        = 0;

    if (pMyObject == NULL)
    {
        AnscTraceError(("%s:%d:: Pointer is null!!\n", __FUNCTION__, __LINE__));
        return ANSC_STATUS_FAILURE;
    }
    PDATAMODEL_PPP           pPpp         = (PDATAMODEL_PPP)pMyObject->hPPP;

    if (pPpp == NULL)
    {
        AnscTraceError(("%s:%d:: Pointer is null!!\n", __FUNCTION__, __LINE__));
        return ANSC_STATUS_FAILURE;
    }

    /* Initiation Device.PPP.Interface */

    AnscSListInitializeHeader(&pPpp->IfList);

    pPpp->ulIfNextInstance = 1;

    pPpp->hIrepFolderCOSA = g_GetRegistryRootFolder(g_pDslhDmlAgent);

    pPoamIrepFoDml = (PPOAM_IREP_FOLDER_OBJECT)pPpp->hIrepFolderCOSA;
    if ( !pPoamIrepFoDml )
    {
        return ANSC_STATUS_FAILURE;
    }

    pPoamIrepFoPPPIf =
        (PPOAM_IREP_FOLDER_OBJECT)pPoamIrepFoDml->GetFolder
        (
         (ANSC_HANDLE)pPoamIrepFoDml,
         IREP_FOLDER_NAME_PPPIF
        );

    if ( !pPoamIrepFoPPPIf )
    {
        pPoamIrepFoPPPIf =
            pPoamIrepFoDml->AddFolder
            (
             (ANSC_HANDLE)pPoamIrepFoDml,
             IREP_FOLDER_NAME_PPPIF,
             0
            );
    }

    if ( !pPoamIrepFoPPPIf )
    {
        return ANSC_STATUS_FAILURE;
    }
    else
    {
        pPpp->hIrepFolderPPPIf = (ANSC_HANDLE)pPoamIrepFoPPPIf;
    }

    return returnStatus;

}

