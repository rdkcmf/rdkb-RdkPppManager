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
#include "pppmgr_ssp_global.h"
#include "pppmgr_ssp_messagebus_interface.h"

#define DEBUG_INI_NAME  "/etc/debug.ini"

char                                     g_Subsystem[32]         = {0};
extern char*                             pComponentName;
extern  ANSC_HANDLE                      bus_handle;
extern ANSC_STATUS PppMgr_Init();

#if defined(_ANSC_LINUX)
static void daemonize(void) 
{
    int fd;
    switch (fork()) {
        case 0:
            break;
        case -1:
            // Error
            CcspTraceInfo(("Error daemonizing (fork)! %d - %s\n", errno, strerror(
                            errno)));
            exit(0);
            break;
        default:
            _exit(0);
    }

    if (setsid() < 0) 
    {
        CcspTraceInfo(("Error demonizing (setsid)! %d - %s\n", errno, strerror(errno)));
        exit(0);
    }

#ifndef  _DEBUG
    fd = open("/dev/null", O_RDONLY);
    if (fd != 0) {
        dup2(fd, 0);
        close(fd);
    }
    fd = open("/dev/null", O_WRONLY);
    if (fd != 1) {
        dup2(fd, 1);
        close(fd);
    }
    fd = open("/dev/null", O_WRONLY);
    if (fd != 2) {
        dup2(fd, 2);
        close(fd);
    }
#endif
}

static int  cmd_dispatch(int  command)
{
    switch ( command )
    {
        case    'e' :

#ifdef _ANSC_LINUX
            CcspTraceInfo(("Connect to bus daemon...\n"));

            {
                char                            CName[256];

                if ( g_Subsystem[0] != 0 )
                {
                    sprintf(CName, "%s%s", g_Subsystem, RDK_COMPONENT_ID_PPP_MANAGER);
                }
                else
                {
                    sprintf(CName, "%s", RDK_COMPONENT_ID_PPP_MANAGER);
                }

                ssp_Mbi_MessageBusEngage
                    ( 
                     CName,
                     CCSP_MSG_BUS_CFG,
                     RDK_COMPONENT_PATH_PPP_MANAGER
                    );
            }
#endif

            ssp_create();
            ssp_engage();

            break;

        case    'm':

            AnscPrintComponentMemoryTable(pComponentName);

            break;

        case    't':

            AnscTraceMemoryTable();

            break;

        case    'c':

            ssp_cancel();

            break;

        default:
            break;
    }

    return 0;
}

static void _print_stack_backtrace(void)
{
#ifdef __GNUC__
#ifndef _BUILD_ANDROID
        void* tracePtrs[100];
        char** funcNames = NULL;
        int i, count = 0;

        count = backtrace( tracePtrs, 100 );
        backtrace_symbols_fd( tracePtrs, count, 2 );

        funcNames = backtrace_symbols( tracePtrs, count );

        if ( funcNames ) {
            // Print the stack trace
            for( i = 0; i < count; i++ )
                printf("%s\n", funcNames[i] );

            // Free the string pointers
            free( funcNames );
        }
#endif
#endif
}

void sig_handler(int sig)
{
    if ( sig == SIGINT ) 
    {
        signal(SIGINT, sig_handler); /* reset it to this function */
        CcspTraceInfo(("SIGINT received!\n"));
        exit(0);
    }
    else if ( sig == SIGUSR1 ) 
    {
        signal(SIGUSR1, sig_handler); /* reset it to this function */
        CcspTraceInfo(("SIGUSR1 received!\n"));
    }
    else if ( sig == SIGUSR2 ) 
    {
        CcspTraceInfo(("SIGUSR2 received!\n"));
    }
    else if ( sig == SIGCHLD ) 
    {
        signal(SIGCHLD, sig_handler); /* reset it to this function */
        CcspTraceInfo(("SIGCHLD received!\n"));
    }
    else if ( sig == SIGPIPE ) 
    {
        signal(SIGPIPE, sig_handler); /* reset it to this function */
        CcspTraceInfo(("SIGPIPE received!\n"));
    }
    else if ( sig == SIGALRM ) 
    {
        signal(SIGALRM, sig_handler); /* reset it to this function */
        CcspTraceInfo(("SIGALRM received!\n"));
#ifndef DISABLE_LOGAGENT
        RDKLogEnable = GetLogInfo(bus_handle,"eRT.","Device.LogAgent.X_RDKCENTRAL-COM_LoggerEnable");
        RDKLogLevel = (char)GetLogInfo(bus_handle,"eRT.","Device.LogAgent.X_RDKCENTRAL-COM_LogLevel");
        PPPMANAGER_RDKLogLevel = GetLogInfo(bus_handle,"eRT.","Device.LogAgent.X_RDKCENTRAL-COM_PppManager_LogLevel");
        PPPMANAGER_RDKLogEnable = (char)GetLogInfo(bus_handle,"eRT.","Device.LogAgent.X_RDKCENTRAL-COM_PppManager_LoggerEnable");
#endif
    }
    else 
    {
        /* get stack trace first */
        _print_stack_backtrace();
        CcspTraceInfo(("Signal %d received, exiting!\n", sig));
        exit(0);
    }

}
#endif

int main(int argc, char* argv[])
{
    BOOL                bRunAsDaemon = TRUE;
    int                 idx = 0;
    int                 ind = -1;
    int                 cmdChar            = 0;
    int                 err;
    char                *subSys = NULL;
    BOOL                bPPPIniatilized = TRUE;

#ifdef FEATURE_SUPPORT_RDKLOG
    RDK_LOGGER_INIT();
#endif

    for(idx = 1; idx < argc; idx++)
    {
        if((strcmp(argv[idx], "-subsys") == 0))
        {
            if((idx + 1) < argc) 
            {
                AnscCopyString(g_Subsystem, argv[idx+1]);
            }
            else
            {
                CcspTraceError(("parameter after -subsys is missing"));
            }
        }
        else if ( strcmp(argv[idx], "-c") == 0 )
        {
            bRunAsDaemon = FALSE;
        }
    }

    pComponentName          = RDK_COMPONENT_NAME_PPP_MANAGER;

#if defined(_ANSC_WINDOWSNT)
    AnscStartupSocketWrapper(NULL);

    cmd_dispatch('e');

    RDKLogEnable = GetLogInfo(bus_handle,"eRT.","Device.LogAgent.X_RDKCENTRAL-COM_LoggerEnable");
    RDKLogLevel = (char)GetLogInfo(bus_handle,"eRT.","Device.LogAgent.X_RDKCENTRAL-COM_LogLevel");
    PPPMANAGER_RDKLogLevel = GetLogInfo(bus_handle,"eRT.","Device.LogAgent.X_RDKCENTRAL-COM_PppManager_LogLevel");
    PPPMANAGER_RDKLogEnable = (char)GetLogInfo(bus_handle,"eRT.","Device.LogAgent.X_RDKCENTRAL-COM_PppManager_LoggerEnable");

    while ( cmdChar != 'q' )
    {
        cmdChar = getchar();

        cmd_dispatch(cmdChar);
    }

#elif defined(_ANSC_LINUX)
    if ( bRunAsDaemon ) 
        daemonize();

    CcspTraceInfo(("\nAfter daemonize before signal\n"));

#ifdef INCLUDE_BREAKPAD
    breakpad_ExceptionHandler();
#else
    signal(SIGTERM, sig_handler);
    signal(SIGINT, sig_handler);
    /*signal(SIGCHLD, sig_handler);*/
    signal(SIGUSR1, sig_handler);
    signal(SIGUSR2, sig_handler);

    signal(SIGSEGV, sig_handler);
    signal(SIGBUS, sig_handler);
    signal(SIGKILL, sig_handler);
    signal(SIGFPE, sig_handler);
    signal(SIGILL, sig_handler);
    signal(SIGQUIT, sig_handler);
    signal(SIGHUP, sig_handler);
#endif

    cmd_dispatch('e');

#ifdef _COSA_SIM_
    subSys = "";        /* PC simu use empty string as subsystem */
#else
    subSys = NULL;      /* use default sub-system */
#endif

    RDKLogEnable = GetLogInfo(bus_handle,"eRT.","Device.LogAgent.X_RDKCENTRAL-COM_LoggerEnable");
    RDKLogLevel = (char)GetLogInfo(bus_handle,"eRT.","Device.LogAgent.X_RDKCENTRAL-COM_LogLevel");
    PPPMANAGER_RDKLogLevel = GetLogInfo(bus_handle,"eRT.","Device.LogAgent.X_RDKCENTRAL-COM_PppManager_LogLevel");
    PPPMANAGER_RDKLogEnable = (char)GetLogInfo(bus_handle,"eRT.","Device.LogAgent.X_RDKCENTRAL-COM_PppManager_LoggerEnable");

    err = Cdm_Init(bus_handle, subSys, NULL, NULL, pComponentName);

    if (err != CCSP_SUCCESS)
    {
        fprintf(stderr, "Cdm_Init: %s\n", Cdm_StrError(err));

        bPPPIniatilized = FALSE;

    }

    if(ANSC_STATUS_FAILURE == PppMgr_Init())
    {
        fprintf(stderr, "PPP Manager Initiliasation Failed: %s\n", Cdm_StrError(err));

        bPPPIniatilized = FALSE;
    }
    /* Check if the main thread should be run or not */
    if(bPPPIniatilized)
    {
        if (bRunAsDaemon)
        {
            while(1)
            {
                sleep(30);
            }
        }
        else
        {
            while ( cmdChar != 'q' )
            {
                cmdChar = getchar();

                cmd_dispatch(cmdChar);
            }
        }
    }

#endif
    err = Cdm_Term();
    if (err != CCSP_SUCCESS)
    {
        fprintf(stderr, "Cdm_Term: %s\n", Cdm_StrError(err));

        exit(1);
    }
    CcspTraceInfo(("\n Before ssp_cancel() \n"));

    ssp_cancel();

    CcspTraceInfo(("\nExiting the main function\n"));

    return 0;

}
