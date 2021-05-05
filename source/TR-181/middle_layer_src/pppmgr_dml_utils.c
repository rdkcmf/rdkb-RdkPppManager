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

extern  ANSC_HANDLE bus_handle;
extern char g_Subsystem[32];

#define NET_STATS_FILE "/proc/net/dev"

void get_wan_proto(wanProto_t * p_wan_proto)
{
    char          output[64] =  {0};

    if (!p_wan_proto)
        return;

    *p_wan_proto = DHCP;

    if ( !syscfg_get(NULL, "wan_proto", output, sizeof(output)) )
    {
        if (!strncmp(output, "pppoe", 5))
            *p_wan_proto = PPPOE;
    }
}

ULONG
PppGetIfAddr
    (
        char*       netdev
    )
{
    ANSC_IPV4_ADDRESS       ip4_addr = {0};

#ifdef _ANSC_LINUX

    struct ifreq            ifr;
    int                     fd = 0;

    strcpy(ifr.ifr_name, netdev);

    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) >= 0)
    {
        if (!ioctl(fd, SIOCGIFADDR, &ifr))
           memcpy(&ip4_addr.Value, ifr.ifr_ifru.ifru_addr.sa_data + 2,4);
        else {
           perror("PppGetIfAddr IOCTL failure.");
           CcspTraceWarning(("Cannot get ipv4 address of netdev:%s\n",netdev));
        }
        close(fd);
    }
    else
        perror("PppGetIfAddr failed to open socket.");

#else

    AnscGetLocalHostAddress(ip4_addr.Dot);

#endif

    return ip4_addr.Value;

}

/*this API is used by bbhm to get pppoe IF address*/
ULONG get_ppp_ip_addr(void)
{
    ULONG addr       = 0;
    wanProto_t proto = 0;
    char buf[128]    = {0};

    /*ppp0 ip address is valid with 3 conditions: ppp0 ip address, ppp_status is "up"; wan_proto is pppoe*/

    get_wan_proto(&proto);
    if (proto != PPPOE)
        return 0;

    if (!commonSyseventGet("ppp_status", buf, sizeof(buf)))
    {
        if (strncmp(buf, "up", 2) != 0)
            return 0;
    }
    else
        return 0;

    return PppGetIfAddr("ppp0");

    return 0;
}

int get_session_id(ULONG * p_id)
{

    FILE * fp;
    char buf[1024] = {0};
    char result[1024] = {0};

    /*session id is only valid when ppp0 link is up*/
    if (!get_ppp_ip_addr())
        return 0;

    if (fp = fopen(LOG_FILE, "r+"))
    {
        while (fgets(buf, sizeof(buf)-1, fp))
        {
            if (strstr(buf, "pppd"))
            {
                if (strstr(buf, "PPP session is") )
                {
                    memset(result, 0, sizeof(result));
                    memcpy(result, buf, sizeof(result)-1);
                }
            }
            memset(buf, 0, sizeof(buf));
        }

        /*result stores the last line for pppd session id*/
        if (result[0])
        {
            char * p = strstr(result, "PPP session is");
            int    id = 0;

            if (p)
            {
                if (sscanf(p, "PPP session is %d", &id) == 1)
                    *p_id = id;
            }
        }

        fclose(fp);
    }

    return 0;

}

int get_auth_proto(int * p_proto)
{
    FILE * fp;
    char buf[1024] = {0};
    char result[1024] = {0};

    if (fp = fopen(LOG_FILE, "r+"))
    {
        while (fgets(buf, sizeof(buf)-1, fp))
        {
            if (strstr(buf, "pppd"))
            {
                if (strstr(buf, "authentication succeeded") || strstr(buf, "authentication failed"))
                {
                    memset(result, 0, sizeof(result));
                    memcpy(result, buf, sizeof(result)-1);
                }
            }
            memset(buf, 0, sizeof(buf));
        }

        /*result stores the last line for pppd authenticatoin log*/
        if (result[0])
        {
            if (strstr(result, "CHAP"))
                *p_proto = DML_PPP_AUTH_CHAP;
            else if (strstr(result, "PAP"))
                *p_proto = DML_PPP_AUTH_PAP;
            else if (strstr(result, "MS-CHAP"))
                *p_proto = DML_PPP_AUTH_MS_CHAP;
        }

        fclose(fp);
    }

    return 0;
}

int safe_strcpy(char * dst, char * src, int dst_size)
{
    if (!dst || !src) return -1;

    memset(dst, 0, dst_size);
    strncpy(dst, src, strlen(src)<=dst_size-1 ? strlen(src):dst_size-1 );

    return 0;
}
