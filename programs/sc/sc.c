/*
 * Copyright 2010 Hans Leidekker
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#define WIN32_LEAN_AND_MEAN

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <windows.h>
#include <winsvc.h>
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(sc);

static BOOL parse_string_param( int argc, const WCHAR *argv[], unsigned int *index,
                                const WCHAR *param_name, size_t name_len, const WCHAR **out )
{
    if (!wcsnicmp( argv[*index], param_name, name_len ))
    {
        if (argv[*index][name_len])
        {
            *out = &argv[*index][name_len];
            return TRUE;
        }
        else if (*index < argc - 1)
        {
            *index += 1;
            *out = argv[*index];
            return TRUE;
        }
    }
    return FALSE;
}

struct create_params
{
    const WCHAR *displayname;
    const WCHAR *binpath;
    const WCHAR *group;
    const WCHAR *depend;
    const WCHAR *obj;
    const WCHAR *password;
    DWORD type;
    DWORD start;
    DWORD error;
    BOOL tag;
};

static BOOL parse_create_params( int argc, const WCHAR *argv[], struct create_params *cp )
{
    unsigned int i;

    cp->displayname = NULL;
    cp->type        = SERVICE_WIN32_OWN_PROCESS;
    cp->start       = SERVICE_DEMAND_START;
    cp->error       = SERVICE_ERROR_NORMAL;
    cp->binpath     = NULL;
    cp->group       = NULL;
    cp->tag         = FALSE;
    cp->depend      = NULL;
    cp->obj         = NULL;
    cp->password    = NULL;

#define PARSE(x, y) parse_string_param( (argc), (argv), &(i), (x), ARRAY_SIZE(x) - 1, (y) )
    for (i = 0; i < argc; i++)
    {
        const WCHAR *tag, *type, *start, *error;

        if (PARSE( L"displayname=", &cp->displayname )) continue;
        if (PARSE( L"binpath=", &cp->binpath )) continue;
        if (PARSE( L"group=", &cp->group )) continue;
        if (PARSE( L"depend=", &cp->depend )) continue;
        if (PARSE( L"obj=", &cp->obj )) continue;
        if (PARSE( L"password=", &cp->password )) continue;

        if (PARSE( L"tag=", &tag ))
        {
            if (!wcsicmp( tag, L"yes" ))
            {
                WINE_FIXME("tag argument not supported\n");
                cp->tag = TRUE;
            }
            continue;
        }
        if (PARSE( L"type=", &type ))
        {
            if (!wcsicmp( type, L"own" )) cp->type = SERVICE_WIN32_OWN_PROCESS;
            else if (!wcsicmp( type, L"share" )) cp->type = SERVICE_WIN32_SHARE_PROCESS;
            else if (!wcsicmp( type, L"kernel" )) cp->type = SERVICE_KERNEL_DRIVER;
            else if (!wcsicmp( type, L"filesys" )) cp->type = SERVICE_FILE_SYSTEM_DRIVER;
            else if (!wcsicmp( type, L"rec" )) cp->type = SERVICE_RECOGNIZER_DRIVER;
            else if (!wcsicmp( type, L"interact" )) cp->type |= SERVICE_INTERACTIVE_PROCESS;
            continue;
        }
        if (PARSE( L"start=", &start ))
        {
            if (!wcsicmp( start, L"boot" )) cp->start = SERVICE_BOOT_START;
            else if (!wcsicmp( start, L"system" )) cp->start = SERVICE_SYSTEM_START;
            else if (!wcsicmp( start, L"auto" )) cp->start = SERVICE_AUTO_START;
            else if (!wcsicmp( start, L"demand" )) cp->start = SERVICE_DEMAND_START;
            else if (!wcsicmp( start, L"disabled" )) cp->start = SERVICE_DISABLED;
            continue;
        }
        if (PARSE( L"error=", &error ))
        {
            if (!wcsicmp( error, L"normal" )) cp->error = SERVICE_ERROR_NORMAL;
            else if (!wcsicmp( error, L"severe" )) cp->error = SERVICE_ERROR_SEVERE;
            else if (!wcsicmp( error, L"critical" )) cp->error = SERVICE_ERROR_CRITICAL;
            else if (!wcsicmp( error, L"ignore" )) cp->error = SERVICE_ERROR_IGNORE;
            continue;
        }
    }
#undef PARSE
    if (!cp->binpath) return FALSE;
    return TRUE;
}

static BOOL parse_failure_actions( const WCHAR *arg, SERVICE_FAILURE_ACTIONSW *fa )
{
    unsigned int i, count;
    WCHAR *actions, *p;

    actions = wcsdup( arg );
    if (!actions) return FALSE;

    for (p = actions, count = 0; *p; p++)
    {
        if (*p == '/')
        {
            count++;
            *p = 0;
        }
    }
    count = count / 2 + 1;

    fa->cActions = count;
    fa->lpsaActions = malloc( fa->cActions * sizeof(SC_ACTION) );
    if (!fa->lpsaActions)
    {
        free( actions );
        return FALSE;
    }

    p = actions;
    for (i = 0; i < count; i++)
    {
        if (!wcsicmp( p, L"run" )) fa->lpsaActions[i].Type = SC_ACTION_RUN_COMMAND;
        else if (!wcsicmp( p, L"restart" )) fa->lpsaActions[i].Type = SC_ACTION_RESTART;
        else if (!wcsicmp( p, L"reboot" )) fa->lpsaActions[i].Type = SC_ACTION_REBOOT;
        else fa->lpsaActions[i].Type = SC_ACTION_NONE;

        p += lstrlenW( p ) + 1;
        fa->lpsaActions[i].Delay = wcstol( p, NULL, 10 );
        p += lstrlenW( p ) + 1;
    }

    free( actions );
    return TRUE;
}

static BOOL parse_failure_params( int argc, const WCHAR *argv[], SERVICE_FAILURE_ACTIONSW *fa )
{
    unsigned int i;

    fa->dwResetPeriod = 0;
    fa->lpRebootMsg   = NULL;
    fa->lpCommand     = NULL;
    fa->cActions      = 0;
    fa->lpsaActions   = NULL;

#define PARSE(x, y) parse_string_param( (argc), (argv), &(i), (x), ARRAY_SIZE(x) - 1, (y) )
    for (i = 0; i < argc; i++)
    {
        const WCHAR *reset, *actions;

        if (PARSE( L"reset=", &reset ))
        {
            fa->dwResetPeriod = wcstol( reset, NULL, 10 );
            continue;
        }
        if (PARSE( L"reboot=", (const WCHAR **)&fa->lpRebootMsg )) continue;
        if (PARSE( L"command=", (const WCHAR **)&fa->lpCommand )) continue;
        if (PARSE( L"actions=", &actions ))
        {
            if (!parse_failure_actions( actions, fa )) return FALSE;
            continue;
        }
    }
#undef PARSE
    return TRUE;
}

static void usage( void )
{
    WINE_MESSAGE( "Usage: sc command servicename [parameter= value ...]\n" );
    exit( ERROR_INVALID_COMMAND_LINE );
}

static const WCHAR *service_type_string( DWORD type )
{
    switch (type)
    {
        case SERVICE_WIN32_OWN_PROCESS: return L"WIN32_OWN_PROCESS";
        case SERVICE_WIN32_SHARE_PROCESS: return L"WIN32_SHARE_PROCESS";
        case SERVICE_WIN32: return L"WIN32";
        case SERVICE_KERNEL_DRIVER: return L"KERNEL_DRIVER";
        case SERVICE_FILE_SYSTEM_DRIVER: return L"FILE_SYSTEM_DRIVER";
        case SERVICE_RECOGNIZER_DRIVER: return L"RECOGNIZER_DRIVER";
        case SERVICE_ADAPTER: return L"ADAPTER";
        default: return L"";
    }
}

static const WCHAR *service_state_string( DWORD state )
{
    static const WCHAR * const state_str[] = { L"", L"STOPPED", L"START_PENDING",
        L"STOP_PENDING", L"RUNNING", L"CONTINUE_PENDING", L"PAUSE_PENDING", L"PAUSED" };

    if (state < ARRAY_SIZE( state_str )) return state_str[ state ];
    return L"";
}

static void print_service_status( const WCHAR *name, const SERVICE_STATUS_PROCESS *status,
                                  BOOL extended )
{
    printf( "SERVICE_NAME: %ls\n"
            "        TYPE               : %lx  %ls\n"
            "        STATE              : %lx  %ls\n"
            "        WIN32_EXIT_CODE    : %lu  (0x%lx)\n"
            "        SERVICE_EXIT_CODE  : %lu  (0x%lx)\n"
            "        CHECKPOINT         : 0x%lx\n"
            "        WAIT_HINT          : 0x%lx\n",
            name, status->dwServiceType, service_type_string( status->dwServiceType ),
            status->dwCurrentState, service_state_string( status->dwCurrentState ),
            status->dwWin32ExitCode, status->dwWin32ExitCode,
            status->dwServiceSpecificExitCode, status->dwServiceSpecificExitCode,
            status->dwCheckPoint, status->dwWaitHint );
    if (extended)
        printf( "        PID                : %lu\n"
                "        FLAGS              : %lu\n",
                status->dwProcessId, status->dwServiceFlags );
}

static DWORD query_service( SC_HANDLE manager, const WCHAR *name, BOOL extended )
{
    SC_HANDLE service;
    SERVICE_STATUS_PROCESS status;
    DWORD ret = ERROR_SUCCESS, size;

    service = OpenServiceW( manager, name, SERVICE_QUERY_STATUS );
    if (service)
    {
        if (!QueryServiceStatusEx( service, SC_STATUS_PROCESS_INFO, (BYTE *)&status,
                                   sizeof(status), &size ))
        {
            ret = GetLastError();
            WINE_ERR("failed to query service status %lu\n", ret);
        }
        else
            print_service_status( name, &status, extended );
        CloseServiceHandle( service );
    }
    else
    {
        ret = GetLastError();
        WINE_ERR("failed to open service %lu\n", ret);
    }

    return ret;
}

static DWORD parse_type( const WCHAR *str )
{
    if (!wcsicmp( str, L"all" )) return SERVICE_WIN32 | SERVICE_DRIVER;
    if (!wcsicmp( str, L"driver" )) return SERVICE_DRIVER;
    if (!wcsicmp( str, L"kernel" )) return SERVICE_KERNEL_DRIVER;
    if (!wcsicmp( str, L"filesys" )) return SERVICE_FILE_SYSTEM_DRIVER;
    if (!wcsicmp( str, L"rec" ) || !wcsicmp( str, L"recognizer" ))
        return SERVICE_RECOGNIZER_DRIVER;
    if (!wcsicmp( str, L"interact" )) return SERVICE_INTERACTIVE_PROCESS;
    if (!wcsicmp( str, L"own" )) return SERVICE_WIN32_OWN_PROCESS;
    if (!wcsicmp( str, L"share" )) return SERVICE_WIN32_SHARE_PROCESS;
    return 0;  /* unknown */
}

static DWORD parse_state( const WCHAR *str )
{
    if (!wcsicmp( str, L"active" )) return SERVICE_ACTIVE;
    if (!wcsicmp( str, L"inactive" )) return SERVICE_INACTIVE;
    return SERVICE_STATE_ALL;
}

/* 'sc query' and 'sc queryex' without a service name list every service. */
static DWORD enum_services( SC_HANDLE manager, DWORD type, DWORD state, BOOL extended )
{
    ENUM_SERVICE_STATUS_PROCESSW *info;
    DWORD size = 0x4000, needed = 0, count = 0, resume = 0, ret;
    unsigned int i;

    for (;;)
    {
        if (!(info = malloc( size ))) return ERROR_NOT_ENOUGH_MEMORY;
        /* Restart the enumeration each time: ERROR_MORE_DATA advances the resume
         * handle past what already fits, so reusing it would drop the services
         * that were read into the buffer we just freed. */
        resume = 0;
        if (EnumServicesStatusExW( manager, SC_ENUM_PROCESS_INFO, type, state, (BYTE *)info, size,
                                   &needed, &count, &resume, NULL ))
            break;
        ret = GetLastError();
        free( info );
        if (ret != ERROR_MORE_DATA) return ret;
        size = needed > size ? needed : size * 2;
    }

    for (i = 0; i < count; i++)
    {
        if (i) printf( "\n" );
        print_service_status( info[i].lpServiceName, &info[i].ServiceStatusProcess, extended );
    }

    free( info );
    return ERROR_SUCCESS;
}

static DWORD query_services( SC_HANDLE manager, int argc, const WCHAR *argv[], BOOL extended )
{
    const WCHAR *name = NULL, *str;
    DWORD type = SERVICE_WIN32 | SERVICE_DRIVER, state = SERVICE_STATE_ALL;
    unsigned int i;

#define PARSE(x, y) parse_string_param( (argc), (argv), &(i), (x), ARRAY_SIZE(x) - 1, (y) )
    for (i = 0; i < argc; i++)
    {
        if (PARSE( L"type=", &str ))
        {
            if (!(type = parse_type( str )))
            {
                WINE_ERR("invalid service type %s\n", debugstr_w( str ));
                return ERROR_INVALID_PARAMETER;
            }
            continue;
        }
        if (PARSE( L"state=", &str )) { state = parse_state( str ); continue; }
        if (PARSE( L"bufsize=", &str )) continue;
        if (PARSE( L"ri=", &str )) continue;
        if (PARSE( L"res=", &str )) { WINE_FIXME("res argument not supported\n"); continue; }
        if (PARSE( L"group=", &str )) { WINE_FIXME("group argument not supported\n"); continue; }
        if (!name) { name = argv[i]; continue; }
        WINE_FIXME("unexpected argument %s\n", debugstr_w( argv[i] ));
    }
#undef PARSE

    if (name) return query_service( manager, name, extended );
    return enum_services( manager, type, state, extended );
}

int __cdecl wmain( int argc, const WCHAR *argv[] )
{
    SC_HANDLE manager, service;
    SERVICE_STATUS status;
    DWORD ret = ERROR_SUCCESS;

    if (argc < 2) usage();

    if (argc > 2 && argv[2][0] == '\\' && argv[2][1] == '\\')
    {
        WINE_FIXME("server argument not supported\n");
        return ERROR_INVALID_COMMAND_LINE;
    }

    manager = OpenSCManagerW( NULL, NULL, SC_MANAGER_ALL_ACCESS );
    if (!manager)
    {
        ret = GetLastError();
        WINE_ERR("failed to open service manager: %lu\n", ret);
        return ret;
    }

    if (argc < 3 && wcsicmp( argv[1], L"query" ) && wcsicmp( argv[1], L"queryex" ))
    {
        CloseServiceHandle( manager );
        usage();
    }

    if (!wcsicmp( argv[1], L"create" ))
    {
        struct create_params cp;

        if (argc < 4)
        {
            CloseServiceHandle( manager );
            usage();
        }
        if (!parse_create_params( argc - 3, argv + 3, &cp ))
        {
            WINE_ERR("failed to parse create parameters\n");
            CloseServiceHandle( manager );
            return ret;
        }
        service = CreateServiceW( manager, argv[2], cp.displayname, SERVICE_ALL_ACCESS,
                                  cp.type, cp.start, cp.error, cp.binpath, cp.group, NULL,
                                  cp.depend, cp.obj, cp.password );
        if (service)
        {
            CloseServiceHandle( service );
            ret = ERROR_SUCCESS;
        }
        else
        {
            ret = GetLastError();
            WINE_ERR("failed to create service %lu\n", ret);
        }
    }
    else if (!wcsicmp( argv[1], L"description" ))
    {
        service = OpenServiceW( manager, argv[2], SERVICE_CHANGE_CONFIG );
        if (service)
        {
            SERVICE_DESCRIPTIONW sd;
            sd.lpDescription = argc > 3 ? (WCHAR *)argv[3] : NULL;
            if (!ChangeServiceConfig2W( service, SERVICE_CONFIG_DESCRIPTION, &sd ))
            {
                ret = GetLastError();
                WINE_ERR("failed to set service description %lu\n", ret);
            }
            CloseServiceHandle( service );
        }
        else
        {
            ret = GetLastError();
            WINE_ERR("failed to open service %lu\n", ret);
        }
    }
    else if (!wcsicmp( argv[1], L"failure" ))
    {
        service = OpenServiceW( manager, argv[2], SERVICE_CHANGE_CONFIG );
        if (service)
        {
            SERVICE_FAILURE_ACTIONSW sfa;
            if (parse_failure_params( argc - 3, argv + 3, &sfa ))
            {
                if (!ChangeServiceConfig2W( service, SERVICE_CONFIG_FAILURE_ACTIONS, &sfa ))
                {
                    ret = GetLastError();
                    WINE_ERR("failed to set service failure actions %lu\n", ret);
                }
                free( sfa.lpsaActions );
            }
            else
                WINE_ERR("failed to parse failure parameters\n");
            CloseServiceHandle( service );
        }
        else
        {
            ret = GetLastError();
            WINE_ERR("failed to open service %lu\n", ret);
        }
    }
    else if (!wcsicmp( argv[1], L"delete" ))
    {
        service = OpenServiceW( manager, argv[2], DELETE );
        if (service)
        {
            if (!DeleteService( service ))
            {
                ret = GetLastError();
                WINE_ERR("failed to delete service %lu\n", ret);
            }
            CloseServiceHandle( service );
        }
        else
        {
            ret = GetLastError();
            WINE_ERR("failed to open service %lu\n", ret);
        }
    }
    else if (!wcsicmp( argv[1], L"start" ))
    {
        service = OpenServiceW( manager, argv[2], SERVICE_START );
        if (service)
        {
            if (!StartServiceW( service, argc - 3, argv + 3 ))
            {
                ret = GetLastError();
                WINE_ERR("failed to start service %lu\n", ret);
            }
            else
                ret = query_service( manager, argv[2], FALSE );
            CloseServiceHandle( service );
        }
        else
        {
            ret = GetLastError();
            WINE_ERR("failed to open service %lu\n", ret);
        }
    }
    else if (!wcsicmp( argv[1], L"stop" ))
    {
        service = OpenServiceW( manager, argv[2], SERVICE_STOP );
        if (service)
        {
            if (!ControlService( service, SERVICE_CONTROL_STOP, &status ))
            {
                ret = GetLastError();
                WINE_ERR("failed to stop service %lu\n", ret);
            }
            else
                ret = query_service( manager, argv[2], FALSE );
            CloseServiceHandle( service );
        }
        else
        {
            ret = GetLastError();
            WINE_ERR("failed to open service %lu\n", ret);
        }
    }
    else if (!wcsicmp( argv[1], L"query" ))
    {
        ret = query_services( manager, argc - 2, argv + 2, FALSE );
    }
    else if (!wcsicmp( argv[1], L"queryex" ))
    {
        ret = query_services( manager, argc - 2, argv + 2, TRUE );
    }
    else if (!wcsicmp( argv[1], L"sdset" ))
    {
        WINE_FIXME("SdSet command not supported, faking success\n");
    }
    else
    {
        WINE_FIXME("command not supported\n");
        ret = ERROR_INVALID_COMMAND_LINE;
    }

    CloseServiceHandle( manager );
    return ret;
}
