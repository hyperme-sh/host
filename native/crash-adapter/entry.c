#define _GNU_SOURCE
#include <sentry.h>
#include <dlfcn.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
extern int sentry_host_capture_policy_version(void);
extern void hypermesh_host_crash_start(const char *handler);
extern void hypermesh_host_crash_stop(void);

static sentry_options_t *host_options(const char *database,const char *handler) {
    if (sentry_host_capture_policy_version()!=1) return NULL;
    sentry_options_t *options=sentry_options_new();
    if (!options) return NULL;
    sentry_options_set_dsn(options, "");
    sentry_options_set_proxy(options, "");
    sentry_options_set_require_user_consent(options, 1);
    sentry_options_set_auto_session_tracking(options, 0);
    sentry_options_set_debug(options, 0);
    sentry_options_set_cache_keep(options, 0);
    sentry_options_set_max_breadcrumbs(options, 0);
    sentry_options_set_database_path(options,database);
    sentry_options_set_handler_path(options,handler);
    return options;
}
int hypermesh_host_sdk_initialize(const char *database,const char *handler) {
    sentry_options_t *options=host_options(database,handler);
    return options?sentry_init(options):1;
}
void hypermesh_host_sdk_close(void) { sentry_close(); }
#ifndef HOST_OPTIONS_UNIT
__attribute__((constructor)) static void host_capture_enter(void) {
    Dl_info info;
    if (!dladdr((void *)&host_capture_enter,&info) || !info.dli_fname) return;
    char path[PATH_MAX];
    if (strlen(info.dli_fname)>=sizeof(path)) return;
    strcpy(path,info.dli_fname);
    char *slash=strrchr(path,'/');if(!slash) return;
    const size_t prefix=(size_t)(slash-path)+1;
    if(prefix+strlen("crashpad_handler")>=sizeof(path)) return;
    strcpy(path+prefix,"crashpad_handler");
    hypermesh_host_crash_start(path);
}
__attribute__((destructor)) static void host_capture_leave(void) { hypermesh_host_crash_stop(); }
#endif
