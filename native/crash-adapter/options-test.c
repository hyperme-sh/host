#define HOST_OPTIONS_UNIT
#include "entry.c"
int main(void) {
    sentry_options_t *o=host_options("/unit/database","/unit/handler");
    if(!o) return 1;
    int failed=strcmp(sentry_options_get_dsn(o),"")!=0
        || strcmp(sentry_options_get_proxy(o),"")!=0
        || !sentry_options_get_require_user_consent(o)
        || sentry_options_get_auto_session_tracking(o)
        || sentry_options_get_debug(o)
        || sentry_options_get_cache_keep(o)!=0
        || sentry_options_get_max_breadcrumbs(o)!=0;
    sentry_options_free(o);return failed;
}
