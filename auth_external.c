
#include <sys/time.h>
#include <stdlib.h>

#include "../../core/sr_module.h"
#include "../../core/usr_avp.c"
#include "../../core/pvar.h"
#include "../../core/lvalue.h"


MODULE_VERSION

static int mod_init(void);
static int mod_destroy(void);
static int func_auth_jwt(struct sip_msg *msg, char *key, char* val);

typedef struct StatsdParams{
    char *ip;
    char *port;
} StatsdParams;

static StatsdParams statsd_params= {};

static cmd_export_t commands[] = {
	// {"statsd_gauge", (cmd_function)func_gauge, 2, 0, 0, ANY_ROUTE},
	// {"statsd_start", (cmd_function)func_time_start, 1, 0, 0, ANY_ROUTE},
	// {"statsd_stop", (cmd_function)func_time_end, 1, 0, 0, ANY_ROUTE},
	// {"statsd_incr", (cmd_function)func_incr, 1, 0, 0, ANY_ROUTE},
	// {"statsd_decr", (cmd_function)func_decr, 1, 0, 0, ANY_ROUTE},
	{"auth_external_auth", (cmd_function)func_auth_jwt, 2, 0, 0, ANY_ROUTE},
    {0, 0, 0, 0, 0, 0}
};

static param_export_t parameters[] = {
    {"ip", STR_PARAM, &(statsd_params.ip)},
    {"port", STR_PARAM, &(statsd_params.port)},
    {0, 0, 0}
};

struct module_exports exports = {
    "auth_external",    // module name
    DEFAULT_DLFLAGS, // dlopen flags
    commands,        // exported functions
    parameters,      // exported parameters
    NULL,            // exported statistics
    NULL,            // exported MI functions
    NULL,            // exported seudo-variables
    NULL,            // extra processes
    mod_init,        // module init function (before fork. kids will inherit)
    NULL,            // reply processing function
    (destroy_function) mod_destroy,     // destroy function
    NULL       // child init function
};


static int mod_init(void)
{
    LM_INFO("AuthExternal :: INIT");
    return 0;
}

/**
* destroy module function
*/
static int mod_destroy(void)
{
    //statsd_destroy();
    LM_INFO("AuthExternal :: Destroy");
    return 0;
}
 