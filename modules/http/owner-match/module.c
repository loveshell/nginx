/* ngx_http_owner_match_module.c
 * Heiher <admin@heiher.info>
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_user.h>


typedef struct {
    ngx_uid_t	uid;
	ngx_gid_t	gid;
    ngx_uint_t	deny;      /* unsigned  deny:1; */
} ngx_http_owner_match_rule_t;


typedef struct {
    ngx_array_t  *rules;     /* array of ngx_http_owner_match_rule_t */
} ngx_http_owner_match_loc_conf_t;


static ngx_int_t ngx_http_owner_match_handler(ngx_http_request_t *r);
static char *ngx_http_owner_match_rule(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static void *ngx_http_owner_match_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_owner_match_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_http_owner_match_init(ngx_conf_t *cf);


static ngx_command_t  ngx_http_owner_match_commands[] = {

    { ngx_string("omallow"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF
                        |NGX_CONF_TAKE2|NGX_CONF_1MORE,
      ngx_http_owner_match_rule,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("omdeny"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF
                        |NGX_CONF_TAKE2|NGX_CONF_1MORE,
      ngx_http_owner_match_rule,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};



static ngx_http_module_t  ngx_http_owner_match_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_owner_match_init,                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_owner_match_create_loc_conf,       /* create location configuration */
    ngx_http_owner_match_merge_loc_conf         /* merge location configuration */
};


ngx_module_t  ngx_http_owner_match_module = {
    NGX_MODULE_V1,
    &ngx_http_owner_match_module_ctx,           /* module context */
    ngx_http_owner_match_commands,              /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_http_owner_match_handler(ngx_http_request_t *r)
{
	ngx_int_t					rt;
	ngx_uid_t					uid;
	ngx_gid_t					gid;
    ngx_uint_t                   i;
	u_char                    *last;
    size_t                     root;
    ngx_str_t                  path;
	ngx_log_t                 *log;
	ngx_file_info_t				fi;
    ngx_http_owner_match_rule_t      *rule;
    ngx_http_owner_match_loc_conf_t  *alcf;

    alcf = ngx_http_get_module_loc_conf(r, ngx_http_owner_match_module);

    if (alcf->rules == NULL) {
        return NGX_DECLINED;
    }

	if (r->uri.data[r->uri.len - 1] == '/') {
        return NGX_DECLINED;
    }

	log = r->connection->log;

    /*
     * ngx_http_map_uri_to_path() allocates memory for terminating '\0'
     * so we do not need to reserve memory for '/' for possible redirect
     */

    last = ngx_http_map_uri_to_path(r, &path, &root, 0);
    if (last == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    path.len = last - path.data;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                   "http filename: \"%s\"", path.data);

	if (ngx_file_info(path.data, &fi) == NGX_FILE_ERROR) {
		ngx_log_error(NGX_LOG_CRIT, log, ngx_errno,
                      ngx_file_info_n " \"%s\" failed", path.data);

		return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
	uid = ngx_file_uid(&fi);
	gid = ngx_file_gid(&fi);

	rt = NGX_DECLINED;
    rule = alcf->rules->elts;
    for (i = 0; i < alcf->rules->nelts; i++) {

        ngx_log_debug3(NGX_LOG_DEBUG_HTTP, log, 0,
                       "owner match file: %s uid: %d gid: %d",
                       path.data, rule[i].uid, rule[i].gid);

		if(((unsigned int)-1==rule[i].uid) && ((unsigned int)-1==rule[i].gid)) {	/* all */
			if (rule[i].deny) {
                ngx_log_error(NGX_LOG_ERR, log, 0,
                                "owner match file: %s forbidden by rule",
								path.data);

                rt = NGX_HTTP_FORBIDDEN;
				break;
            }

            rt = NGX_OK;
			break;
		}
		else if ((uid==rule[i].uid) && (gid==rule[i].gid)) {
            if (rule[i].deny) {
                ngx_log_error(NGX_LOG_ERR, log, 0,
                                "owner match file: %s forbidden by rule",
								path.data);

                rt = NGX_HTTP_FORBIDDEN;
				break;
            }

            rt = NGX_OK;
			break;
        }
    }

	/* free path */
	ngx_pfree(r->pool, path.data);

    return rt;
}
	

static char *
ngx_http_owner_match_rule(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_owner_match_loc_conf_t *alcf = conf;

    ngx_str_t               *value;
	ngx_uint_t				nvalue;
    ngx_http_owner_match_rule_t  *rule;

    if (alcf->rules == NULL) {
        alcf->rules = ngx_array_create(cf->pool, 4,
                                       sizeof(ngx_http_owner_match_rule_t));
        if (alcf->rules == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    rule = ngx_array_push(alcf->rules);
    if (rule == NULL) {
        return NGX_CONF_ERROR;
    }

    value = cf->args->elts;
	nvalue = cf->args->nelts;

    rule->deny = (value[0].data[2] == 'd') ? 1 : 0;

    if (value[1].len == 3 && ngx_strcmp(value[1].data, "all") == 0) {
		rule->uid = -1;
		rule->gid = -1;

        return NGX_CONF_OK;
    }

	rule->uid = ngx_uid_by_username(&value[1]);
	if(3 == nvalue) {
		rule->gid = ngx_gid_by_groupname(&value[2]);
	} else {
		rule->gid = ngx_gid_by_username(&value[1]);
	}

    return NGX_CONF_OK;
}


static void *
ngx_http_owner_match_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_owner_match_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_owner_match_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    return conf;
}


static char *
ngx_http_owner_match_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_owner_match_loc_conf_t  *prev = parent;
    ngx_http_owner_match_loc_conf_t  *conf = child;

    if (conf->rules == NULL) {
        conf->rules = prev->rules;
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_owner_match_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_owner_match_handler;

    return NGX_OK;
}
