
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_USER_H_INCLUDED_
#define _NGX_USER_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef uid_t  ngx_uid_t;
typedef gid_t  ngx_gid_t;


ngx_int_t ngx_libc_crypt(ngx_pool_t *pool, u_char *key, u_char *salt,
    u_char **encrypted);

ngx_uid_t ngx_uid_by_username(ngx_str_t * name);
ngx_gid_t ngx_gid_by_username(ngx_str_t * name);
ngx_gid_t ngx_gid_by_groupname(ngx_str_t * name);

#endif /* _NGX_USER_H_INCLUDED_ */
