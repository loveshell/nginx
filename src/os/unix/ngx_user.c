
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>


/*
 * Solaris has thread-safe crypt()
 * Linux has crypt_r(); "struct crypt_data" is more than 128K
 * FreeBSD needs the mutex to protect crypt()
 *
 * TODO:
 *     ngx_crypt_init() to init mutex
 */


#if (NGX_CRYPT)

#if (NGX_HAVE_GNU_CRYPT_R)

ngx_int_t
ngx_libc_crypt(ngx_pool_t *pool, u_char *key, u_char *salt, u_char **encrypted)
{
    char               *value;
    size_t              len;
    ngx_err_t           err;
    struct crypt_data   cd;

    ngx_set_errno(0);

    cd.initialized = 0;
    /* work around the glibc bug */
    cd.current_salt[0] = ~salt[0];

    value = crypt_r((char *) key, (char *) salt, &cd);

    err = ngx_errno;

    if (err == 0) {
        len = ngx_strlen(value) + 1;

        *encrypted = ngx_pnalloc(pool, len);
        if (*encrypted) {
            ngx_memcpy(*encrypted, value, len);
            return NGX_OK;
        }
    }

    ngx_log_error(NGX_LOG_CRIT, pool->log, err, "crypt_r() failed");

    return NGX_ERROR;
}

#else

ngx_int_t
ngx_libc_crypt(ngx_pool_t *pool, u_char *key, u_char *salt, u_char **encrypted)
{
    char       *value;
    size_t      len;
    ngx_err_t   err;

#if (NGX_THREADS && NGX_NONREENTRANT_CRYPT)

    /* crypt() is a time consuming funtion, so we only try to lock */

    if (ngx_mutex_trylock(ngx_crypt_mutex) != NGX_OK) {
        return NGX_AGAIN;
    }

#endif

    ngx_set_errno(0);

    value = crypt((char *) key, (char *) salt);

    if (value) {
        len = ngx_strlen(value) + 1;

        *encrypted = ngx_pnalloc(pool, len);
        if (*encrypted) {
            ngx_memcpy(*encrypted, value, len);
        }

#if (NGX_THREADS && NGX_NONREENTRANT_CRYPT)
        ngx_mutex_unlock(ngx_crypt_mutex);
#endif
        return NGX_OK;
    }

    err = ngx_errno;

#if (NGX_THREADS && NGX_NONREENTRANT_CRYPT)
    ngx_mutex_unlock(ngx_crypt_mutex);
#endif

    ngx_log_error(NGX_LOG_CRIT, pool->log, err, "crypt() failed");

    return NGX_ERROR;
}

#endif

#endif /* NGX_CRYPT */


ngx_uid_t
ngx_uid_by_username(ngx_str_t * name)
{
	struct passwd * pwd = NULL;

	pwd = getpwnam((const char*)name->data);
	if(pwd) {
		return pwd->pw_uid;
	}

	return -1;
}


ngx_gid_t
ngx_gid_by_username(ngx_str_t * name)
{
	struct passwd * pwd = NULL;

	pwd = getpwnam((const char*)name->data);
	if(pwd) {
		return pwd->pw_gid;
	}

	return -1;
}


ngx_gid_t
ngx_gid_by_groupname(ngx_str_t * name)
{
	struct group * grp = NULL;

	grp = getgrnam((const char*)name->data);
	if(grp) {
		return grp->gr_gid;
	}

	return -1;
}
