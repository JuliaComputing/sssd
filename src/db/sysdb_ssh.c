/*
    Authors:
        Jan Cholasta <jcholast@redhat.com>

    Copyright (C) 2012 Red Hat

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <talloc.h>

#include "db/sysdb_ssh.h"
#include "db/sysdb_private.h"

static errno_t
sysdb_update_ssh_host(struct sysdb_ctx *sysdb,
                      const char *name,
                      struct sysdb_attrs *attrs)
{
    TALLOC_CTX *tmp_ctx;
    errno_t ret;

    DEBUG(SSSDBG_TRACE_FUNC, ("Updating host %s\n", name));

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    ret = sysdb_store_custom(sysdb, name, SSH_HOSTS_SUBDIR, attrs);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              ("Error storing host %s [%d]: %s\n", name, ret, strerror(ret)));
        goto done;
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}

errno_t
sysdb_store_ssh_host(struct sysdb_ctx *sysdb,
                     const char *name,
                     const char *alias,
                     time_t now,
                     struct sysdb_attrs *attrs)
{
    TALLOC_CTX *tmp_ctx;
    errno_t ret, sret;
    bool in_transaction = false;
    const char *search_attrs[] = { SYSDB_NAME_ALIAS, NULL };
    bool new_alias;
    struct ldb_message *host = NULL;
    struct ldb_message_element *el;
    unsigned int i;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    ret = sysdb_attrs_add_string(attrs, SYSDB_OBJECTCLASS, SYSDB_SSH_HOST_OC);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              ("Could not set object class [%d]: %s\n", ret, strerror(ret)));
        goto done;
    }

    ret = sysdb_attrs_add_string(attrs, SYSDB_NAME, name);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              ("Could not set name attribute [%d]: %s\n", ret, strerror(ret)));
        goto done;
    }

    if (alias) {
        new_alias = true;

        ret = sysdb_transaction_start(sysdb);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to start transaction\n"));
            goto done;
        }

        in_transaction = true;

        /* copy aliases from the existing entry */
        ret = sysdb_get_ssh_host(tmp_ctx, sysdb, name, search_attrs, &host);
        if (ret != EOK && ret != ENOENT) {
            goto done;
        }

        if (host) {
            el = ldb_msg_find_element(host, SYSDB_NAME_ALIAS);

            if (el) {
                for (i = 0; i < el->num_values; i++) {
                    if (strcmp((char *)el->values[i].data, alias) == 0) {
                        new_alias = false;
                    }

                    ret = sysdb_attrs_add_val(attrs,
                                              SYSDB_NAME_ALIAS, &el->values[i]);
                    if (ret != EOK) {
                        DEBUG(SSSDBG_OP_FAILURE,
                              ("Could not add name alias %s [%d]: %s\n",
                               el->values[i].data, ret, strerror(ret)));
                        goto done;
                    }
                }
            }
        }

        /* add alias only if it is not already present */
        if (new_alias) {
            ret = sysdb_attrs_add_string(attrs, SYSDB_NAME_ALIAS, alias);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE,
                      ("Could not add name alias %s [%d]: %s\n",
                       alias, ret, strerror(ret)));
                goto done;
            }
        }
    }

    ret = sysdb_attrs_add_time_t(attrs, SYSDB_LAST_UPDATE, now);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              ("Could not set sysdb lastUpdate [%d]: %s\n",
               ret, strerror(ret)));
        goto done;
    }

    ret = sysdb_update_ssh_host(sysdb, name, attrs);
    if (ret != EOK) {
        goto done;
    }

    if (in_transaction) {
        ret = sysdb_transaction_commit(sysdb);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to commit transaction\n"));
            goto done;
        }

        in_transaction = false;
    }

    ret = EOK;

done:
    if (in_transaction) {
        sret = sysdb_transaction_cancel(sysdb);
        if (sret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("Could not cancel transaction\n"));
        }
    }

    talloc_free(tmp_ctx);

    return ret;
}

errno_t
sysdb_update_ssh_known_host_expire(struct sysdb_ctx *sysdb,
                                   const char *name,
                                   time_t now,
                                   int known_hosts_timeout)
{
    TALLOC_CTX *tmp_ctx;
    errno_t ret;
    struct sysdb_attrs *attrs;

    DEBUG(SSSDBG_TRACE_FUNC,
          ("Updating known_hosts expire time of host %s\n", name));

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    attrs = sysdb_new_attrs(tmp_ctx);
    if (!attrs) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_attrs_add_time_t(attrs, SYSDB_SSH_KNOWN_HOSTS_EXPIRE,
                                 now + known_hosts_timeout);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              ("Could not set known_hosts expire time [%d]: %s\n",
               ret, strerror(ret)));
        goto done;
    }

    ret = sysdb_update_ssh_host(sysdb, name, attrs);
    if (ret != EOK) {
        goto done;
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}

errno_t
sysdb_delete_ssh_host(struct sysdb_ctx *sysdb,
                      const char *name)
{
    DEBUG(SSSDBG_TRACE_FUNC, ("Deleting host %s\n", name));
    return sysdb_delete_custom(sysdb, name, SSH_HOSTS_SUBDIR);
}

static errno_t
sysdb_search_ssh_hosts(TALLOC_CTX *mem_ctx,
                       struct sysdb_ctx *sysdb,
                       const char *filter,
                       const char **attrs,
                       struct ldb_message ***hosts,
                       size_t *num_hosts)
{
    errno_t ret;
    TALLOC_CTX *tmp_ctx;
    struct ldb_message **results;
    size_t num_results;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    ret = sysdb_search_custom(tmp_ctx, sysdb, filter, SSH_HOSTS_SUBDIR, attrs,
                              &num_results, &results);
    if (ret != EOK && ret != ENOENT) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Error looking up host [%d]: %s\n",
               ret, strerror(ret)));
        goto done;
    } if (ret == ENOENT) {
        DEBUG(SSSDBG_TRACE_FUNC, ("No such host\n"));
        *hosts = NULL;
        *num_hosts = 0;
        goto done;
    }

    *hosts = talloc_steal(mem_ctx, results);
    *num_hosts = num_results;
    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}

errno_t
sysdb_get_ssh_host(TALLOC_CTX *mem_ctx,
                   struct sysdb_ctx *sysdb,
                   const char *name,
                   const char **attrs,
                   struct ldb_message **host)
{
    TALLOC_CTX *tmp_ctx;
    errno_t ret;
    const char *filter;
    struct ldb_message **hosts;
    size_t num_hosts;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    filter = talloc_asprintf(tmp_ctx, "(%s=%s)", SYSDB_NAME, name);
    if (!filter) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_search_ssh_hosts(tmp_ctx, sysdb, filter, attrs,
                                 &hosts, &num_hosts);
    if (ret != EOK) {
        goto done;
    }

    if (num_hosts > 1) {
        ret = EINVAL;
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Found more than one host with name %s\n", name));
        goto done;
    }

    *host = talloc_steal(mem_ctx, hosts[0]);
    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}

errno_t
sysdb_get_ssh_known_hosts(TALLOC_CTX *mem_ctx,
                          struct sysdb_ctx *sysdb,
                          time_t now,
                          const char **attrs,
                          struct ldb_message ***hosts,
                          size_t *num_hosts)
{
    TALLOC_CTX *tmp_ctx;
    errno_t ret;
    const char *filter;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    filter = talloc_asprintf(tmp_ctx, "(%s>=%ld)",
                             SYSDB_SSH_KNOWN_HOSTS_EXPIRE, (long)now);
    if (!filter) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_search_ssh_hosts(mem_ctx, sysdb, filter, attrs,
                                 hosts, num_hosts);

done:
    talloc_free(tmp_ctx);

    return ret;
}
