/*
    SSSD

    github_init.c - Initialization of the github provider

    Copyright (C) 2019 Julia Computing Inc

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

#include <ctype.h>
#include <jansson.h>

#include "providers/data_provider/dp.h"
#include "util/tev_curl.h"
#include "util/util.h"

#define GITHUB_TIMEOUT 5
#define CONFDB_GITHUB_KEY "github_key"

#define JSON_CHECK_RET(ret)                                                    \
    if (ret != 0) {                                                            \
        DEBUG(SSSDBG_CRIT_FAILURE,                                             \
              "Failed to unpack JSON payload on line %d: %s\n", error.line,    \
              error.text);                                                     \
        ret = ERR_JSON_DECODING;                                               \
        goto done;                                                             \
    }

#define JSON_CHECK_PARSE(root)                                                 \
    if (root == NULL) {                                                        \
        DEBUG(SSSDBG_CRIT_FAILURE,                                             \
              "Failed to parse JSON payload on line %d: %s\n", error.line,     \
              error.text);                                                     \
        ret = ERR_JSON_DECODING;                                               \
        goto done;                                                             \
    }

#define JSON_CHECK_IS_OBJECT(root)                                             \
    if (!json_is_object(root)) {                                               \
        DEBUG(SSSDBG_CRIT_FAILURE, "Json data is not an object.\n");           \
        json_decref(root);                                                     \
        ret = ERR_JSON_DECODING;                                               \
        goto done;                                                             \
    }

#define JSON_CHECK_IS_ARRAY(root)                                              \
    if (!json_is_array(root)) {                                                \
        DEBUG(SSSDBG_CRIT_FAILURE, "Json data is not an array.\n");            \
        json_decref(root);                                                     \
        ret = ERR_JSON_DECODING;                                               \
        goto done;                                                             \
    }

// We map UIDs and GIDs as follows:
// - UIDs get shifted one bit to the left
// - GIDs for a users primary group are the same as their UIDs
// - GIDs for organizations are the organization id, shifted to the left and
//   with the lowest bit set.
static errno_t github_map_user_uid(uid_t uid, uid_t *mapped_uid) {
    // Reject UIDs that have the high bit set
    if ((uid & (1L << 31)) != 0) {
        return EINVAL;
    }
    *mapped_uid = uid << 1;
    return EOK;
}

static errno_t github_map_org_gid(gid_t gid, gid_t *mapped_gid) {
    // Reject UIDs that have the high bit set
    if ((gid & (1L << 31)) != 0) {
        return EINVAL;
    }
    *mapped_gid = (gid << 1) | 1;
    return EOK;
}

/* TODO: This is copied from ldap. Can we move this somewhere central? */
static errno_t get_sysdb_grouplist_ex(TALLOC_CTX *mem_ctx,
                                      struct sysdb_ctx *sysdb,
                                      struct sss_domain_info *domain,
                                      const char *name, char ***grouplist,
                                      bool get_dn) {
    errno_t ret;
    const char *attrs[2];
    struct ldb_message *msg;
    TALLOC_CTX *tmp_ctx;
    struct ldb_message_element *groups;
    char **sysdb_grouplist = NULL;
    unsigned int i;

    attrs[0] = SYSDB_MEMBEROF;
    attrs[1] = NULL;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx)
        return ENOMEM;

    ret = sysdb_search_user_by_name(tmp_ctx, domain, name, attrs, &msg);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Error searching user [%s] by name: [%s]\n",
              name, strerror(ret));
        goto done;
    }

    groups = ldb_msg_find_element(msg, SYSDB_MEMBEROF);
    if (!groups || groups->num_values == 0) {
        /* No groups for this user in sysdb currently */
        sysdb_grouplist = NULL;
    } else {
        sysdb_grouplist = talloc_array(tmp_ctx, char *, groups->num_values + 1);
        if (!sysdb_grouplist) {
            ret = ENOMEM;
            goto done;
        }

        if (get_dn) {
            /* Get distinguish name */
            for (i = 0; i < groups->num_values; i++) {
                sysdb_grouplist[i] = talloc_strdup(
                    sysdb_grouplist, (const char *)groups->values[i].data);
                if (sysdb_grouplist[i] == NULL) {
                    ret = ENOMEM;
                    goto done;
                }
            }
        } else {
            /* Get a list of the groups by groupname only */
            for (i = 0; i < groups->num_values; i++) {
                ret = sysdb_group_dn_name(sysdb, sysdb_grouplist,
                                          (const char *)groups->values[i].data,
                                          &sysdb_grouplist[i]);
                if (ret != EOK) {
                    DEBUG(SSSDBG_MINOR_FAILURE,
                          "Could not determine group name from [%s]: [%s]\n",
                          (const char *)groups->values[i].data, strerror(ret));
                    goto done;
                }
            }
        }

        sysdb_grouplist[groups->num_values] = NULL;
    }

    *grouplist = talloc_steal(mem_ctx, sysdb_grouplist);

done:
    talloc_free(tmp_ctx);
    return ret;
}

struct github_context {
    struct tcurl_ctx *tcurl;
    struct be_ctx *be_ctx;
    struct confdb_ctx *cdb;
};

int sssm_github_init(TALLOC_CTX *mem_ctx, struct be_ctx *be_ctx,
                     struct data_provider *provider, const char *module_name,
                     void **_module_data) {
    struct github_context *ctx;
    ctx = talloc_zero(mem_ctx, struct github_context);
    if (ctx == NULL) {
        return ENOMEM;
    }

    ctx->be_ctx = be_ctx;
    ctx->tcurl = tcurl_init(mem_ctx, be_ctx->ev);
    if (ctx->tcurl == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Cannot initialize tcurl\n");
        talloc_zfree(ctx);
        return ENOMEM;
    }
    *_module_data = ctx;

    return EOK;
}

struct github_req_state {
    TALLOC_CTX *mem_ctx;
    const char *user;
    const char *user_fqdn;
    struct github_context *ctx;
    struct dp_reply_std reply;
};

struct tevent_req *github_send_api_request(TALLOC_CTX *mem_ctx,
                                           struct github_context *ctx,
                                           const char *url,
                                           struct sss_iobuf *body) {
    struct tcurl_request *tcurl_req;
    struct tevent_req *subreq;
    errno_t ret;

    const char **headers = talloc_zero_array(mem_ctx, const char *, 4);

    char *github_key;
    ret = confdb_get_string(ctx->be_ctx->cdb, mem_ctx, ctx->be_ctx->conf_path,
                            CONFDB_GITHUB_KEY, NULL, &github_key);
    int header_idx = 0;
    headers[header_idx++] = "User-Agent: SSSD GitHub Auth Plugin";
    if (github_key != NULL) {
        char *auth_header =
            talloc_asprintf(headers, "Authorization: token %s", github_key);
        if (auth_header == NULL)
            return NULL;
        headers[header_idx++] = auth_header;
    }
    if (body) {
        headers[header_idx++] = "Content-Type: application/json; charset=utf-8";
    }

    tcurl_req = tcurl_http(mem_ctx, body ? TCURL_HTTP_POST : TCURL_HTTP_GET,
                           NULL, url, headers, body);
    if (tcurl_req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create TCURL request!\n");
        return NULL;
    }

    ret = tcurl_req_verify_peer(tcurl_req, NULL, NULL, true, true);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to verify HTTP peer!\n");
        return NULL;
    }

    subreq = tcurl_request_send(mem_ctx, ctx->be_ctx->ev, ctx->tcurl, tcurl_req,
                                GITHUB_TIMEOUT);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to send request!\n");
        return NULL;
    }

    return subreq;
}

static void github_fetch_user_keys(struct tevent_req *subreq) {
    struct sss_iobuf *response;
    struct tevent_req *req;
    struct github_req_state *state;
    struct sss_domain_info *domain;
    struct sysdb_attrs *attrs = NULL;
    int http_code = 0;
    errno_t ret;
    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct github_req_state);
    ret = tcurl_request_recv(state, subreq, &response, &http_code);
    if (ret != EOK)
        goto done;

    domain = state->ctx->be_ctx->domain;
    if (http_code == 200) {
        attrs = sysdb_new_attrs(state->mem_ctx);
        if (attrs == NULL) {
            ret = ENOMEM;
            goto done;
        }

        json_error_t error;
        json_t *root = json_loadb((const char *)sss_iobuf_get_data(response),
                                  sss_iobuf_get_len(response), 0, &error);
        JSON_CHECK_PARSE(root);
        JSON_CHECK_IS_ARRAY(root);

        int idx;
        json_t *value;
        json_array_foreach(root, idx, value) {
            int key_id;
            char *key;
            ret = json_unpack_ex(value, &error, JSON_STRICT, "{s:i, s:s}", "id",
                                 &key_id, "key", &key);
            JSON_CHECK_RET(ret);

            ret = sysdb_attrs_add_mem(attrs, SYSDB_SSH_PUBKEY, key + 8,
                                      strlen(key) - 8);
            if (ret != EOK) {
                goto done;
            }
        }

        DEBUG(SSSDBG_TRACE_LIBS, "Storing authorized keys.\n");
        ret =
            sysdb_set_user_attr(domain, state->user_fqdn, attrs, SYSDB_MOD_REP);
        if (ret != EOK) {
            goto done;
        }
    } else {
        ret = EINVAL;
        goto done;
    }

done:
    dp_reply_std_set(&state->reply, DP_ERR_DECIDE, ret, NULL);
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        DEBUG(SSSDBG_OP_FAILURE, "github request failed [%d]: %s\n", ret,
              sss_strerror(ret));
        tevent_req_error(req, ret);
    }
}

static void github_org_query_done(struct tevent_req *subreq) {
    struct sss_iobuf *response;
    struct tevent_req *req;
    struct github_req_state *state;
    int http_code = 0;
    errno_t ret;
    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct github_req_state);
    ret = tcurl_request_recv(state, subreq, &response, &http_code);
    if (ret != EOK)
        goto done;

    time_t now = time(NULL);
    if (http_code == 200) {
        json_t *root = NULL;
        json_error_t error;

        DEBUG(SSSDBG_TRACE_LIBS, "Response was :%s",
              sss_iobuf_get_data(response));
        root = json_loadb((const char *)sss_iobuf_get_data(response),
                          sss_iobuf_get_len(response), 0, &error);
        JSON_CHECK_PARSE(root);
        JSON_CHECK_IS_OBJECT(root);

        int totalCount;
        json_t *organizations = NULL;
        ret =
            json_unpack_ex(root, &error, JSON_STRICT, "{s:{s:{s:{s:i, s:o}}}}",
                           "data", "user", "organizations", "totalCount",
                           &totalCount, "nodes", &organizations);
        JSON_CHECK_RET(ret);
        JSON_CHECK_IS_ARRAY(organizations);

        struct sss_domain_info *domain = state->ctx->be_ctx->domain;

        int idx;
        json_t *value;
        char **github_groups = talloc_zero_array(
            state->mem_ctx, char *, json_array_size(organizations) + 1);
        json_array_foreach(organizations, idx, value) {
            gid_t gid;
            char *login;
            ret = json_unpack_ex(value, &error, JSON_STRICT, "{s:s, s:i}",
                                 "login", &login, "databaseId", &gid);
            JSON_CHECK_RET(ret);
            char *login_lower = sss_tc_utf8_str_tolower(state->mem_ctx, login);
            char *group_fqdn = sss_create_internal_fqname(
                state->mem_ctx, login_lower, domain->name);
            github_groups[idx] = group_fqdn;

            ret = github_map_org_gid(gid, &gid);
            if (ret) {
                goto done;
            }

            // TODO: Is it in any way better to check whether the group exists
            // already before doing this/Do we need to do this at all?
            sysdb_store_group(domain, group_fqdn, gid, NULL,
                              domain->group_timeout, now);
        }

        /* Get the current sysdb group list for this user so we can update it.
         */
        char **sysdb_groups = NULL;
        ret = get_sysdb_grouplist_ex(state->mem_ctx, domain->sysdb, domain,
                                     state->user_fqdn, &sysdb_groups, false);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Could not get the list of groups for "
                  "[%s] in the sysdb: [%s]\n",
                  state->user_fqdn, strerror(ret));
            goto done;
        }
        DEBUG(SSSDBG_TRACE_LIBS, "Memberships collected for [%s]\n",
              state->user_fqdn);

        /* Find the differences between the sysdb and LDAP lists.
         * Groups in the sysdb only must be removed. */
        char **add_groups;
        char **del_groups;
        ret = diff_string_lists(state->mem_ctx, github_groups, sysdb_groups,
                                &add_groups, &del_groups, NULL);
        if (ret != EOK) {
            goto done;
        }

        DEBUG(SSSDBG_TRACE_LIBS, "Updating memberships for [%s]\n",
              state->user_fqdn);
        ret = sysdb_update_members(domain, state->user_fqdn, SYSDB_MEMBER_USER,
                                   (const char *const *)add_groups,
                                   (const char *const *)del_groups);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE, "Membership update failed [%d]: %s\n",
                  ret, strerror(ret));
            goto done;
        }
    } else {
        DEBUG(SSSDBG_TRACE_LIBS, "Github request returned with code %d\n",
              http_code);
    }

done:
    dp_reply_std_set(&state->reply, DP_ERR_DECIDE, ret, NULL);
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        DEBUG(SSSDBG_OP_FAILURE, "github request failed [%d]: %s\n", ret,
              sss_strerror(ret));
        tevent_req_error(req, ret);
    }
}

static void github_user_query_done(struct tevent_req *subreq) {
    struct sss_iobuf *response;
    struct tevent_req *req;
    struct github_req_state *state;
    struct sysdb_attrs *attrs = NULL;
    int http_code = 0;
    errno_t ret;
    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct github_req_state);
    ret = tcurl_request_recv(state, subreq, &response, &http_code);
    if (ret != EOK)
        goto done;

    if (http_code == 403) {
        // A 403 on reading public data generally means a rate limit..
        DEBUG(SSSDBG_OP_FAILURE, "GitHub responded with rate limit %s\n",
              sss_iobuf_get_data(response));
        ret = EBUSY;
    } else if (http_code == 404) {
        // It is important to return ENOENT here to make sure the requested
        // user ends up in the negative cache.
        ret = ENOENT;
    } else if (http_code == 200) {
        json_t *root = NULL;
        json_error_t error;

        root = json_loadb((const char *)sss_iobuf_get_data(response),
                          sss_iobuf_get_len(response), 0, &error);
        JSON_CHECK_PARSE(root);
        JSON_CHECK_IS_OBJECT(root);

        ret = EOK;
        uid_t uid;
        char *login = NULL;
        json_t *name = NULL, *location = NULL, *email = NULL;
        ret = json_unpack_ex(root, &error, JSON_STRICT,
                             "{s:i, s:o, s:s, s:o, s:o, *}", "id", &uid, "name",
                             &name, "login", &login, "location", &location,
                             "email", &email);

        if (ret != 0) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Failed to unpack GitHub reply line %d: %s\n", error.line,
                  error.text);
            json_decref(root);
            ret = ERR_JSON_DECODING;
            goto done;
        }

        ret = github_map_user_uid(uid, &uid);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Failed to map uid %d\n", uid);
            goto done;
        }

        char *gecos = talloc_asprintf(
            state->mem_ctx, "%s,%s,,,%s",
            json_is_string(name) ? json_string_value(name) : login,
            json_is_string(location) ? json_string_value(location) : "",
            json_is_string(email) ? json_string_value(email) : "");

        struct sss_domain_info *domain = state->ctx->be_ctx->domain;
        char *login_lower = sss_tc_utf8_str_tolower(state->mem_ctx, login);
        char *fqname_lower = sss_create_internal_fqname(
            state->mem_ctx, login_lower, domain->name);
        if (fqname_lower == NULL) {
            ret = ENOMEM;
            goto done;
        }

        DEBUG(SSSDBG_TRACE_LIBS, "Attempting to store user\n");
        time_t now = time(NULL);
        // TODO: Can we somehow preserve the case here, while still allowing
        // case insensitive lookups?
        ret = sysdb_store_user(
            domain, fqname_lower, NULL, uid, uid, gecos,
            talloc_asprintf(state->mem_ctx, "/home/%s", login_lower),
            "/bin/bash", NULL, attrs, NULL, domain->user_timeout, now);
        if (ret != EOK)
            goto done;

        // Store the group corresponding to the user's primary group
        sysdb_store_group(domain, fqname_lower, uid, NULL,
                          domain->group_timeout, now);

        json_decref(root);

        subreq = github_send_api_request(
            state->mem_ctx, state->ctx,
            talloc_asprintf(state->mem_ctx,
                            "https://api.github.com/users/%s/keys",
                            login_lower),
            NULL);
        if (subreq == NULL) {
            ret = ENOMEM;
            goto done;
        }
        tevent_req_set_callback(subreq, github_fetch_user_keys, req);
        return;

    } else {
        ret = EINVAL;
    }

done:
    dp_reply_std_set(&state->reply, DP_ERR_DECIDE, ret, NULL);
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        DEBUG(SSSDBG_OP_FAILURE, "github request failed [%d]: %s\n", ret,
              sss_strerror(ret));
        tevent_req_error(req, ret);
    }
}

static int is_valid_github_username(char *username) {
    size_t nchars = 0;
    char last_c = '\0';
    if (*username == '-' || *username == '\0')
        return false;
    while (*username != '\0') {
        char c = *username;
        if (!isalnum(c) && c != '-')
            return false;
        if (++nchars > 39)
            return false;
        last_c = c;
        ++username;
    }
    if (last_c == '-')
        return false;
    return true;
}

static int is_all_numeric_username(char *username) {
    while (*username != '\0') {
        if (!isdigit(*username++))
            return false;
    }
    return true;
}

struct tevent_req *github_account_info_handler_send(
    TALLOC_CTX *mem_ctx, struct github_context *ctx, struct dp_id_data *data,
    struct dp_req_params *params) {
    struct github_req_state *state;
    struct tevent_req *req;
    errno_t ret;
    req = tevent_req_create(mem_ctx, &state, struct github_req_state);
    state->mem_ctx = mem_ctx;
    state->ctx = ctx;
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }
    ret = EINVAL;
    int request = data->entry_type & BE_REQ_TYPE_MASK;
    switch (data->entry_type & BE_REQ_TYPE_MASK) {
    case BE_REQ_INITGROUPS:
    case BE_REQ_USER:
        if (data->filter_type != BE_FILTER_NAME) {
            ret = EINVAL;
            goto immediate;
        }

        char *username = NULL;
        ret = sss_parse_internal_fqname(mem_ctx, data->filter_value, &username,
                                        NULL);
        if (ret != EOK || username == NULL)
            goto immediate;

        if (!is_valid_github_username(username)) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "`%s` is not a valid github user name\n", username);
            ret = EINVAL;
            goto immediate;
        }

        // By default, we disallow importing all numeric usernames,
        // because several popular tools will first try to look up
        // a username before interpreting it as a UID and we want to avoid
        // such confusion.
        // TODO: We could map these as #xxxx, since `#` is an invalid character
        // in github usernames and this would avoid the confusion. Also,
        // we should make this configurable.
        if (is_all_numeric_username(username)) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "`%s` is all numeric and thus disallowed for security\n", username);
            ret = EINVAL;
            goto immediate;
        }

        DEBUG(SSSDBG_TRACE_LIBS, "Got request for %s\n", username);
        state->user = username;
        state->user_fqdn = data->filter_value;
        if (request == BE_REQ_USER) {
            char *url = talloc_asprintf(
                mem_ctx, "https://api.github.com/users/%s", username);
            if (url == NULL) {
                ret = ENOMEM;
                goto immediate;
            }

            DEBUG(SSSDBG_TRACE_LIBS, "Sending request to url `%s`\n", url);
            struct tevent_req *subreq =
                github_send_api_request(mem_ctx, ctx, url, NULL);
            if (subreq == NULL) {
                ret = ENOMEM;
                goto immediate;
            }
            tevent_req_set_callback(subreq, github_user_query_done, req);
            DEBUG(SSSDBG_TRACE_LIBS, "Sending github request\n");
            return req;
        } else {
            char *body =
                talloc_asprintf(mem_ctx,
                                "{ \"query\": \"{ user(login: \\\"%s\\\") {"
                                "organizations(first: 100) {"
                                "totalCount nodes { login databaseId }"
                                "}}} \"}",
                                username);
            DEBUG(SSSDBG_TRACE_LIBS, "Sending GraphQL request %s\n", body);

            struct sss_iobuf *buf =
                sss_iobuf_init_readonly(mem_ctx, body, strlen(body));
            struct tevent_req *subreq = github_send_api_request(
                mem_ctx, ctx, "https://api.github.com/graphql", buf);
            if (subreq == NULL) {
                ret = ENOMEM;
                goto immediate;
            }
            tevent_req_set_callback(subreq, github_org_query_done, req);
            DEBUG(SSSDBG_TRACE_LIBS, "Sending github request\n");
            return req;
        }
    }
immediate:
    dp_reply_std_set(&state->reply, DP_ERR_DECIDE, ret, NULL);
    tevent_req_error(req, EINVAL);
    return tevent_req_post(req, params->ev);
}

errno_t github_account_info_handler_recv(TALLOC_CTX *mem_ctx,
                                         struct tevent_req *req,
                                         struct dp_reply_std *data) {
    return EOK;
}

int sssm_github_id_init(TALLOC_CTX *mem_ctx, struct be_ctx *be_ctx,
                        void *module_data, struct dp_method *dp_methods) {
    DEBUG(SSSDBG_TRACE_LIBS, "CTX is %p\n", module_data);
    dp_set_method(
        dp_methods, DPM_ACCOUNT_HANDLER, github_account_info_handler_send,
        github_account_info_handler_recv, (struct github_context *)module_data,
        struct github_context, struct dp_id_data, struct dp_reply_std);

    return EOK;
}
