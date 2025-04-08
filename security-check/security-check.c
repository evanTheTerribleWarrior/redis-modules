#include "redismodule.h"
#include <stdlib.h>
#include <string.h>

// template function for the rename-command checks
int check_not_renamed_generic(const char *val, const char *original_cmd) {
    return val == NULL || strlen(val) == 0 || strcmp(val, original_cmd) == 0;
}

// DEFINE Wrapper for the rename-command checks
#define DEFINE_RENAME_CHECK_FN(cmdname)                      \
    int check_##cmdname##_not_renamed(const char *val) {     \
        return check_not_renamed_generic(val, #cmdname);     \
    }

// DEFINE Wrapper for the equality check e.g. is protected-mode == "no"?
#define DEFINE_EQUALS_CHECK_FN(fnname, expected_value)               \
    int fnname(const char *val) {                                    \
        return val && strcmp(val, expected_value) == 0;              \
    }

// DEFINE Wrapper for checking empty value e.g. requirepass == ""?
#define DEFINE_EMPTY_CHECK_FN(fnname)                      \
    int fnname(const char *val) {                          \
        return val == NULL || strlen(val) == 0;            \
    }

// DEFINE Wrapper for checking if substring exists e.g. bind = 0.0.0.0
#define DEFINE_CONTAINS_CHECK_FN(fnname, substring)                  \
    int fnname(const char *val) {                                 \
        return val && strstr(val, substring);                        \
    }

DEFINE_RENAME_CHECK_FN(FLUSHALL)
DEFINE_RENAME_CHECK_FN(CONFIG)
DEFINE_RENAME_CHECK_FN(DEBUG)
DEFINE_RENAME_CHECK_FN(MODULE)
DEFINE_RENAME_CHECK_FN(SCRIPT)
DEFINE_RENAME_CHECK_FN(KEYS)

DEFINE_EQUALS_CHECK_FN(check_protected_mode_off, "no")
DEFINE_EQUALS_CHECK_FN(check_appendonly_off, "no")
DEFINE_EQUALS_CHECK_FN(check_maxmemory_zero, "0")
DEFINE_EQUALS_CHECK_FN(check_noeviction_policy, "noeviction")
DEFINE_EQUALS_CHECK_FN(check_port_default, "6379")
DEFINE_EQUALS_CHECK_FN(check_timeout_not_set, "0")
DEFINE_EQUALS_CHECK_FN(check_tls_disabled, "0")

DEFINE_EMPTY_CHECK_FN(check_requirepass_missing)
DEFINE_EMPTY_CHECK_FN(check_aclfile_missing)
DEFINE_EMPTY_CHECK_FN(check_unixsocket_missing)
DEFINE_EMPTY_CHECK_FN(check_save_disabled)

DEFINE_CONTAINS_CHECK_FN(check_bind_insecure, "0.0.0.0")
DEFINE_CONTAINS_CHECK_FN(check_client_buffer_unlimited, "0 0 0")

typedef struct {
    const char *key;
    int (*insecure_check_fn)(const char *value);
    const char *message;
} RedisConfigStruct;

// To categorise the results based on severity, not yet implemented
typedef enum {
    SEVERITY_CRITICAL,
    SEVERITY_WARNING,
    SEVERITY_INFO
} SeverityLevel;


static const RedisConfigStruct CONFIG_KEYS_RULES[] = {
    {"requirepass", check_requirepass_missing, "requirepass is missing"},
    {"protected-mode", check_protected_mode_off, "protected-mode is disabled"},
    {"appendonly", check_appendonly_off, "AOF persistence is disabled"},
    {"maxmemory", check_maxmemory_zero, "maxmemory is not set"},
    {"maxmemory-policy", check_noeviction_policy, "noeviction policy is set"},
    {"aclfile", check_aclfile_missing, "ACL file is not configured"},
    {"bind", check_bind_insecure, "bind listens to all interfaces"},
    {"port", check_port_default, "redis port is not changed from default 6379"},
    {"unixsocket", check_unixsocket_missing, "unixsocket is not configured"},
    {"save", check_save_disabled, "save is not enabled"},
    {"rename-command FLUSHALL", check_FLUSHALL_not_renamed, "FLUSHALL command is not renamed"},
    {"rename-command CONFIG", check_CONFIG_not_renamed, "CONFIG command is not renamed"},
    {"rename-command DEBUG", check_DEBUG_not_renamed, "DEBUG command is not renamed"},
    {"rename-command MODULE", check_MODULE_not_renamed, "MODULE command is not renamed"},
    {"rename-command SCRIPT", check_SCRIPT_not_renamed, "SCRIPT command is not renamed"},
    {"rename-command KEYS", check_KEYS_not_renamed, "KEYS command is not renamed"},
    {"timeout", check_timeout_not_set, "Client timeout is not set"},
    {"tls-port", check_tls_disabled, "TLS encryption is not enabled"},
    {"client-output-buffer-limit", check_client_buffer_unlimited, "Client output buffer limits are not set"},
    { NULL, NULL, NULL }
};

RedisModuleString **create_config_key_args(RedisModuleCtx *ctx, int *count) {
    
    int n = 0;

    for (int i = 0; CONFIG_KEYS_RULES[i].key != NULL; i++) {
        n++;
    }

    RedisModuleString **args = RedisModule_Alloc(sizeof(RedisModuleString *) * n);

    for (int i = 0; i < n; i++) {
        args[i] = RedisModule_CreateString(ctx, CONFIG_KEYS_RULES[i].key, strlen(CONFIG_KEYS_RULES[i].key));
    }

    *count = n;
    return args;
}


RedisModuleDict *build_config_dict(RedisModuleCtx *ctx, RedisModuleCallReply *reply) {
    
    RedisModuleDict *dict = RedisModule_CreateDict(ctx);
    size_t len = RedisModule_CallReplyLength(reply);

    for (size_t i = 0; i + 1 < len; i += 2) {
        RedisModuleCallReply *key_reply = RedisModule_CallReplyArrayElement(reply, i);
        RedisModuleCallReply *value_reply = RedisModule_CallReplyArrayElement(reply, i + 1);

        size_t key_len, val_len;
        const char *key_str = RedisModule_CallReplyStringPtr(key_reply, &key_len);
        const char *val_str = RedisModule_CallReplyStringPtr(value_reply, &val_len);

        if (key_str && val_str) {
            char *copied_val = RedisModule_Alloc(val_len + 1);
            memcpy(copied_val, val_str, val_len);
            copied_val[val_len] = '\0';
            RedisModule_DictSetC(dict, (void *)key_str, key_len, copied_val);
        }
    }
    return dict;
}


int SecurityCheck_RedisCommand(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {

    RedisModule_AutoMemory(ctx);
    RedisModule_ReplyWithArray(ctx, REDISMODULE_POSTPONED_ARRAY_LEN);

    // We build one array with all the config parameters we want to check (from CONFIG_KEY_RULES table)
    // and we will pass it as parameter to the Redis CONFIG GET command)
    int args_count;
    RedisModuleString **args_array = create_config_key_args(ctx, &args_count);

    // We get the array reply with all the config keys and their values
    RedisModuleCallReply *reply = RedisModule_Call(ctx, "CONFIG", "cv", "GET", args_array, args_count);
    if (RedisModule_CallReplyType(reply) != REDISMODULE_REPLY_ARRAY) {
        return RedisModule_ReplyWithError(ctx, "ERR failed to fetch config values");
    }

    // Build dictionary of key/value pairs from the reply array
    RedisModuleDict *reply_dict = build_config_dict(ctx, reply);

    int total_issues = 0;

    for (int i = 0; CONFIG_KEYS_RULES[i].key != NULL; i++) {

        int is_insecure = 0;
        int nokey;

        // Get the actual value from the config file dictionary for the specific key
        void* dict_value = RedisModule_DictGetC(reply_dict, (void *)CONFIG_KEYS_RULES[i].key, strlen(CONFIG_KEYS_RULES[i].key),&nokey);

        if (nokey || dict_value == NULL) {
            continue;
        }

        // Then we check if this key has an equivalent insecure value to check against
        // or a checker function (e.g. bind)
        is_insecure = CONFIG_KEYS_RULES[i].insecure_check_fn(dict_value);

        // If the value is insecure, we add the relevant message to the result array
        if (is_insecure) {
            RedisModule_ReplyWithString(
                ctx, 
                RedisModule_CreateString(ctx, CONFIG_KEYS_RULES[i].message , strlen(CONFIG_KEYS_RULES[i].message))
            );
            total_issues++;
        }

    }
    
    RedisModule_ReplySetArrayLength(ctx, total_issues);
    return REDISMODULE_OK;
}


int RedisModule_OnLoad(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
    if (RedisModule_Init(ctx,"security.check",1,REDISMODULE_APIVER_1) == REDISMODULE_ERR)
        return REDISMODULE_ERR;

    if (RedisModule_CreateCommand(ctx,"security.check",
        SecurityCheck_RedisCommand, "readonly", 0, 0, 0) == REDISMODULE_ERR)
        return REDISMODULE_ERR;

    return REDISMODULE_OK;
}