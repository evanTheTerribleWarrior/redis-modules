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

#define DEFINE_GROUP_BY_SEVERITY(severity)  \


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

typedef enum {
    CRITICAL,
    HIGH,
    WARNING
} SeverityLevel;

typedef struct {
    const char *key;
    int (*insecure_check_fn)(const char *value);
    const char *message;
    SeverityLevel severity;
} RedisConfigStruct;

// Struct to create severity groups and grow them dynamically
typedef struct {
    RedisModuleString **messages;
    size_t count;
    size_t capacity;
} SeverityGroup;

SeverityGroup critical = {0}, high = {0}, warning = {0};

static const RedisConfigStruct CONFIG_KEYS_RULES[] = {
    {"requirepass", check_requirepass_missing, "requirepass is missing", CRITICAL},
    {"protected-mode", check_protected_mode_off, "protected-mode is disabled", CRITICAL},
    {"appendonly", check_appendonly_off, "AOF persistence is disabled", WARNING},
    {"maxmemory", check_maxmemory_zero, "maxmemory is not set", HIGH},
    {"maxmemory-policy", check_noeviction_policy, "noeviction policy is set", HIGH},
    {"aclfile", check_aclfile_missing, "ACL file is not configured", HIGH},
    {"bind", check_bind_insecure, "bind listens to all interfaces", CRITICAL},
    {"port", check_port_default, "redis port is not changed from default 6379", WARNING},
    {"unixsocket", check_unixsocket_missing, "unixsocket is not configured", HIGH},
    {"save", check_save_disabled, "save is not enabled", WARNING},
    {"rename-command FLUSHALL", check_FLUSHALL_not_renamed, "FLUSHALL command is not renamed", CRITICAL},
    {"rename-command CONFIG", check_CONFIG_not_renamed, "CONFIG command is not renamed", HIGH},
    {"rename-command DEBUG", check_DEBUG_not_renamed, "DEBUG command is not renamed", WARNING},
    {"rename-command MODULE", check_MODULE_not_renamed, "MODULE command is not renamed", WARNING},
    {"rename-command SCRIPT", check_SCRIPT_not_renamed, "SCRIPT command is not renamed", HIGH},
    {"rename-command KEYS", check_KEYS_not_renamed, "KEYS command is not renamed", HIGH},
    {"timeout", check_timeout_not_set, "Client timeout is not set", HIGH},
    {"tls-port", check_tls_disabled, "TLS encryption is not enabled", HIGH},
    {"client-output-buffer-limit", check_client_buffer_unlimited, "Client output buffer limits are not set", HIGH},
    { NULL, NULL, NULL, 0}
};

// Prepare a long string with the rules so it can be passed to CONFIG GET as parameter
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

// Build key/value dictionary with the CONFIG GET reply so values can be easily
// retrieved and compared against the rules
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

// Dynamically expand the array of each severity group with new messages 
// as issues are discovered that belong to this category
void add_to_severity_group(SeverityGroup *group, RedisModuleString *msg) {
    if (group->count == group->capacity) {
        size_t new_cap = group->capacity == 0 ? 8 : group->capacity * 2;
        group->messages = RedisModule_Realloc(group->messages, sizeof(RedisModuleString *) * new_cap);
        group->capacity = new_cap;
    }
    group->messages[group->count++] = msg;
}

// Print arrays of severity groups to the client
void reply_with_severity_group(RedisModuleCtx *ctx, const char *severity_str, SeverityGroup *group) {
    RedisModule_ReplyWithArray(ctx, 2);
    RedisModule_ReplyWithSimpleString(ctx, severity_str);
    RedisModule_ReplyWithArray(ctx, group->count);
    for (size_t i = 0; i < group->count; i++) {
        RedisModule_ReplyWithString(ctx, group->messages[i]);
    }
}


int SecurityCheck_RedisCommand(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {

    RedisModule_AutoMemory(ctx);
    RedisModule_ReplyWithArray(ctx, REDISMODULE_POSTPONED_LEN);

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

    for (int i = 0; CONFIG_KEYS_RULES[i].key != NULL; i++) {

        int is_insecure = 0;
        int nokey;

        // Get the actual value from the config file dictionary for the specific key
        void* dict_value = RedisModule_DictGetC(reply_dict, (void *)CONFIG_KEYS_RULES[i].key, strlen(CONFIG_KEYS_RULES[i].key),&nokey);

        if (nokey || dict_value == NULL) {
            continue;
        }

        // We check if the value retrieved is considered insecure by using the relevant function pointer
        is_insecure = CONFIG_KEYS_RULES[i].insecure_check_fn(dict_value);

        // If the value is insecure, we add the relevant message to the severity group array
        if (is_insecure) {

            RedisModuleString *msg = RedisModule_CreateString(ctx, CONFIG_KEYS_RULES[i].message, strlen(CONFIG_KEYS_RULES[i].message));
            switch (CONFIG_KEYS_RULES[i].severity) {
                case CRITICAL:
                    add_to_severity_group(&critical, msg);
                    break;
                case HIGH:
                    add_to_severity_group(&high, msg);
                    break;
                case WARNING:
                    add_to_severity_group(&warning, msg);
                    break;
            }

        }

    }

    int group_count = 0;

    if (critical.count) {
        reply_with_severity_group(ctx, "CRITICAL", &critical);
        group_count++;
    }

    if (high.count) {
        reply_with_severity_group(ctx, "HIGH", &high);
        group_count++;
    }

    if (warning.count) {
        reply_with_severity_group(ctx, "WARNING", &warning);
        group_count++;
    }
    
    RedisModule_ReplySetArrayLength(ctx, group_count);
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