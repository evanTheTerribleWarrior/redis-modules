#include "redismodule.h"
#include <stdlib.h>
#include <string.h>

typedef struct {
    const char *key;
    const char *insecure_value;
    int (*insecure_check_fn)(const char *value);
    const char *message;
} RedisConfigStruct;

int check_bind(const char *val) {
    return val && (strstr(val, "0.0.0.0") || strstr(val, "::"));
}

static const RedisConfigStruct CONFIG_KEYS_RULES[] = {
    {"requirepass", "", NULL, "requirepass is missing"},
    {"protected-mode", "no", NULL, "protected-mode is disabled"},
    {"maxmemory", "0", NULL, "maxmemory is not set"},
    {"maxmemory-policy", "noeviction", NULL, "noeviction policy is set"},
    {"bind", NULL, check_bind, "bind listens to all interfaces"},
    { NULL, NULL, NULL, NULL }
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

        void* dict_value = RedisModule_DictGetC(reply_dict, (void *)CONFIG_KEYS_RULES[i].key, strlen(CONFIG_KEYS_RULES[i].key),&nokey);

        printf("We look at key %s and the value found in dictionary is: %s\n", CONFIG_KEYS_RULES[i].key, (const char*)dict_value);
        printf("Nokey has value %d\n", nokey);

        if (nokey || dict_value == NULL) {
            continue;
        }

        // Then we check if this key has an equivalent insecure value to check against
        // or a checker function (e.g. bind)
        if (CONFIG_KEYS_RULES[i].insecure_check_fn){
            is_insecure = CONFIG_KEYS_RULES[i].insecure_check_fn(dict_value);
        }
        else if (CONFIG_KEYS_RULES[i].insecure_value) {
            if (strcmp(dict_value, CONFIG_KEYS_RULES[i].insecure_value) == 0) {
                is_insecure = 1;
            }
        }

        // If the value is insecure, we add the relevant message to the result array
        if (is_insecure) {
            RedisModule_Log(ctx, "notice", "Insecure config detected: %s = %s", CONFIG_KEYS_RULES[i].key, (const char*)dict_value);
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