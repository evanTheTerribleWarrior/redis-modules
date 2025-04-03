#include "redismodule.h"
#include <stdlib.h>
#include <sys/time.h>
#include <stdio.h>

#define ROOT_PATH "$"
#define LOGS_PATH "$.logs"
#define LAST_TIMESTAMP_PATH "$.last_event_timestamp"
#define COUNT_PATH "$.count"

/*

HONEYPOT - Logs captured IPs and data identified from scan attempts on honeypot ports

Definition:
HONEYPOT <IP> <PORT> <MESSAGE>

JSON object:
{
    "ip": "1.2.3.4",
    "count": 5,
    "last_event_timestamp": 123445564,
    "logs": [
        {
            "port": 22,
            "message": "SSH login attempted",
            "timestamp": 1234345
        }
    ]
}

*/


RedisModuleString *generate_key(RedisModuleCtx *ctx, const char *ip){
    return RedisModule_CreateStringPrintf(ctx, "honeypot:%s", ip);
}


int check_key_exists(RedisModuleCtx *ctx, RedisModuleString *log_key) {
    RedisModuleCallReply *exists = RedisModule_Call(ctx, "JSON.TYPE", "sc", log_key, ROOT_PATH);
    if (RedisModule_CallReplyType(exists) == REDISMODULE_REPLY_NULL) {
        return 0;
    } else {
        return 1;
    }
}

RedisModuleString *init_json_obj(RedisModuleCtx *ctx, const char *ip, unsigned long timestamp){
    return RedisModule_CreateStringPrintf(ctx, "{\"ip\": \"%s\", \"count\": 1, \"last_event_timestamp\": %lu, \"logs\": []}", ip, timestamp);
}

RedisModuleString *create_log_obj(RedisModuleCtx *ctx, const char *port, const char *message, unsigned long timestamp){
    return RedisModule_CreateStringPrintf(ctx, "{\"port\": \"%s\", \"message\": \"%s\", \"timestamp\": %lu}", port, message, timestamp);
}

unsigned long get_current_timestamp() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec;
}

int HoneypotLog_RedisCommand(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {

    if (argc != 4) {
        RedisModule_WrongArity(ctx);
        return REDISMODULE_ERR;
    }

    // Let Redis Module to handle memory management
    RedisModule_AutoMemory(ctx);

    size_t ip_len, port_len, msg_len;
    const char *ip = RedisModule_StringPtrLen(argv[1], &ip_len);
    const char *port = RedisModule_StringPtrLen(argv[2], &port_len);
    const char *message = RedisModule_StringPtrLen(argv[3], &msg_len);

    // Generate the key to be used e.g. honeypot:ip
    RedisModuleString *log_key = generate_key(ctx, ip);

    // Check if key exists
    int exists = check_key_exists(ctx, log_key);
    
    unsigned long timestamp = get_current_timestamp();

    // If key does not exist, initiate the JSON object
    if (!exists) {
        RedisModuleString *init_obj = init_json_obj(ctx, ip, timestamp);
        RedisModule_Call(ctx, "JSON.SET", "scs", log_key, ROOT_PATH, init_obj);
    }

    // Create log object and append to $.logs
    RedisModuleString *log_obj = create_log_obj(ctx, port, message, timestamp);
    RedisModule_Call(ctx, "JSON.ARRAPPEND", "scs", log_key, LOGS_PATH, log_obj);

    // If key exists, update $.last_event_timestamp and $.count
    // Otherwise these are already set above
    if (exists) {
        RedisModule_Call(ctx, "JSON.SET", "scl", log_key, LAST_TIMESTAMP_PATH, timestamp);
        RedisModule_Call(ctx, "JSON.NUMINCRBY", "scl", log_key, COUNT_PATH, 1);
    }

    RedisModule_ReplyWithSimpleString(ctx, "OK");
    return REDISMODULE_OK;
}

int RedisModule_OnLoad(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
    if (RedisModule_Init(ctx,"honeypot",1,REDISMODULE_APIVER_1) == REDISMODULE_ERR)
        return REDISMODULE_ERR;

    if (RedisModule_CreateCommand(ctx,"honeypot",
        HoneypotLog_RedisCommand, "write", 0, 0, 0) == REDISMODULE_ERR)
        return REDISMODULE_ERR;

    return REDISMODULE_OK;
}
