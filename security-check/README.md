# Security Check Redis Module

This Redis module, `security-check`, is designed to perform various security checks on Redis data and configurations.

![Security Check Image](https://github.com/user-attachments/assets/0cd6d86d-aeae-4be8-88e9-436dcb702ab9)

## Requirements

-   Redis Stack (or Redis with the RedisJSON module)
-   `gcc` and `make` (for compiling the module)

## Installation and Usage

### 1. Compiling the Module

  **Clone the Repository:**
```bash
git clone https://github.com/evanTheTerribleWarrior/redis-modules
cd redis-modules
cd security-check
```
  **Compile:**
```bash
make  
```
This will create a `security-check.so` file in the directory and automatically download the redismodule.h library from the official Redis repo, if not present. This library is needed for the module to work.
    

### 2. Loading the Module in Redis

  **Locate the Module:** Ensure you know the full path to the compiled `security-check.so` file.
  
  **Start Redis with the Module:**
```bash
redis-server --loadmodule /path/to/security-check.so
```
Replace `/path/to/security-check.so` with the actual path to your module file.
  
  **Alternative: Load via `redis.conf`:**
You can also add the following line to your `redis.conf` file:
```
loadmodule /path/to/security-check.so
```
Then, restart your Redis server.

### 3. Testing the Module

At the moment the module looks at common configurations of the redis instance (that can be retrieved with `CONFIG GET` command). So it is easy to test just by connecting to the cli and running `SECURITY.CHECK`

### 4. Expected Output

The output would be an array of those configurations whose values are considered insecure. For example:

```bash
127.0.0.1:6379> SECURITY.CHECK
1) "requirepass is missing"
2) "protected-mode is disabled"
3) "maxmemory is not set"
4) "noeviction policy is set"
```