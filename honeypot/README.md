# Honeypot Redis Module

This Redis module, `honeypot`, is designed to detect and log port scan attempts and other suspicious network traffic. Every attempt is logged using RedisJSON functionalities

## Requirements

-   Redis Stack (or Redis with the RedisJSON module)
-   `gcc` and `make` (for compiling the module)

## Installation and Usage

### 1. Compiling the Module

1.  **Clone the Repository:**
    ```bash
    git clone https://github.com/evanTheTerribleWarrior/redis-modules
    cd redis-modules
    cd honeypot
    ```
2.  **Compile:**
    ```bash
    make
    ```
    This will create a `honeypot.so` file in the directory and automatically download the redismodule.h library from the official Redis repo, if not present. This library is needed for the module to work.
    

### 2. Loading the Module in Redis

1.  **Locate the Module:** Ensure you know the full path to the compiled `honeypot.so` file.
2.  **Start Redis with the Module:**
    ```bash
    redis-server --loadmodule /path/to/honeypot.so
    ```
    Replace `/path/to/honeypot.so` with the actual path to your module file.
3.  **Alternative: Load via `redis.conf`:**
    You can also add the following line to your `redis.conf` file:
    ```
    loadmodule /path/to/honeypot.so
    ```
    Then, restart your Redis server.

### 3. Testing the Module

1.  **Simulate a Port Scan:**
    You can use `nmap` or `netcat` to simulate a port scan. For example:
    ```bash
    nmap -p 1-1000 <redis-server-ip>
    ```
    Or, using `netcat`:
    ```bash
    nc -v <redis-server-ip> 1234
    ```
    Replace `<redis-server-ip>` with the IP address of your Redis server.

2.  **Check the Logs:**
    Connect to your Redis server using `redis-cli` and check for logged IPs and the associated details. For example you could create an index with the fields you want to be able to search on

    ```bash
    redis-cli
    FT.CREATE idx_honeypot ON JSON PREFIX 1 honeypot: SCHEMA $.ip AS ip TAG $.count AS count NUMERIC
    FT.SEARCH idx_honeypot "*"
    ```
    This will give all the JSON records

### 4. Expected Output

After simulating a port scan, you should see JSON data similar to this in Redis for each IP logged:

```json
[
  {
    "ip": "1.2.3.4",
    "count": 5,
    "last_event_timestamp": 123445564,
    "logs": [
        {
            "port": 22,
            "message": "message",
            "timestamp": 1234345
        }
    ]
  }
]
```