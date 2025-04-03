# Honeypot Redis Module

This Redis module, `honeypot`, is designed to detect and log port scan attempts and other suspicious network traffic. Every attempt is logged using RedisJSON functionalities

![Honeypot Image](https://github.com/user-attachments/assets/1cb00a98-6833-48db-b6f4-ff9c43f509df)

## Requirements

-   Redis Stack (or Redis with the RedisJSON module)
-   `gcc` and `make` (for compiling the module)

## Installation and Usage

### 1. Compiling the Module

  **Clone the Repository:**
    ```bash
    git clone https://github.com/evanTheTerribleWarrior/redis-modules
    cd redis-modules
    cd honeypot
    ```
  **Compile:**
    ```bash
    make
    ```
    This will create a `honeypot.so` file in the directory and automatically download the redismodule.h library from the official Redis repo, if not present. This library is needed for the module to work.
    

### 2. Loading the Module in Redis

  **Locate the Module:** Ensure you know the full path to the compiled `honeypot.so` file.
  
  **Start Redis with the Module:**
    ```bash
    redis-server --loadmodule /path/to/honeypot.so
    ```
    Replace `/path/to/honeypot.so` with the actual path to your module file.
  
  **Alternative: Load via `redis.conf`:**
    You can also add the following line to your `redis.conf` file:
    ```
    loadmodule /path/to/honeypot.so
    ```
    Then, restart your Redis server.

### 3. Testing the Module

The provided bash script `capture.sh` could be used as an example to test the module, and adapted as necessary. It uses `tcpdump` with specific flags to capture the traffic and the output is parsed in order to pass the IP, port and full message to the `honeypot` module.

**Run the test script:**

```bash
bash capture.sh
```

**Generate traffic:**
For simplicity the script listens to sample port 9001. In order to generate traffic you can use tools like `nc` and `nmap`.
For example:

```bash
nc 127.0.0.1 9001
```

```bash
nmap 127.0.0.1 -p 9001
```

You can change the flags and ports accordingly to match your needs

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