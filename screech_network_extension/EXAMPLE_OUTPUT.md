# Screech Network Extension + File Monitoring Example Output

This file shows example output from the updated Screech macOS implementation with file event monitoring capabilities.

## Console Output

```
[SCREECH INFO] ScreechMainApp initialized
[SCREECH INFO] Starting Screech monitoring with Network Extension + Endpoint Security
[SCREECH INFO] Setting up Network Extension
[SCREECH INFO] Network Extension configuration saved
[SCREECH INFO] Extension XPC connection established
[SCREECH INFO] Setting up Endpoint Security
[SCREECH INFO] Endpoint Security setup completed
[SCREECH INFO] Screech monitoring started successfully
[SCREECH INFO] Network monitoring: Using Network Extension framework
[SCREECH INFO] Process monitoring: Using Endpoint Security framework
[SCREECH INFO] File monitoring: Using Endpoint Security framework
[SCREECH INFO] Output format: Compatible with Linux eBPF screech
[SCREECH INFO] Monitoring network connections and process events... Press Ctrl+C to stop.

[2024-01-15 10:30:45.123] NEW CONNECTION: TCP 192.168.1.100:54321 -> 142.250.191.14:443 (PID: 1234, Process: Safari)
[2024-01-15 10:30:45.124] EXEC: curl (PID: 1235)
[2024-01-15 10:30:45.125] NEW CONNECTION: TCP 192.168.1.100:54322 -> 93.184.216.34:80 (PID: 1235, Process: curl)
[2024-01-15 10:30:45.126] FILE_CREATE: TextEdit -> /Users/user/Documents/document.txt (PID: 1236, Process: TextEdit, Size: 0 bytes)
[2024-01-15 10:30:45.127] FILE_WRITE: TextEdit -> /Users/user/Documents/document.txt (PID: 1236, Process: TextEdit, Size: 1024 bytes)
[2024-01-15 10:30:45.128] FILE_READ: cat -> /Users/user/Documents/document.txt (PID: 1237, Process: cat, Size: 1024 bytes)
[2024-01-15 10:30:45.129] FILE_CREATE: vim -> /Users/user/code.c (PID: 1238, Process: vim, Size: 0 bytes)
[2024-01-15 10:30:45.130] FILE_WRITE: vim -> /Users/user/code.c (PID: 1238, Process: vim, Size: 2048 bytes)
```

## Log File Format (Greppable)

### screech_TextEdit.log
```
[2024-01-15 10:30:45.126] FILE|FILE_CREATE|PID:1236|PROC:TextEdit|UID:501|FILE:document.txt|SIZE:0|MODE:644|PATH:/Users/user/Documents/document.txt
[2024-01-15 10:30:45.127] FILE|FILE_WRITE|PID:1236|PROC:TextEdit|UID:501|FILE:document.txt|SIZE:1024|MODE:644|PATH:/Users/user/Documents/document.txt
```

### screech_cat.log
```
[2024-01-15 10:30:45.128] FILE|FILE_READ|PID:1237|PROC:cat|UID:501|FILE:document.txt|SIZE:1024|MODE:644|PATH:/Users/user/Documents/document.txt
```

### screech_vim.log
```
[2024-01-15 10:30:45.129] FILE|FILE_CREATE|PID:1238|PROC:vim|UID:501|FILE:code.c|SIZE:0|MODE:644|PATH:/Users/user/code.c
[2024-01-15 10:30:45.130] FILE|FILE_WRITE|PID:1238|PROC:vim|UID:501|FILE:code.c|SIZE:2048|MODE:644|PATH:/Users/user/code.c
```

### screech_Safari.log
```
[2024-01-15 10:30:45.123] CONN|TCP 192.168.1.100:54321->142.250.191.14:443|PID:1234|PROC:Safari|UID:501|PATH:/Applications/Safari.app/Contents/MacOS/Safari
```

### screech_curl.log
```
[2024-01-15 10:30:45.124] EVENT|EXEC|PID:1235|PROC:curl|UID:501|PATH:/usr/bin/curl
[2024-01-15 10:30:45.125] CONN|TCP 192.168.1.100:54322->93.184.216.34:80|PID:1235|PROC:curl|UID:501|PATH:/usr/bin/curl
```

## Filtering Examples

### Show only file creation events
```bash
grep "FILE|FILE_CREATE" screech_*.log
```
Output:
```
screech_TextEdit.log:[2024-01-15 10:30:45.126] FILE|FILE_CREATE|PID:1236|PROC:TextEdit|UID:501|FILE:document.txt|SIZE:0|MODE:644|PATH:/Users/user/Documents/document.txt
screech_vim.log:[2024-01-15 10:30:45.129] FILE|FILE_CREATE|PID:1238|PROC:vim|UID:501|FILE:code.c|SIZE:0|MODE:644|PATH:/Users/user/code.c
```

### Show all events from TextEdit
```bash
grep "PROC:TextEdit" screech_*.log
```
Output:
```
screech_TextEdit.log:[2024-01-15 10:30:45.126] FILE|FILE_CREATE|PID:1236|PROC:TextEdit|UID:501|FILE:document.txt|SIZE:0|MODE:644|PATH:/Users/user/Documents/document.txt
screech_TextEdit.log:[2024-01-15 10:30:45.127] FILE|FILE_WRITE|PID:1236|PROC:TextEdit|UID:501|FILE:document.txt|SIZE:1024|MODE:644|PATH:/Users/user/code.c
```

### Show network connections only
```bash
grep "CONN|" screech_*.log
```
Output:
```
screech_Safari.log:[2024-01-15 10:30:45.123] CONN|TCP 192.168.1.100:54321->142.250.191.14:443|PID:1234|PROC:Safari|UID:501|PATH:/Applications/Safari.app/Contents/MacOS/Safari
screech_curl.log:[2024-01-15 10:30:45.125] CONN|TCP 192.168.1.100:54322->93.184.216.34:80|PID:1235|PROC:curl|UID:501|PATH:/usr/bin/curl
```

### Show file operations on specific file types
```bash
grep "FILE.*\.txt\|FILE.*\.c" screech_*.log
```
Output:
```
screech_TextEdit.log:[2024-01-15 10:30:45.126] FILE|FILE_CREATE|PID:1236|PROC:TextEdit|UID:501|FILE:document.txt|SIZE:0|MODE:644|PATH:/Users/user/Documents/document.txt
screech_TextEdit.log:[2024-01-15 10:30:45.127] FILE|FILE_WRITE|PID:1236|PROC:TextEdit|UID:501|FILE:document.txt|SIZE:1024|MODE:644|PATH:/Users/user/Documents/document.txt
screech_cat.log:[2024-01-15 10:30:45.128] FILE|FILE_READ|PID:1237|PROC:cat|UID:501|FILE:document.txt|SIZE:1024|MODE:644|PATH:/Users/user/Documents/document.txt
screech_vim.log:[2024-01-15 10:30:45.129] FILE|FILE_CREATE|PID:1238|PROC:vim|UID:501|FILE:code.c|SIZE:0|MODE:644|PATH:/Users/user/code.c
screech_vim.log:[2024-01-15 10:30:45.130] FILE|FILE_WRITE|PID:1238|PROC:vim|UID:501|FILE:code.c|SIZE:2048|MODE:644|PATH:/Users/user/code.c
```

## Event Types Monitored

1. **Network Events** (via Network Extension)
   - TCP connections (inbound/outbound)
   - UDP flows
   - Process correlation

2. **Process Events** (via Endpoint Security)
   - Process execution (EXEC)
   - Process forking (FORK)
   - Process termination (EXIT)

3. **File Events** (via Endpoint Security) - **NEW**
   - File creation (FILE_CREATE)
   - File writing (FILE_WRITE)
   - File reading (FILE_READ)

All events include process information (PID, process name, user ID, process path) and are logged in a consistent, greppable format for easy analysis and correlation.
