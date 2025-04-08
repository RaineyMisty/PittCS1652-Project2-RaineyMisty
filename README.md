## Repository Description

- This repository is for the `petnet` project, which is a user-level TCP stack implementation.

### Repository Link
- [PittCS1652-Project2-RaineyMisty](https://www.github.com/RaineyMisty/PittCS1652-Project2-RaineyMisty)

### Contributors

- RaineyMisty
  - It's me

- Eastlive
  - It's also me, another account

## Dependencies:

`libunwind-dev`

## Completeness

### Minimal TCP Stack Implementation

This project is a minimal user-level TCP implementation as part of a networking assignment. It supports basic features including:

#### Features Implemented

1. **3-Way Handshake Phase**

  - Received SYN
  - Replied with SYN-ACK
  - Received final ACK
  - Connection state successfully transitioned to `ESTABLISHED`

2. **Data Transmission Phase**

  - Correctly received the message `"Hello"`
  - Sent appropriate ACK in response
  - Properly handled repeated data/ACK packets (duplicates are filtered and acknowledged once)

3. **Connection Termination Phase**

  - Peer sent a FIN
  - Server responded with an ACK, then sent its own FIN
  - Peer replied with the final ACK  
  - Server transitioned to `CLOSED` state upon receiving the final ACK
  - Repeated FINs from peer are gracefully ignored

#### Project Structure

```
.
├── core/
│   ├── tcp.c
│   └── tcp_connection.h
└── README.md             # This file
```

### How to Run

#### Step 1: Compile the project

```bash
make clean # This step is mandatory
make
```

#### Step 2: Run the TCP server

```bash
./apps/listen_server 3000
```

This starts the server and binds to `192.168.201.12:3000`

#### Step 3: Connect using `nc` (netcat)

```bash
nc 192.168.201.12 3000
```

Type:

```
Hello
```

and press `Ctrl+D` to send the message.

#### Step 4: Inspect with tcpdump

I use `tcpdump` to inspect the packets

```bash
sudo tcpdump -i petnet_bridge -n -X port 3000
```

### Sample Logs

```
Received SYN from 192.168.201.1:52552
Sent SYN-ACK to 192.168.201.1:52552
Received valid ACK from 192.168.201.1:52552 → Connection ESTABLISHED

Received 5 bytes from socket
The data is: Hello
Sent Data Received ACK to 192.168.201.1:52552

Received FIN from 192.168.201.1:52552
Sent ACK in receiving FIN to 192.168.201.1:52552
Sent FIN to 192.168.201.1:52552
Received ACK in LAST_ACK → Connection CLOSED
```

## Notes about `tcp_connection.h`

- The implementation maintains `snd_nxt` and `rcv_nxt` to manage sequence/ack numbers.

## TODO / Improvements

- ✅`__send_ack()`, `__send_syn_ack()` and `___send_fin()`, these three functions can be abstracted into one function to make the code more industrialized.

## Error fix

### Port occupied

```
$ ./apps/listen_server 3000
PETNET[133279153248064] 1743955263.304043> error> listen_server.c(97): Failed to listen on TCP socket (errno=98)
```

- Port 3000 is already occupied by another program and cannot be listened to again

- Use `sudo lsof -i :3000` or `ps -ef | grep listen_server` to find id

- Use `sudo kill -9 <id>` to kill the process

- If cannot find the process, restart the petnet

```
sudo ./petnet_down.sh
sudo ./petnet_up.sh
```

## How to run this project in a new Ubuntu computer

- My VM is broken, so I need to run this project in a new Ubuntu computer.

### Step 1: Install dependencies

```bash
sudo apt-get install libunwind-dev
```

### Step 2: Modify the petnet network setup file

```bash
sudo vim ./petnet/petnet_up.sh
```

- Change the the `username` to your username on the line 4

```text
sudo ip tuntap add dev petnet_tap1 mode tap user <your_username>
```

-  Save and exit