# SimplePing
Ping with linux raw socket using ICMP(V6)

## Build
```bash
mkdir build && cd build
cmake ..
make
```

## Run
* ping google.com `sudo ./simpleping google.com`
* ping 127.0.0.1 with ttl=64 `sudo ./simpleping 127.0.0.1 64`
* ping ::1 with auto hop limit 3 times `sudo ./simpleping ::1 0 3`
