# socks5
A light weight socks5 proxy server implemented in c using epoll and nonblocking socket.\
You can use it to surf the Internet scientifically, only UNIX/Linux platforms are supported currently.
## Suport
- No authentication
- Username & Password authentication
- Ipv4 & Ipv6
- Domain name resolution
- "CONNECT" command in socks5 protocol
## Build
```
make
```
## Usage
```
-a : ip address
-p : port
-u<optional> : username
-k<optional> : password
```
## Example
1.Run the server.
```
./socks5 -a 192.168.1.40 -p 6080 -u abc123 -p qwe123
```
2.Run a client such as Proxifier in windows.\
![](https://github.com/bhhbazinga/socks5/blob/master/screenshot/1.png)
3.Configure a socks5 proxy server using the address and port above.\
![](https://github.com/bhhbazinga/socks5/blob/master/screenshot/2.png)
4.Change the proxification rules using the socks5 proxy server we just configured.\
If you see the traffic passing through the socks5 proxy server, you succeeded.\
Enjoy it!
## TODO
- Asynchronous DNS resolutiuon and Cache
- A socks5 client that connects the browser to the server
- Encrypted transmitting
- "BIND" and "ASSOCIATE" command may be supported
