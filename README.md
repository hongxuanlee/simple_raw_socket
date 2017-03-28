### simple raw socket demo

It's only use for linux, I'm still not check in OSX.

### usage

- compile

```
  gcc main.c -o main
```

- set proxy_ip

```
  #define PROXY_IP "100.69.167.224"  // your proxy dev ip
```

- run 

```
  ./main 115.239.211.112  // forward ip to real http server, this ip is www.baidu.com
```

- curl in another machine， now you will recieve result, and every ip packet will through your proxy dev.

```
  curl PROXY_IP:55555
```

### iptables

if you use tcpdump , and despect proxy dev alway send RST to request source, set iptables below：

```
sudo iptables -A OUTPUT -p tcp -m tcp --tcp-flags RST RST -j DROP
```

when your end your demo , then move it by:

```
sudo iptables -D OUTPUT -p tcp -m tcp --tcp-flags RST RST -j DROP

```


