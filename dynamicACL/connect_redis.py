import redis
import socket

set_UE = "ue_ip"
set_UE_rev = "ue_ip_rev"

# hostname = socket.gethostbyname('redis')

r = redis.Redis(host="127.0.0.1", port=6379, db=0)

arg = input().split()

if (arg[0] == "hvals"):
    for x in r.hvals(set_UE):
        if arg[1] == x.decode('UTF-8'):
            print("True", end='')
            break
    else:
        print("False", end='')
elif (arg[0] == "hget"):
    imsi = r.hget(set_UE_rev, arg[1]).decode('UTF-8')
    print(r.hget(imsi, arg[2]).decode('UTF-8'), end='')