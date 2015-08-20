rm -f uddns.db
echo "adding users..."
./uddns.py fzn a 4
./uddns.py toto toto 1
./uddns.py titi titi 2
./uddns.py &
echo "testing some stuff..."
echo "GET /create4?u=fzn&p=a&n=new" | socat openssl:localhost:4443,cafile=server.pem -
echo "GET /create4?u=fzn&p=a&n=newtwo" | socat openssl:localhost:4443,cafile=server.pem -
echo "GET /create4?u=titi&p=titi&n=ah" | socat openssl:localhost:4443,cafile=server.pem -
echo "GET /chown?u=fzn&p=a&n=ah&o=toto" | socat openssl:localhost:4443,cafile=server.pem -
echo "GET /update4?u=toto&p=toto&n=ah" | socat openssl:localhost:4443,cafile=server.pem -
echo "GET /dump?u=fzn&p=a" |  socat openssl:localhost:4443,cafile=server.pem -
./uddns.py a		# update!
