all:
	./rebar compile -v
	./rebar escriptize -v
	sed 1,3d rabbit_udp_exchange > rabbit_udp_exchange.ez
	rm -f rabbit_udp_exchange
