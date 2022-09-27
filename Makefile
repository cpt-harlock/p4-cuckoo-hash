P4C = p4c
#P4C = p4c-bm2-ss
P4ARGS = --target bmv2 --arch v1model --std p4-16
all: main.p4
	$(P4C) $(P4ARGS) $^
	
run:
	sudo simple_switch --thrift-port 9091 -i 0@veth0.0 -i 1@veth1.0 main.json

terminal:
	sudo simple_switch_CLI --thrift-port 9091 

#Read register
read_reg:
	echo register_read ch_first_row | sudo simple_switch_CLI --thrift-port 9091


create_interface:
	sudo ip link add veth0.0 type veth peer name veth0.1
	sudo ip link add veth1.0 type veth peer name veth1.1
	sudo ip link set veth0.0 up
	sudo ip link set veth0.1 up
	sudo ip link set veth1.0 up
	sudo ip link set veth1.1 up

delete_interface:
	-sudo ip link del veth0.0 
	-sudo ip link del veth1.0

inserted_keys:
	echo register_read  inserted_keys | sudo simple_switch_CLI --thrift-port 9091
last_key:
	echo register_read  last_key | sudo simple_switch_CLI --thrift-port 9091
recirculation:
	echo register_read  recirculation_counter  | sudo simple_switch_CLI --thrift-port 9091
hit:
	echo register_read  hit_counter  | sudo simple_switch_CLI --thrift-port 9091
cuckoo_first:
	echo register_read  ch_first_row | sudo simple_switch_CLI --thrift-port 9091
cuckoo_second:
	echo register_read  ch_second_row | sudo simple_switch_CLI --thrift-port 9091

