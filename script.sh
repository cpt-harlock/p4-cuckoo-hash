#!/bin/bash
breaking=10
counter=0
# create interfaces and build code
make create_interface
make 
# remove results file
rm results.txt
touch results.txt
echo -e "total keys\tinserted keys\tdiscarded keys\ttotal recirculation" >> results.txt
for trace in equinix_splitted_1000pkts/*; do
	if (( $counter == $breaking )); then
		break
	fi
	total_keys=$(tcpdump -n -r $trace ip | cut -d" "  -f3 | cut -d"." -f1,2,3,4 | sort | uniq | wc -l)
	sudo simple_switch --thrift-port 9091 -i 0@veth0.0 -i 1@veth1.0 main.json &
	# get stats
	sleep 1
	sudo tcpreplay -p 300 -i veth0.1 $trace 2>/dev/null 1>/dev/null
	inserted_keys=$(make inserted_keys 2>/dev/null | egrep "inserted_keys=" | cut -d" "  -f3)
	discarded_keys=$(make discarded 2>/dev/null | egrep "discarded_keys=" | cut -d" "  -f3)
	recirculation_counter=$(make recirculation 2>/dev/null | egrep "recirculation_counter=" | cut -d" "  -f3)
	echo "total keys $total_keys"
	echo "inserted keys $inserted_keys"
	echo "discarded keys $discarded_keys"
	echo "recirculation_counter $recirculation_counter"
	sleep 1
	#echo sudo killall -9 simple_switch
	sudo killall -9 simple_switch
	sleep 1
	counter=$(($counter + 1))
	echo -e "$total_keys\t$inserted_keys\t$discarded_keys\t$recirculation_counter" >> results.txt
done
