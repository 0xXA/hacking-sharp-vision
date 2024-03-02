#!/bin/bash

x=`ifconfig | sed -nr 's/eth([0-9]):.*/\1/p'`

for ((i = 1; i <= 255; i++)); do
	sudo ip address flush dev eth${x}
	sudo ip route flush dev eth${x}
	sudo ip address add 192.168.101.${i}/24 brd + dev eth${x}
	sudo ip route add 192.168.101.1 dev eth${x}
	sudo ip route add default via 192.168.101.1 dev eth${x}

	[[ `wget --quiet 192.168.101.1:81 -O /dev/null; echo $?` -eq 0 ]] && {
		printf 'success!! Interface: eth%d, IP: 192.168.101.%d' ${x} ${i}
		break;
	}

	[[ ${i} -eq 255 ]] && printf 'failed!!'
done