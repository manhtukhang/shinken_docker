#/bin/bash
# 
# Author MT manhtukhang@gmail.com
# 

function getTraffic () {
	local get_data="(snmpget -v 2c -c $2 $1 1.3.6.1.2.1.2.2.1.10.$3 1.3.6.1.2.1.2.2.1.16.$3 1.3.6.1.2.1.2.2.1.5.$3 1.3.6.1.2.1.1.3.0 1.3.6.1.2.1.2.2.1.8.$3)"
	local data_t1=$(eval $get_data)
	sleep 2
	local data_t2=$(eval $get_data)



	local traffic_data_in1=$(echo $data_t1 | awk '{print $4}')
	local traffic_data_in2=$(echo $data_t2 | awk '{print $4}')


	local traffic_data_out1=$(echo $data_t1 | awk '{print $8}')
	local traffic_data_out2=$(echo $data_t2 | awk '{print $8}')


	local time1=$(echo $data_t1 | cut -d "(" -f2 | cut -d ")" -f1)
	local time2=$(echo $data_t2 | cut -d "(" -f2 | cut -d ")" -f1)


	delta_traffic_in=$(echo "$traffic_data_in1 $traffic_data_in2" | awk '{print ($2-$1)}')
	delta_traffic_out=$(echo "$traffic_data_out1 $traffic_data_out2" | awk '{print ($2-$1)}')
	delta_time=$(echo "$time1 $time2" | awk '{print ($2-$1)/100}')
	if_speed=$(echo $data_t1 | awk '{speed=($12/1000000); if(speed == 0){print 100} else {print speed}}')

	if ( [ -z "$(echo $data_t1 | grep up )" ] && [ $delta_traffic_in == 0 ] && [ $delta_traffic_out == 0 ] ); then
		 echo -e "WARNING - Port is DOWN";
		 exit 1;
	fi
}

#___________________________
function caculateTraffic () {
	echo "$1 $delta_time $if_speed" | awk '{print int(($1*8*100)/($2*$3))}'
}

#___________________________
function convertTraffic () {
	echo $1 | awk '{\
				traffic=$1;\

				if (traffic > 1000000){\
					traffic=(traffic/1000000);\
					unit="Mbps";\
				}else if (traffic > 1000){
					traffic=(traffic/1000)
					unit="Kbps";\
				}else{
					traffic=traffic;\
					unit="bps";\
				}\

			}END{printf "%.2f %s", traffic, unit}'
}

#____________________________
function trafficCaculate () {
	getTraffic $1 $2 $3
	# echo $delta_traffic_in

	local traffic_in_raw=$(caculateTraffic $delta_traffic_in)
	local traffic_out_raw=$(caculateTraffic $delta_traffic_out)
	

	local warning_lvl=$(echo $if_speed | awk '{print ($1*85*1000000/100)}')
	local critical_lvl=$(echo $if_speed | awk '{print ($1*95*1000000/100)}')
	# echo $waring_lvl_1

	# local traffic_in_kb=$(echo $traffic_in | awk '{print ($1/1024)}')
	# local traffic_out_kb=$(echo $traffic_out | awk '{print ($1/1024)}')
	
	traffic_in=$(convertTraffic $traffic_in_raw)
	traffic_out=$(convertTraffic $traffic_out_raw)

	echo "OK - Port is UP -- Traffic Avg - In:" $traffic_in  "Out:" $traffic_out"|in="$traffic_in_raw"bps;"$warning_lvl";"$critical_lvl "out="$traffic_out_raw"bps;"$warning_lvl";"$critical_lvl

}

# ______________ main __________________
# 
# while opt=$1; do
# 	case $opt in
# 		port)
HOST_ADDRESS=$1
COMMUNITY=$2
PORT_INDEX=$3
trafficCaculate $HOST_ADDRESS $COMMUNITY $PORT_INDEX
# 			break
# 		;;

# 		*)
# 			echo -e "Usage: check mode <arg>"
# 			echo -e " mode: "
# 			echo -e "  - lc_cpu								Check local CPU"
# 			echo -e "  - lc_ram								Check local RAM"
# 			echo -e "  - port_traff	<arg: host_address community port_index>		Check port in/out traffic"
# 			echo -e "  - "
# 			break
# 		;;
#   esac
# done
# exit 0
