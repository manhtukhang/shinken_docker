disk_use="$(snmpwalk -v2c -c $2 $1 1.3.6.1.4.1.12356.101.4.1.6 | awk '{print $4}') $(snmpwalk -v2c -c $2 $1 1.3.6.1.4.1.12356.101.4.1.7 | awk '{print $4}')"
# disk_use="1280 3027"
echo $disk_use |\
awk '{\
		percent=int(100*$1/$2);\
		print "Disk capacity: "$2"Mb - Disk used: "$1"Mb|percentages="int(100*$1/$2)"% used="$1"Mb";\
	}{if (percent > 95){\
		exit 2;\
	}else if (percent > 80){\
		exit 1;\
	}\
}'

