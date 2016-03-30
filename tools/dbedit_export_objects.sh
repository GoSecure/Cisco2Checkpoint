#!/bin/bash 
echo "printxml network_objects" > printxml_netobj.txt
echo "printxml services" > printxml_services.txt
echo '<a>' > customer_network_objects.xml
dbedit -local -f printxml_netobj.txt >> customer_network_objects.xml
echo '</a>' >> customer_network_objects.xml
echo '<a>' > customer_service_objects.xml
dbedit -local -f printxml_services.txt >> customer_service_objects.xml
echo '</a>' >> customer_service_objects.xml
# rm printxml_netobj.txt
# rm printxml_services.txt
