# HTTP Sniffer
A Python Program that sniffs HTTP Packets and displays useful information on the screen.

## Requirements
Language Used = Python3<br />
Modules/Packages used:
* os
* sys
* pickle
* scapy
* datetime
* optparse
* colorama
* time

## Input
* '-i', "--iface" : Interface on which sniffing has to be done
* '-v', "--verbose" : Display Useful Information related to the packets on the screen (True/False)(Default = True)
* '-w', "--write" : Dump the Packets to file
* '-r', "--read" : Read Packets from a dump file

## Output
It displays the IP Addresses with method they are trying to access something with HTTP and RAW Data, when RAW Layer is present in the sniffed packet depending upon the inputs provided by the user.