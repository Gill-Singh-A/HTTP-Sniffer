# HTTP Sniffer
A Python Program that sniffs HTTP Packets and displays useful information on the screen.

## Requirements
Language Used = Python3<br />
Modules/Packages used:
* sys
* scapy
* datetime
* optparse
* colorama
* time

## Input
It takes the Interface on which sniffing has to be done from the command that is used to run the Python Program.<br />
If no Interface is provided, then it uses the default Interface.

## Output
It displays the IP Addresses with method they are trying to access something with HTTP.<br />
It also displays RAW Data, when RAW Layer is present in the sniffed packet.