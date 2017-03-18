#!/bin/sh

#wget "http://software77.net/cgi-bin/ip-country/geo-ip.pl?action=download" -O IPtoCountry.csv.gz
wget "http://software77.net/geo-ip?DL=1" -O IPtoCountry.csv.gz
gunzip IPtoCountry.csv.gz
