#!/bin/sh

openssl des3 -d -salt -in file.des3 -out file.txt -k supersecretpassword123
