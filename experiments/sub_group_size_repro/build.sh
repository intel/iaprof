#!/bin/bash

icpx nsg.cpp -fsycl -o nsg.exe
icpx nsg.cpp -fsycl -g -o nsg_g.exe

icpx sg.cpp -fsycl -o sg.exe
icpx sg.cpp -fsycl -g -O0 -o sg_g.exe
