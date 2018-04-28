#!/bin/bash
make -C /usr/src/linux-`uname -r` SUBDIRS=$PWD modules
