#!/bin/sh

libtoolize --force && \
aclocal && \
autoheader && \
automake --foreign --add-missing && \
autoconf
