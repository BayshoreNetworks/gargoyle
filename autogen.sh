#!/bin/sh

echo "Generating configure files... may take a while."

autoreconf --install --force && \
echo "Preparing was successful if no error messages were displayed above."

