#!/bin/bash
# Compiles main.py to a binary file.

pip3 install pyinstaller
pyinstaller --onefile Scrummage.py
mv dist/Scrummage Scrummage
rm -r dist
rm -r build
rm Scrummage.spec
