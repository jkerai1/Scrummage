#!/bin/bash
# Compiles main.py to a binary file.

pip3 install pyinstaller
pyinstaller --onefile main.py
mv dist/main main
rm -r dist
rm -r build
rm main.spec
