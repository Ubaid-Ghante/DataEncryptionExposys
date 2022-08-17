#! /bin/bash
echo "Installling required pakages"
pip install pycryptodome

python ./gui.py

chmod +r Encrypted\ Message\ and\ Key.txt

python ./gui2.py

