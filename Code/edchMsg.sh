#! /bin/bash
echo "Installling required pakages"
pip install pycryptodome

python ./AES_256_encryption.py

printf "Your message has been encrypted. Here is your\n\t\tKey\n\t\tCiphertext\n\t\tNonce\n\t\tAuthentication Tag\n respectively\n"
chmod +r Encrypted\ Message\ and\ Key.txt
cat Encrypted\ Message\ and\ Key.txt

printf "\nSending encrypted file to localhost for demonstration\nThe localhost is on port 1025\n"

python -m smtpd -c DebuggingServer -n localhost:1025 &

python ./sender.py

echo "Decrypting the recived data...."
python ./AES_256_decryption.py

echo "Your message is.."
cat Output.txt