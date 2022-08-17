#!/usr/bin/python

import smtplib

sender = 'from@fromdomain.com'
receivers = ['to@todomain.com']

filehandle = open("Encrypted Message and Key.txt", "r")
message = """From: From Person <from@fromdomain.com>
To: To Person <to@todomain.com>
Subject: Your encrypted message:

""" + filehandle.read()

try:
   smtpObj = smtplib.SMTP('localhost:1025')
   smtpObj.sendmail(sender, receivers, message)         
   print ("Successfully sent email")
except smtplib.SMTPException:
   print ("Error: unable to send email")