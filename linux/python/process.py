#!/usr/bin/env python
import subprocess
import time 


child = subprocess.Popen(["/usr/bin/python","./while","-l"],stdout=subprocess.PIPE)

print "subprocess runing"
#out = child.communicate()

print child.pid
while True:
	retcode = child.poll()
	if retcode == None:
		print 'alive'
	else:
		print 'turn out'
	time.sleep(3)
