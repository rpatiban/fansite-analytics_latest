#!C:/Program Files/Python36/python.exe

# #####################################################################################
# Author : Raghu Patibandla
# Date   : April 4th 2017
# ====================================================================================
# Program to perform basic analytics on the server log file, to provide useful metrics
# 	and to detect the patterns of failed logins
# ====================================================================================
# Inputs : 5 file names are expected in the sequence 
#	  <input log>
#	, <o/p for feature1>
#	, <o/p for feature3>
#	, <o/p for feature2>
#	, <o/p for feature4>
#
# Example :  How to run on Windows OS
# C:\>python src/process_log.py log_input/log.txt log_output/hosts.txt 
#	log_output/hours.txt log_output/resources.txt log_output/blocked.txt
# ====================================================================================
# Please Note: In the given run.sh, the parameters sequence-
#	feature 3 output(hours.txt) before the feature 2 output (resources.txt)
#
# #####################################################################################

import re
import datetime
import sys

# CONSTANTS for Feature 4
# List of HTML response codes that considered as client-side failed attempts
# This list allows to maintain the future changes of codes
LSTHTMLCD = [400,401,402,403,404,405,406,407,408,409,410,411,412,413,414,415, \
			 416,417,418,421,422,423,424,425,426,427,428,429,431,451] 

# Constant for fail attempts limit 
FAIL_ATTEMPTS_ALLOWED = 3

# Constant for fail attempts time limit  (in secs.)
FAIL_ATTEMPTS_DURATION = 20

# Constant for blocking time limit  (in secs.)
BLOCK_DURATION = 300


#Getting starting time
current_time = datetime.datetime.now()
print(current_time)

# Feature 1 - Dictionary to keep the counts of hosts' vists
dictHosts = dict()

# Feature 2 - Dictionary to keep the resources and their bandwidth consumption
dictResources = dict()

# Feature 3 Assumption : All lines in input file are in date and time sequence. 
# This program does not consider any additional sorting of the input
# Feature 3 -Dictionary to keep the access count for a given hour
dictHours = dict()

# Feature 3 - flag to on/off for holding 60 mins time intervals
flgHold = True

# Feature 4 - Dictionaries to keep the count of trails, 
#	failed attempts TS, and the blocked hosts TS
dictFailedAttemptsCnt = dict()
dictFailedAttemptsTimeLimit = dict()
dictBlockedTimeLimit = dict()

# -------------- Program Start ------------------

if (len(sys.argv) != 6) :
	print('ERROR: not enough parameters')
else :
	# Assigning parameters to appropriate variables
	# in case of parameters sequence change - please change it here
	input_log = sys.argv[1]
	feature1_output = sys.argv[2]
	feature2_output = sys.argv[4]
	feature3_output = sys.argv[3]
	feature4_output = sys.argv[5]
	
	try :
	
		# Feature 4 - Output - logs blocked requests
		with open(feature4_output, 'w') as blocked_file:

			# Open/read weblog and process each line for hosts
			with open(input_log,'r') as webLog :
				for logLine in webLog:
					# Preserving the line for Feature 4 log
					line_to_log = logLine

					#Seperate the resrouce path for consistency
					web_resource=re.findall(r'^[^"]*(".*")[^"]*$',logLine)
					logLine = logLine.replace(web_resource[0],'')

					logLine = logLine.split()
					# Get Current host
					currentHost = str(logLine[0])	

					# Get Timestamp from the current line
					strTS = logLine[3].replace('[', '')
					currentTS = datetime.datetime.strptime(strTS, '%d/%b/%Y:%H:%M:%S')

					# ----------- Feature 1 Logic --------
					#counting the host vists into the dict
					if currentHost in dictHosts:		
						dictHosts[currentHost] += 1
					else:
						dictHosts[currentHost] = 1
					# ------------ End of Feature 1 ------

					# ----------- Feature 2 Logic --------
					currentResource = web_resource[0]
					#Remove unnecessary words to keep the resrouce path consistent
					currentResource = currentResource.replace('GET ', '')
					currentResource = currentResource.replace('PUT ', '')
					currentResource = currentResource.replace(' HTTP/1.0', '')
					currentResource = currentResource.replace(' HTTP/V1.0', '')
					currentResource = currentResource.replace('"','')
					
					if (logLine[6].isdigit()) :
						bytesSentover = int(logLine[6])

						#counting the resource bandwidth consumption into the dict
						if currentResource in dictResources:		
							dictResources[currentResource] += bytesSentover
						else:
							dictResources[currentResource] = bytesSentover
					# ------------ End of Feature 2 ------

					# ----------- Feature 3 Logic --------
					if (flgHold is False) :
						if (currentTS <= currentEndTS) :
							# count it in when the current time belongs to the current period
							dictHours[tsWithTZ] += 1	
						else :
							# When current time goes out of current period create a new current period
							flgHold = True

					# Determining Top and bottom of 60 min interval for keeping the count
					if (flgHold is True) :
						currentStartTS = currentTS
						currentEndTS = currentStartTS + datetime.timedelta(hours=1)
						tsWithTZ = strTS + " " + logLine[4].replace(']', '')
						dictHours[tsWithTZ] = 1
						flgHold = False
					# ------------ End of Feature 3 ------

					# ----------- Feature 4 Logic --------
					# Check if the current host is blocked
					if (currentHost in dictBlockedTimeLimit) :
						# BLOCKED HOST
						# Check if  the host is under BLOCKED time limit
						if (currentTS < dictBlockedTimeLimit[currentHost]) :
							# BLOCKING continues and logs the attempt
							blocked_file.write('%s' %line_to_log)
							continue
						else :
							# BLOCKING IS OVER for the host
							try:
								# Reset blocked dictionary for the host
								del dictBlockedTimeLimit[currentHost]
							except KeyError:
								print("ERROR with blocked hosts! please contact your DE")
								print(KeyError)
								pass
					else :
						# The current host is NOT BLOCKED yet
						# Check if the current attempt is a client failure
						currentHTMLCD = int(logLine[5])
						if (currentHTMLCD in LSTHTMLCD) :

							# FAILED ATTEMPT Scenario
							# Check if this is a consecutive failed attempt
							if (currentHost in dictFailedAttemptsCnt) :

								# Failed Attempt (FA) - Consecutive 
								# Check if under FA DURATION 
								if (currentTS < dictFailedAttemptsTimeLimit[currentHost]) :

									# Check if under allowed FA limit
									if (dictFailedAttemptsCnt[currentHost] <= FAIL_ATTEMPTS_ALLOWED) :
										# Increase failed attempts count
										dictFailedAttemptsCnt[currentHost] += 1
									else :
										# It is time for BLOCK the host
										blocked_end_ts = currentTS + datetime.timedelta(seconds=BLOCK_DURATION)
										dictBlockedTimeLimit[currentHost] = blocked_end_ts

										# Reset FA Dictionaries
										try:
											# Reset failed attempts count for the host
											del dictFailedAttemptsCnt[currentHost]

											# Reset failed attempts time limit for the host
											del dictFailedAttemptsTimeLimit[currentHost]

										except KeyError:
											print("ERROR with blocked hosts! please contact your DE")
											print(KeyError)
								else :
									# Reset FA Dictionaries
									try:
										# Reset failed attempts count for the host
										del dictFailedAttemptsCnt[currentHost]

										# Reset failed attempts time limit for the host
										del dictFailedAttemptsTimeLimit[currentHost]

									except KeyError:
										print("ERROR with blocked hosts! please contact your DE")
										print(KeyError)
							else:
								# FIRST FAILED ATTEMPT - Set FA Dictionaries for the host
								dictFailedAttemptsCnt[currentHost] = 1
								fa_end_ts = currentTS + datetime.timedelta(seconds=FAIL_ATTEMPTS_DURATION)
								dictFailedAttemptsTimeLimit[currentHost] = fa_end_ts

						else :
							# SUCCESSFUL ATTEMPT scnario
							try:

								# Reset failed attempts count for the host
								if (currentHost in dictFailedAttemptsCnt) :
									del dictFailedAttemptsCnt[currentHost]

								# Reset failed attempts time limit for the host
								if (currentHost in dictFailedAttemptsTimeLimit) :
									del dictFailedAttemptsTimeLimit[currentHost]

							except KeyError:
								print("ERROR with blocked hosts! please contact your DE")
								print(KeyError)
					# ------------ End of Feature 4 ------



		#-------------------- Output section ----------------
		
		# Feature 1 o/p - Report top 10 hosts to file:
		lineCnt = 0
		with open(feature1_output, 'w') as f:
			for h in sorted(dictHosts, key=dictHosts.get, reverse=True):
				if (lineCnt < 10) : 
					f.write('%s,%d \n' % (h, dictHosts[h]))
					lineCnt+=1
				else:
					break
		# ------------ End of Feature 1 output ------

		# Feature 2 o/p - Report top 10 high bandwidth resources to file:
		lineCnt = 0
		with open(feature2_output, 'w') as f:
			for r in sorted(dictResources, key=dictResources.get, reverse=True):
				if (lineCnt < 10) : 
					f.write('%s \n' % (r))
					lineCnt+=1
				else:
					break
		# ------------ End of Feature 2 output ------

		# Feature 3 o/p - Report top 10 busy hours to file:
		lineCnt = 0
		with open(feature3_output, 'w') as f:
			for hr in sorted(dictHours, key=dictHours.get, reverse=True):
				if (lineCnt < 10) : 
					f.write('%s,%d \n' % (hr, dictHours[hr]))
					lineCnt+=1
				else:
					break
		# ------------ End of Feature 3 output ------

		#---------------- END of Output section --------------


	# Exception handling
	except:
		e=sys.exc_info()
		print('ERROR: something went wrong ')
		print(e)


#Getting Ending time
current_time = datetime.datetime.now()
print(current_time)
