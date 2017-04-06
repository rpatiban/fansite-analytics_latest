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
reqested_hosts = dict()

# Feature 2 - Dictionary to keep the resources and their bandwidth consumption
web_resources = dict()

# Feature 3 Assumption : All lines in input file are in date and time sequence. 
# This program does not consider any additional sorting of the input
# All log entries in a 60 min duration are considered them as they belong to a specific hour
# Please note: each line is not considered as a starting point of a new 60 min durtation
# Feature 3 -Dictionary to keep the access count for a given hour
busy_hours = dict()

# Feature 3 - flag to on/off for holding 60 mins time intervals
flag_hold = True

# Feature 4 - Dictionaries to keep the count of trails, 
#	failed attempts TS, and the blocked hosts TS
failed_attempts_allowed_cnt = dict()
failed_attempts_time_limit = dict()
blocked_time_limit = dict()

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
				for line_from_log in webLog:
					# Preserving the line for Feature 4 log
					line_to_log = line_from_log

					#Seperate the resrouce path for consistency
					web_resource=re.findall(r'^[^"]*(".*")[^"]*$',line_from_log)
					line_from_log = line_from_log.replace(web_resource[0],'')

					line_from_log = line_from_log.split()
					# Get Current host
					current_host = str(line_from_log[0])	

					# Get Timestamp from the current line
					string_ts = line_from_log[3].replace('[', '')
					current_ts = datetime.datetime.strptime(string_ts, '%d/%b/%Y:%H:%M:%S')

					# ----------- Feature 1 Logic --------
					#counting the host vists into the dict
					if current_host in reqested_hosts:		
						reqested_hosts[current_host] += 1
					else:
						reqested_hosts[current_host] = 1
					# ------------ End of Feature 1 ------

					# ----------- Feature 2 Logic --------
					current_web_resource = web_resource[0]
					#Remove unnecessary words to keep the resrouce path consistent
					current_web_resource = current_web_resource.replace('GET ', '')
					current_web_resource = current_web_resource.replace('POST ', '')
					current_web_resource = current_web_resource.replace(' HTTP/1.0', '')
					current_web_resource = current_web_resource.replace(' HTTP/V1.0', '')
					current_web_resource = current_web_resource.replace('"','')
					
					if (line_from_log[6].isdigit()) :
						bytesSentover = int(line_from_log[6])

						#counting the resource bandwidth consumption into the dict
						if current_web_resource in web_resources:		
							web_resources[current_web_resource] += bytesSentover
						else:
							web_resources[current_web_resource] = bytesSentover
					# ------------ End of Feature 2 ------

					# ----------- Feature 3 Logic --------
					if (flag_hold is False) :
						if (current_ts <= current_end_ts) :
							# count it in when the current time belongs to the current period
							busy_hours[ts_with_tz] += 1	
						else :
							# When current time goes out of current period create a new current period
							flag_hold = True

					# Determining Top and bottom of 60 min interval for keeping the count
					if (flag_hold is True) :
						current_start_ts = current_ts
						current_end_ts = current_start_ts + datetime.timedelta(hours=1)
						ts_with_tz = string_ts + " " + line_from_log[4].replace(']', '')
						busy_hours[ts_with_tz] = 1
						flag_hold = False
					# ------------ End of Feature 3 ------

					# ----------- Feature 4 Logic --------
					# Check if the current host is blocked
					if (current_host in blocked_time_limit) :
						# BLOCKED HOST
						# Check if  the host is under BLOCKED time limit
						if (current_ts < blocked_time_limit[current_host]) :
							# BLOCKING continues and logs the attempt
							blocked_file.write('%s' %line_to_log)
							continue
						else :
							# BLOCKING IS OVER for the host
							try:
								# Reset blocked dictionary for the host
								del blocked_time_limit[current_host]
							except KeyError:
								print("ERROR with blocked hosts! please contact your DE")
								print(KeyError)
								pass
					else :
						# The current host is NOT BLOCKED yet
						# Check if the current attempt is a client failure
						current_html_res_cd = int(line_from_log[5])
						if (current_html_res_cd in LSTHTMLCD) :

							# FAILED ATTEMPT Scenario
							# Check if this is a consecutive failed attempt
							if (current_host in failed_attempts_allowed_cnt) :

								# Failed Attempt (FA) - Consecutive 
								# Check if under FA DURATION 
								if (current_ts < failed_attempts_time_limit[current_host]) :

									# Check if under allowed FA limit
									if (failed_attempts_allowed_cnt[current_host] < (FAIL_ATTEMPTS_ALLOWED-1)) :
										# Increase failed attempts count
										failed_attempts_allowed_cnt[current_host] += 1
									else :
										# It is time for BLOCK the host
										blocked_end_ts = current_ts + datetime.timedelta(seconds=BLOCK_DURATION)
										blocked_time_limit[current_host] = blocked_end_ts

										# Reset FA Dictionaries
										try:
											# Reset failed attempts count for the host
											del failed_attempts_allowed_cnt[current_host]

											# Reset failed attempts time limit for the host
											del failed_attempts_time_limit[current_host]

										except KeyError:
											print("ERROR with blocked hosts! please contact your DE")
											print(KeyError)
								else :
									# Reset FA Dictionaries
									try:
										# Reset failed attempts count for the host
										del failed_attempts_allowed_cnt[current_host]

										# Reset failed attempts time limit for the host
										del failed_attempts_time_limit[current_host]

									except KeyError:
										print("ERROR with blocked hosts! please contact your DE")
										print(KeyError)
							else:
								# FIRST FAILED ATTEMPT - Set FA Dictionaries for the host
								failed_attempts_allowed_cnt[current_host] = 1
								fa_end_ts = current_ts + datetime.timedelta(seconds=FAIL_ATTEMPTS_DURATION)
								failed_attempts_time_limit[current_host] = fa_end_ts

						else :
							# SUCCESSFUL ATTEMPT scnario
							try:

								# Reset failed attempts count for the host
								if (current_host in failed_attempts_allowed_cnt) :
									del failed_attempts_allowed_cnt[current_host]

								# Reset failed attempts time limit for the host
								if (current_host in failed_attempts_time_limit) :
									del failed_attempts_time_limit[current_host]

							except KeyError:
								print("ERROR with blocked hosts! please contact your DE")
								print(KeyError)
					# ------------ End of Feature 4 ------



		#-------------------- Output section ----------------
		
		# Feature 1 o/p - Report top 10 hosts to file:
		line_cnt = 0
		with open(feature1_output, 'w') as f:
			for h in sorted(reqested_hosts, key=reqested_hosts.get, reverse=True):
				if (line_cnt < 10) : 
					f.write('%s,%d \n' % (h, reqested_hosts[h]))
					line_cnt+=1
				else:
					break
		# ------------ End of Feature 1 output ------

		# Feature 2 o/p - Report top 10 high bandwidth resources to file:
		line_cnt = 0
		with open(feature2_output, 'w') as f:
			for r in sorted(web_resources, key=web_resources.get, reverse=True):
				if (line_cnt < 10) : 
					f.write('%s \n' % (r))
					line_cnt+=1
				else:
					break
		# ------------ End of Feature 2 output ------

		# Feature 3 o/p - Report top 10 busy hours to file:
		line_cnt = 0
		with open(feature3_output, 'w') as f:
			for hr in sorted(busy_hours, key=busy_hours.get, reverse=True):
				if (line_cnt < 10) : 
					f.write('%s,%d \n' % (hr, busy_hours[hr]))
					line_cnt+=1
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
