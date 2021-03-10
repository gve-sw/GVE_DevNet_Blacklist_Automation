"""
Copyright (c) 2020 Cisco and/or its affiliates.

This software is licensed to you under the terms of the Cisco Sample
Code License, Version 1.1 (the "License"). You may obtain a copy of the
License at

               https://developer.cisco.com/docs/licenses

All use of the material herein must be in accordance with the terms of
the License. All rights not expressly granted by the License are
reserved. Unless required by applicable law or agreed to separately in
writing, software distributed under the License is distributed on an "AS
IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
or implied.
"""
import os
import requests
import urllib3
import schedule
import time
from netmiko import Netmiko
from src.db import get_db

urllib3.disable_warnings()
BLACKLIST_PATH = 'src/Blacklists'
INTELLIGENCE_URL = 'https://www.talosintelligence.com/documents/ip-blacklist'


def automatedBehaviour(app, user_id, automated_Blacklist):
	with app.app_context():
		print('STARTING AUTOMATED BLACKLIST UPDATE')
		# Task Setup
		intelligence_File_Name = "{}/Talos_Intelligence_Feed.txt".format(BLACKLIST_PATH)
		blacklist_File_Name = "{}/{}".format(BLACKLIST_PATH, automated_Blacklist)
		temp = automated_Blacklist.split('.')
		acl_Name = temp[0]
		task_Time = time.strftime("%a, %d %b %Y %H:%M:%S +0000", time.localtime())
		db = get_db()
		acl_Build_Commands = [
			'ip access-list standard {}'.format(acl_Name)
		]

		# Retrieve Talos Intelligence
		response = requests.request("GET", INTELLIGENCE_URL, verify=False)
		print("Intelligence received, scanning...")
		intelligence_File = open(intelligence_File_Name, "w")
		intelligence_File.write(response.text)
		intelligence_File.close()
		print("Talos Sync completed!")

		# Compare Talos Intelligence to selected List
		with open(intelligence_File_Name, 'r') as feed:
			with open(blacklist_File_Name, 'r') as existing:
				updates = set(feed).difference(existing)
		updates.discard('\n')

		# If changes are needed
		if len(updates) > 0:
			task_Type = 'Update(s) Found'
			task_Description = '{} has {} updates from Talos!'.format(acl_Name, len(updates))

			for update in updates:
				acl_Build_Commands.append('deny {}'.format(update))

			print("Applying Updates")
			router_List = db.execute(
				'SELECT rl.id, host, sshusername, sshpassword'
				' FROM routerdb rl JOIN user u ON rl.user_id = u.id'
				' ORDER BY host DESC'
			).fetchall()

			# Define Command
			for router in router_List:
				router_info = {
					"device_type": "cisco_xe",
					"ip": router['host'],
					"username": router['sshusername'],
					"password": router['sshpassword'],
					"port": "22"
				}
				net_connect = Netmiko(**router_info)
				net_connect.send_config_set(acl_Build_Commands)
				net_connect.disconnect()

			blacklist_File = open(blacklist_File_Name, "w")
			blacklist_File.write(response.text)
			blacklist_File.close()

		else:
			task_Type = 'Check'
			task_Description= 'No updates from Talos'

		print("Storing Task in DB")
		# Commit task to DB
		db.execute(
			'INSERT INTO tasklog (user_id, task_time, url_list, type, description) VALUES (?, ?, ?, ?, ?)',
			(user_id, task_Time, automated_Blacklist, task_Type, task_Description)
		)
		db.commit()
		print('Job Completed')
		print('------------------------------\n')


def startAutomatedTask(app, user_id, automated_Blacklist):
	"""

	:param app:
	:param user_id:
	:param automated_Blacklist:
	:return:
	"""
	print('Clearing existing task schedule')
	schedule.clear()
	print('Scheduling new task for {}'.format(automated_Blacklist))
	schedule.every(1).minute.do(automatedBehaviour, app=app, user_id=user_id, automated_Blacklist=automated_Blacklist)
	print('Job Scheduled!')

	while True:
		schedule.run_pending()
		time.sleep(10)
