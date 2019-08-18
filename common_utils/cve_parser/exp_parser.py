#!/usr/bin/env python
#encoding=utf8

import os
import sys
import pdb
path = os.path.abspath(os.path.dirname(os.path.abspath(__file__)) + '/../../')
sys.path.append(path)

import requests
from bs4 import BeautifulSoup
from common_utils.database import DB_CVE


class EXP_Parser:
	def __init__(self):
#		self.baseurl = 'http://cve.mitre.org/data/refs/refmap/source-EXPLOIT-DB.html'
#		self.files_url = 'https://raw.githubusercontent.com/offensive-security/exploit-database/master/files_exploits.csv'
		self.res_path = os.path.dirname(os.path.abspath(__file__)) + '/../../res/exp/'
		self.html = ''
		self.output = {}

		self.db = DB_CVE()

		self.id_from_files = set()
		self.count_ok = 0
		self.count_bad = 0


	def run(self):
		self.get_html()
		self.parse_html()
		self.parse_csv()
		self.dump_to_db()

	def parse_csv(self):
		csv_file = open(self.res_path + 'files_exploits.csv').read()
		for line in csv_file.splitlines():
			self.id_from_files.add(line.split(',')[0])

	def dump_to_db(self):
		sys.stdout.write("Starting to dump to Database...   ")
		sys.stdout.flush()

		for exp_id in self.output:
#			pdb.set_trace()
			if str(exp_id) in self.id_from_files:
				self.count_ok += 1
				cve_ids = self.output[exp_id]
				for cve_id in cve_ids:
					self.db.update_exp(cve_id=cve_id, exp_id=exp_id, commit=False)
			else:
				self.count_bad += 1
		self.db.commit()

		print "Done! Good:", self.count_ok, "  Bad:", self.count_bad

	def parse_html(self):
		sys.stdout.write("Starting to parse the html...   ")
		sys.stdout.flush()

		html = self.html[self.html.find('<!--begin Main Content-->'):self.html.find('<!--end Main Content-->')]
		soup = BeautifulSoup(html, 'lxml')
		soup = soup.find_all('table')[1]

		for row in soup.find_all('tr'):
			cols = row.find_all('td')
			exp_id = cols[0].string.strip('EXPLOIT-DB:')
			exp_id = int(exp_id)
			cve_id = []
			for a_tag in cols[1].find_all('a'):
				tmp = str(a_tag.string)
				cve_id.append(tmp)
			self.output[exp_id] = cve_id
		print "Done!"

	def get_html(self):
#		sys.stdout.write("Starting to fetch the html: (%s)...   " % self.baseurl)
#		sys.stdout.flush()

		# Method1: Read the downloaded html file
		self.html = open(self.res_path + 'source-EXPLOIT-DB.html').read()

		# # Method2: download it directly here...
		# http = requests.get(self.baseurl)
		# if http.status_code != 200:
		# 	raise RuntimeError("http:" + str(http.status_code))
		# else:
		# 	self.html = http.text

		print "Done!"


if __name__ == '__main__':
	exp = EXP_Parser()
	exp.run()

	print "\nGoing to delete useless exploit-db entries...\n"
	del exp
