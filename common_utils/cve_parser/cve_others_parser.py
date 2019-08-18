#!/usr/bin/env python
#encoding=utf8

import re
import os
import sys
path = os.path.abspath(os.path.dirname(os.path.abspath(__file__)) + '/../../')
sys.path.append(path)

from common_utils.database import DB_CVE, DB_third_party_soft_cve


class CVE_Parser2:
	def __init__(self):
		self.db_third = DB_third_party_soft_cve(init=True)
		self.db_cve = DB_CVE()

	def dump_to_db(self, package, result):
		self.db_third.clear(package)
		_result = []
		for i in result:
			# deduplicate the entries...
			if i not in _result:
				_result.append(i)
				# Insert the data first, and then call commit() to write the transaction.
				# This will faster the process quite a lot
				self.db_third.insert(package=package, affected_ver=i[1], cveid=i[0], commit=False)
		self.db_third.commit()
		return len(_result)

	def parse(self, package, search, reg):
		data = []
		rows = self.db_cve.get_by_cpe(search)
		for row in rows:
			cveid = row[0]
			cpe = row[10].split('||')
			for _cpe in cpe:

				# First, we use str.find() to skip some cpe, cause re.search() just runs too slowly...
				if _cpe.find(search) == -1:
					continue
				res = re.search(reg, _cpe)
				if res is not None:
					affected_ver = res.group(2)
					data.append([cveid, affected_ver])
				else:
					print 'Failed search....', _cpe , ' in CVE:', cveid
		return self.dump_to_db(package, result=data)


if __name__ == '__main__':
	parser = CVE_Parser2()

	# PHP
	print 'Parsing PHP...   Count:',
	print parser.parse(package='php', search='cpe:/a:php:php:', reg=r'(php:php:)([\d\.]+)')

	# Mysql
	print 'Parsing MySQL...   Count:',
#	print parser.parse(package='mysql', search='cpe:/a:oracle:mysql:', reg=r'(oracle:mysql:)([\d\.]+)')
	print parser.parse(package='mysqld', search='cpe:/a:oracle:mysql:', reg=r'(oracle:mysql:)([\d\.]+)')

	# Apache
	print 'Parsing Apache...   Count:',
#	print parser.parse(package='apache', search='cpe:/a:apache:http_server:', reg=r'(apache:http_server:)([\d\.]+)')
	print parser.parse(package='httpd', search='cpe:/a:apache:http_server:', reg=r'(apache:http_server:)([\d\.]+)')

	# Nginx
	print 'Parsing Nginx...   Count:',
	print parser.parse(package='nginx', search='cpe:/a:nginx:nginx:', reg=r'(nginx:nginx:)([\d\.]+)')

	# java
	print 'Parsing Java JDK...   Count:',
	print parser.parse(package='java', search='cpe:/a:oracle:jdk:', reg=r'(oracle:jdk:)([\d\.]+.*)')

	# tomcat
	print 'Parsing tomcat...   Count:',
	print parser.parse(package='tomcat', search='cpe:/a:apache:tomcat:', reg=r'(apache:tomcat:)([\d\.]+)')

	# docker
	print 'Parsing docker...   Count:',
	print parser.parse(package='docker', search='cpe:/a:docker:docker:', reg=r'(docker:docker:)([\d\.]+)')

	# nodejs
	print 'Parsing nodejs...   Count:',
#	print parser.parse(package='nodejs', search='cpe:/a:nodejs:node.js:', reg=r'(nodejs:node\.js:)([\d\.]+)')
	print parser.parse(package='node', search='cpe:/a:nodejs:node.js:', reg=r'(nodejs:node\.js:)([\d\.]+)')
