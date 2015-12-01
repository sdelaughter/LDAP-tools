"""Last Updated 12/1/15
Written by Samuel DeLaughter

"""

__version__ = "1.6.1"

import logging
import sys
import time
import string
import random
import ldap
import base64, hashlib, os	#For generating ssha passwords
from pprint import pprint	#For printing dictionaries
from getpass import getpass	#For prompting for passwords
from datetime import datetime


def seconds_since_epoch():
	"""Return the number of seconds since the epoch (1/1/70)
	
	Parameters
	----------
	None
		
	Returns
	-------
	seconds : int
		The number of seconds since the epoch
	
	"""
	seconds = int(time.time())
	return seconds


def days_since_epoch():
	"""Return the integer number of days since the epoch (1/1/70)
	
	Parameters
	----------
	None
		
	Returns
	-------
	days : int
		The number of days since the epoch
	
	"""
	seconds = time.time()
	days = int(seconds / 86400)
	return days
	

def days_to_pwd_expiration(sambaPwdMustChange):
	"""Determine number of days remaining until a user's password will expire
	
	Parameters
	----------
	sambaPwdMustChange : string
		The sambaPwdMustChange value from a user's LDAP account
	
	Returns
	-------
	days_to_expiration : int
	
	"""
	change_day = ((float(sambaPwdMustChange)) / 86400.0)
	today = days_since_epoch()
	days_to_expiration = (change_day - today)
	return days_to_expiration
	
	
def generate_pwd(length=8):
	"""Generate a random password for a new user
	
	Parameters
	----------
	(optional) length : int
		The number of characters for the new password, 8 by default
	
	Returns
	-------
	pwd : string
		A random alphanumeric string
	
	"""
	chars = (string.ascii_uppercase + string.ascii_lowercase + string.digits)
	pwd = ''.join(random.choice(chars) for _ in range(length))
	return pwd
	
	
def generate_ssha(pwd):
	"""Generate a SSHA version of a password
	
	Parameters
	----------
	pwd : string
		An alphanumeric string, can be generated randomly by generate_pwd()
		
	Returs
	------
	ssha : string
		A base-64 encoded SSHA version of the password
	
	"""
	salt = os.urandom(len(pwd))
	ssha = '{SSHA}' + base64.b64encode(hashlib.sha1(pwd + salt).digest() + salt)
	return ssha
	
	
def generate_sambaNTPassword(pwd):
	"""Generate a Samba NT version of a password
	
	Parameters
	----------
	pwd: string
		An alphanumeric string, can be generated randomly by generate_pwd()
		
	Returs
	------
	sambaNTPassword : string
		A Samba NT encoded version of the password
	
	"""
	nt_password = hashlib.new('md4', pwd.encode('utf-16le')).digest().encode('hex').upper( )
	return nt_password
	
	
def initialize(server='ldapi://'):
	"""Initializes a connection to an LDAP server, using the local server by default
	Connection must bind with login() before performing non-anonymous operations 
		
	Parameters
	----------
	(optional) server : string
		The address of the LDAP server to connect to
		Uses the local server by default
	
	Returns
	-------
	con : LDAPObject
	
	"""
	con = ldap.initialize(server)
	return con
	
	
def login(con, base_dn='ou=people,dc=org', max_attempts=3):
	"""Prompts for a dn and password, and uses them to bind to LDAP.
	Uses anonymous authentication if no username is entered.
	Forces a sys.exit() after some number of unsuccessful login attempts.
	
	Parameters
	----------
	con : LDAPObject
		Create with initialize()
	(optional) base_dn : string
		The base dn for LDAP user accounts
		You should change the default value to match your orginization's own base dn
	(optional) max_attempts : int
		The maximum number of failed login attempts before sys.exit() is forced, 3 by default
		
	"""
	print('')
	print(' ______________________________________________________________________________ ')
	print('|                                                                              |')
	print('| - For anonymous authentication, just press enter                             |')
	print('| - For admin or special account authentication, enter the full bind dn        |')
	print('| - For regular accounts in ou=people, you can simply enter your LDAP username |')
	print('|______________________________________________________________________________|')
	
	attempts = 0
	while attempts < max_attempts:
		username = str(raw_input('\nEnter LDAP username or dn: '))
		if username == '':
			print('Logged in anonymously')
			return
		else:
			if('=' not in username):
				dn = ('uid=' + str(username) + ',' + str(base_dn))
			else:
				dn = username
			print('dn: ' + str(dn))
			passwd = getpass('Enter LDAP password for ' + str(username) + ': ')
			try:
				con.simple_bind_s(dn, passwd)
				logging.info('Successful login as ' + str(dn))
				return
			except ldap.LDAPError, e:
				logging.warning('Unsuccessful login attempt as ' + str(dn))
				sys.stderr.write("Fatal Error.n")
				if type(e.message) == dict:
					for (k, v) in e.message.iteritems():
						sys.stderr.write("%s: %s \n" % (k, v))
				else:
					sys.stderr.write("Error: %s \n" % e.message)
				attempts += 1
				remaining_attempts = max_attempts - attempts
				if remaining_attempts is 1:
					print('\nYou have 1 login attempt remaining')
					print('Python will exit if this attempt fails')
				else:
					print('\nYou have ' + str(remaining_attempts) + ' login attempts remaining')
				
	else:
		logging.warning('Excessive failed logins as ' + str(dn))
		logging.warning('Forcing python exit for excessing failed logins')
		print("You have exceeded the maximum number of login attempts")
		print("Python will now exit")
		sys.exit()
		

def ldapsearch(con, identifier, attrs=[], base_dn='dc=org'):
	"""Returns the results of an ldapsearch.
	
	Parameters
	----------
	con : LDAPObject
		Create with initialize()
	identifier : string
		The value to search on (eg. 'objectClass=posixAccount')
	(optional) attrs : list
		The attributes to return, each one must be formatted as a string
	(optional) base_dn : string
		The base dn to search on
		You should change the default value to match your orginization's own base dn
	
	Returns
	-------
	result : list
		Each item in the list is a separate record in tuple form
		The first item of the tuple is the dn (string)
		The second item of the tuple is a dict of attributes and their values
	
	Examples
	--------
	>>> con=initialize()
	>>> identifier='uid=jschmoe'
	>>> attrs=['uid', 'uidNumber', 'employeeType']
	>>> result=ldapsearch(con, identifier, attrs)
	>>> result
	[('uid=jschmoe,ou=people,dc=org', {'employeeType': ['Staff'], 'uidNumber': ['16000'], 'uid': ['jschmoe']})]
	 
	
	"""
	result = con.search_s(base_dn, ldap.SCOPE_SUBTREE, identifier, attrs)
	return result


def ldapadd(con, dn, record):
	"""Adds a record to LDAP
	
	Parameters
	----------
	con : LDAPobject
		Create with initialize()
	dn : string
		The LDAP dn of the entry to be created
	record : list
		Each list item is a tuple corresponding to a single attribute
		The first item in the tuple is the attribute name
		The second item in the tuple is a list of the corresponding values
		
	Returns
	-------
	None
	
	Examples
	--------
	>>>con=initialize()
	>>>dn='uid=jschmoe,ou=people,dc=org'
	>>>record=[]
	>>>record.append(('uid', ['jschmoe']))
	>>>record.append(('displayName', ['Joe Schmoe']))
	>>>record.append(('givenName', ['Joe', 'Joseph']))
	>>>record.append(('surname', ['Schmoe']))
	>>>ldapadd(con, dn, record)
	
	This will create the following LDIF:
	dn: uid=jschmoe,ou=people,dc=org
	uid: jschmoe
	displayName: Joe Schmoe
	givenName: Joe
	givenName: Joseph
	surname: Schmoe
	
	"""	
	con.add_s(dn, record)	
	
	
def replace_attribute(con, dn, attr, values):
	"""Replace the value(s) assigned to an arribute in an LDAP record
	The attribute will be added to the record if not already present
	
	Parameters
	----------
	con : LDAPObject
		Create with initialize()
	dn : string
		The dn of the LDAP record to be modified
	attr : string
		The name of the attribute to modify
	values : list
		A list of the new values to associate with the attribute
		
	Returns
	-------
	None
	
	"""
	modattrs = [((ldap.MOD_REPLACE, attr, values))]
	con.modify_s(dn, modattrs)


def next_available_uid(con):
	"""Determine the next available uidNumber in the LDAP database
	Somewhat slow since it must check every single user account
	
	Parameters
	----------
	con : LDAPObject
		Create with initialize()
	
	Returns
	-------
	uid : string
		A string version of the next available UID number
	
	"""
	existing_uidNumbers = []
	identifier = 'uidNumber=*'
	attrs = ['uidNumber']
	result = ldapsearch(con, identifier, attrs)
	for i in result:
		uids = i[1]['uidNumber']
		if type(uids) is list:
			for n in uids:
				existing_uidNumbers.append(int(n))
		else:
			existing_uidNumbers.append(int(uids))
	uid = str((max(existing_uidNumbers)) + 1)
	return uid


def next_available_sid(con, prefix='S-1-5-21-4000000000-1200000000-4000000000-'):
	"""Determine the next available sambaSID number in the LDAP database
	Somewhat slow since it must check every single account with a sambaSID
	
	Parameters
	----------
	con : LDAPObject
		Create with initialize()
	(optional) prefix : string
		The SID prefix
		You should change the default value to match your orginization's own SID prefix
	
	Returns
	-------
	sid : string
		A string version of the next available sambaSID number
	
	"""
	
	num_hyphens=prefix.count('-')
	existing_sidNumbers = []
	identifier = 'sambaSID=*'
	attrs = ['sambaSID']
	result = ldapsearch(con, identifier, attrs)
	for i in result:
		sids = i[1]['sambaSID']
		if type(sids) is list:
			for n in sids:
				n = (n.split('-'))
				if len(n) is (num_hyphens+1):
					existing_sidNumbers.append(int(n[num_hyphens]))
		else:
			sids = (sids.split('-'))
			if len(sids) is (num_hyphens+1):
				existing_sidNumbers.append(int(sids[num_hyphens]))
	next_available = ((max(existing_sidNumbers)) + 1)
	sid = (str(prefix) + str(next_available))
	return sid


def next_available_gid(con):
	"""Determine the next available gidNumber in the LDAP database
	Somewhat slow since it must check every single posixGroup account
	
	Parameters
	----------
	con : LDAPObject
		Create with initialize()
	
	Returns
	-------
	gid : string
		A string version of the next available gidNumber
	
	"""
	existing = []
	identifier = 'objectClass=posixGroup'
	attrs = ['gidNumber']
	result = ldapsearch(con, identifier, attrs)
	for i in result:
		gid = i[1]['gidNumber']
		if type(gid) is list:
			for n in gid:
				existing.append(int(n))
		else:
			existing.append(int(gid))
	next_available = ((max(existing)) + 1)
	return str(next_available)


def increment_uid(uid):
	"""Increment a UID or GID number
	Cast from string to int, add one, cast back to string
	Faster than rerunning next_available_uid() or next_available_gid()
	
	Parameters
	----------
	uid : string
		Generally the UID/GID number that was just assigned to a user/group
	
	Returns
	-------
	new : string
		The incremented uid/gid number
		Generally the new next-avialable uid/gid number
	
	"""
	new = str(int(uid) + 1)
	return new
	

def increment_sid(sid, prefix='S-1-5-21-4000000000-1200000000-4000000000-'):
	"""Increment an SID number
	Faster than rerunning next_available_sid()
	
	Parameters
	----------
	sid : string
		Generally the SID number that was just assigned to a user
	
	Returns
	-------
	new : string
		The incremented SID number
		Generally the new next-avialable SID number
	
	"""
	current = sid.split(str(prefix))[1]
	new = ((int(current)) + 1)
	new = (str(prefix) + str(new))
	return new


def handle_long_values(lines):
	"""Recombine any fields that have spilled across multiple lines
	Mainly intended for use when reading an LDIF file
	Works by checking for a leading space on each line
	If found, that line will be added to the preceding one
	
	Parameters
	----------
	lines : list
		A list of each line read from a file
		
	Returns
	-------
	lines : list
		An amended list of the lines read from the file
	
	"""
	for line in range(len(lines)):
		if lines[line].startswith(' '):
			lines[line - 1].append(line.split(' ')[1])
			del lines[line]
	return lines


def file_to_lines(f):
	"""Convert a text or LDIF file into a list of lines
	
	Parameters
	----------
	f : string
		The location of a file to read
	
	Returns
	-------
	lines : list
		A list of the lines read from the file
	
	"""
	lines = []
	for line in f:
		line = line.strip()
		lines.append(line)
	lines = handle_long_values(lines)
	return lines
	
	
def check_for_existing_group(con, cn):
	"""Search LDAP to see if a group cn exists already
	
	Parameters
	----------
	con : LDAPObject
		Create with intialize()
	cn : string
		The cn of a group to search for
		
	Returns
	-------
	0 if no existing group is found
	1 if an existing group is found
	
	"""
	attrs = []
	identifier = ('cn=' + str(cn))
	#Search for the group in LDAP
	try:
		a = ldapsearch(con, identifier, attrs)
		if len(a) != 0:
			return 1
		else:
			return 0
	except:
		logging.warning('WARNING: ldapsearch error in check_for_existing_group() for group cn=' + str(cn))
		print('WARNING: ldapsearch error in check_for_existing_group() for group cn=' + str(cn))
		return 0


def get_group_members(con, cn):
	"""Get the members of an LDAP group
	
	Parameters
	----------
	con : LDAPObject
		Create with intialize()
	cn : string
		The cn of a group
	
	Examples
	--------
	>>> con=initialize()
	>>> cn='itadmins'
	>>> members=get_group_members(con, cn)
	>>> members
	['rtrenneman', 'mmoss', 'jbarber']
	
	"""
	attrs = ['memberUid']
	identifier = ('cn=' + str(cn))
	#Search for the group in LDAP
	try:
		a=ldapsearch(con, identifier, attrs)
		if(len(a) == 1):
		#If the cn matches a single LDAP entity, return a list of its members
			members = a[0][1]['memberUid']
		elif(len(a) == 0):
		#If the group has no members return an empty list
			members = []
		else:
		#Just in case the group cn returns more than one LDAP entity
			members = []
			for r in a:
				for m in a[0][1]['memberUid']:
					members.append(m)
	except:
	#If there's an error in ldapsearch, print a warning and return an empty list
		logging.warning('WARNING: ldapsearch error in get_group_members() for group cn=' + str(cn))
		print('WARNING: ldapsearch error in get_group_members() for group cn=' + str(cn))
		members = []
	return members


def get_group_of_groups_members(con, cn):
	"""Get the members of a group of groups
	
	Parameters
	----------
	con : LDAPObject
		Create with intialize()
	cn : string
		The cn of a parent group
	
	Examples
	--------
	>>> con=initialize()
	>>> cn='itadmins'
	>>> members=get_group_members(con, cn)
	>>> members
	['rtrenneman', 'mmoss', 'jbarber']
	
	"""
	attrs = ['member']
	identifier = ('cn=' + str(cn))
	#Search for the group in LDAP
	try:
		a=ldapsearch(con, identifier, attrs)
		if(len(a) == 1):
		#If the cn matches a single LDAP entity, return a list of its members
			if('member' in a[0][1]):
				members = a[0][1]['member']
			else:
			#If this is a new group, it won't have a member field yet, so return an empty list
				members = []
		elif(len(a) == 0):
		#If the group has no members return an empty list
			members = []
		else:
		#Just in case the group cn returns more than one LDAP entity
			members = []
			for r in a:
				if('member' in a[0][1]):
					for m in a[0][1]['member']:
						members.append(m)
	except:
	#If there's an error in ldapsearch, print a warning and return an empty list
		logging.warning('WARNING: ldapsearch error in get_parent_group_members() for course cn=' + str(cn))
		print('WARNING: ldapsearch error in get_parent_group_members() for course cn=' + str(cn))
		print a
		members = []
	return members
	
	
def update_group_of_groups_membership(con, parent_cn, cn, base_dn='ou=groups,dc=org'):
	"""Update the membership of a group of groups
	Add a given group as a member if it's not one already
	
	Parameters
	----------
	con : LDAPObject
		Create with initialize()
	parent_cn : str
		The cn of the parent group to be checked
	cn : str
		The cn of the course group to be added
	(optional) base_dn : string
		The base dn of the group to update
		You should change the default value to match your orginization's own base dn
		
		
	Returns
	-------
	None
	
	"""
	members = get_group_of_groups_members(con, parent_cn)
			
	dn = ('cn=' + str(cn) + ',' + str(base_dn))
	if(not(dn in members)):
		members.append(dn)
		attr = 'member'
		parent_dn = ('cn=' + str(parent_cn) + ',' + str(base_dn))
		replace_attribute(con, parent_dn, attr, members)
		logging.info('Added member to parent group: ' + str(parent_cn))
		logging.info('               New member is: ' + str(cn))
		if(args.verbose):
			print('Added member to parent group: ' + str(parent_cn))
			print('               New member is: ' + str(cn))
	else:
		logging.debug('Group ' + str(cn) + ' is already a member of parent group ' + str(parent_cn))
	return
