#LDAP-tools
A suite of python functions to simplify common LDAP administration tasks with python-ldap

WARNING: Some functions require organization-specific input, specifically a base dn and SambaSID prefix.
While you can pass your organizations' values to these functions, it's recommended that you modify the default values instead.
Future updates may include a simpler way to do this without having to modify multiple function definitions.
You can find the places where these defaults are defined by searching for "base_dn=" and "samba_prefix="
If your schema doesn't use ou=people for users and ou=groups for groups, you'll need to modify some of the functions more extensively to make them usable.


Summary of currently included functions
---------------------------------------
initialize
	Initializes a connection to an LDAP server, using the local server by default
login
	Prompts for a dn and password, and uses them to bind to LDAP.
	Uses anonymous authentication if no username is entered.
	Forces a sys.exit() after some number of unsuccessful login attempts.
ldapsearch
	Returns the results of an ldapsearch.
ldapadd
	Adds a record to LDAP
replace_attribute
	Replace the value(s) assigned to an arribute in an LDAP record
	The attribute will be added to the record if not already present
next_available_uid
	Determine the next available uidNumber in the LDAP database
next_available_sid
	Determine the next available sambaSID number in the LDAP database
next_available_gid
	Determine the next available gidNumber in the LDAP database
increment_uid
	Increment a UID (or GID) number
increment_sid
	Increment an SID number
handle_long_values
	Recombine any fields that have spilled across multiple lines
	Mainly intended for use when reading an LDIF file
file_to_lines
	Convert a text or LDIF file into a list of lines
check_for_existing_group
	Search LDAP to see if a group cn exists already
get_group_members
	Get the members of a posix group
get_group_of_groups_members
	Get the members of a group of groups
update_group_of_groups_membership
	Update the membership of a group of groups
	Add a given group as a member if it's not one already
generate_pwd
	Generate a random password for a new user
generate_ssha
	Generate a SSHA version of a password
generate_sambaNTPassword
	Generate a Samba NT version of a password
seconds_since_epoch
	Return the number of seconds since the epoch (1/1/70)
days_since_epoch
	Return the integer number of days since the epoch (1/1/70)
days_to_pwd_expiration
	Determine number of days remaining until a user's password will expire
