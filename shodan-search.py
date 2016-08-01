#!/usr/bin/env python

#Import necessary modules, most likely you won't have the "Shodan" module installed. Install by executing "sudo pip install shodan" or "sudo easy_install shodan"
import shodan
import datetime
from email.mime.text import MIMEText
from subprocess import Popen, PIPE

#****************************************#
##**********User Set Variables**********##

#Set your organization name!!
organizationname = 'org:"My Company" '

#Number of days back to search for Shodan results each time this script is executed
dateoffset = 1

#Load API Key. Just a text file with the API key.
with open('/path/to/api/key.txt') as f:
	SHODAN_API_KEY = f.readline().rstrip()

#Email variables, uses sendmail on the server it is being executed from, it runs command "/usr/sbin/sendmail -t -oi"

#Set the email address you want the message to be delivered from
emailfrom = "sourceemailaddress@domain.com"

#Set the email address you want the message to be delivered to. 
#Multiple addresses can be specified with a semi colon between addresses "user@domain.com; user2@domain.com"
emailto = "destinationemailaddress@domain.com"

##**********END User Set Variables**********##
#********************************************#


#set various variables
api = shodan.Shodan(SHODAN_API_KEY)
datesearch = datetime.datetime.strftime(datetime.datetime.now()-datetime.timedelta(dateoffset), '%d/%m/%Y')

def shodansearch():

	apidown = False
	#*#*build Shodan Searches#*#* 
	shodanresults = ''
	#-------------------------------------------------------------------------------------#
	#Servers, endpoints, phones
	ipmibaremetal = organizationname + 'port:"623" after:' + datesearch
	winsmb = organizationname + 'port:"445" after:' + datesearch
	netbios = organizationname + 'port:"137" after:' + datesearch
	winxp = organizationname + 'os:"windows xp" after:' + datesearch
	polycom = organizationname + '"Polycom Command Shell" after:' + datesearch

	#Scada/Industrial
	modbus = organizationname + 'port:"502" after:' + datesearch
	scada = organizationname + '"scada" after:' + datesearch

	#Network Storage
	iomega_nas = organizationname + '"iomega" after:' + datesearch

	#General open access
	defaultpasswd = organizationname + '"default password" after:' + datesearch
	defaultpasswd2 = organizationname + '"admin+1234" after:' + datesearch
	anoymous_access = organizationname + '"Anonymous access granted" after:' + datesearch

	#Network
	snmp = organizationname + 'port:"161" after:' + datesearch
	cisco = organizationname + '"cisco-ios" after:' + datesearch

	#Databases
	mysql = organizationname + 'product:"MySQL" after:' + datesearch
	postgres = organizationname + 'port:"5432" "PostgresSQL" after:' + datesearch
	mongo = organizationname + 'product:"MongoDB" after:' + datesearch
	riak = organizationname + 'port:"8087" "Riak" after:' + datesearch
	elastic = organizationname + 'port:"9200" "json" after:' + datesearch
	redis = organizationname + 'product:"Redis" after:' + datesearch
	memcached = organizationname + 'product:"Memcached" after:' + datesearch
	cassandra = organizationname + 'product:"Cassandra" after:' + datesearch
	couch = organizationname + 'product:"CouchDB" after:' + datesearch

	#Remote Access
	openvnc = organizationname + '"authentication disabled" after:' + datesearch
	#---------------------------------------------------------------------------------------#
	
	try:
		# Run searches, append details to an email
		ipmibaremetal = api.search(ipmibaremetal)
		if ipmibaremetal['matches']:
			shodanresults += "IMPI Bare Metal \n=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=\n"
			for result in ipmibaremetal['matches']:
				if not result['ip_str']:
					ip = "Host IP: "
				else:
					ip = "Host IP: " + str(result['ip_str'])
				if not result['hostnames']:
					hostname = "Hostname: "
				else:
					hostname = "Hostname: " + str(result['hostnames'][0])
				if not result['timestamp']:
					timestamp = "Timestamp: "
				else:
					timestamp = "Timestamp: " + str(result['timestamp'])
				if not result['port']:
					port = "Port: "
				else:
					port = "Port: " + str(result['port'])
				shodanresults += ip + '\n'
				shodanresults += hostname + '\n'
				shodanresults += timestamp + '\n'
				shodanresults += port + '\n'
				shodanresults += '---------------------------------------\n'
			
		winsmb = api.search(winsmb)
		if winsmb['matches']:
			shodanresults += "Windows SMB \n=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=\n"
			for result in winsmb['matches']:
				if not result['ip_str']:
					ip = "Host IP: "
				else:
					ip = "Host IP: " + str(result['ip_str'])
				if not result['hostnames']:
					hostname = "Hostname: "
				else:
					hostname = "Hostname: " + str(result['hostnames'][0])
				if not result['timestamp']:
					timestamp = "Timestamp: "
				else:
					timestamp = "Timestamp: " + str(result['timestamp'])
				if not result['port']:
					port = "Port: "
				else:
					port = "Port: " + str(result['port'])
				shodanresults += ip + '\n'
				shodanresults += hostname + '\n'
				shodanresults += timestamp + '\n'
				shodanresults += port + '\n'
				shodanresults += '---------------------------------------\n'
				
		netbios = api.search(netbios)
		if netbios['matches']:
			shodanresults += "Net Bios \n=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=\n"
			for result in netbios['matches']:
				if not result['ip_str']:
					ip = "Host IP: "
				else:
					ip = "Host IP: " + str(result['ip_str'])
				if not result['hostnames']:
					hostname = "Hostname: "
				else:
					hostname = "Hostname: " + str(result['hostnames'][0])
				if not result['timestamp']:
					timestamp = "Timestamp: "
				else:
					timestamp = "Timestamp: " + str(result['timestamp'])
				if not result['port']:
					port = "Port: "
				else:
					port = "Port: " + str(result['port'])
				shodanresults += ip + '\n'
				shodanresults += hostname + '\n'
				shodanresults += timestamp + '\n'
				shodanresults += port + '\n'
				shodanresults += '---------------------------------------\n'
			
		winxp = api.search(winxp)
		if winxp['matches']:
			shodanresults += "Windows XP \n=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=\n"
			for result in winxp['matches']:
				if not result['ip_str']:
					ip = "Host IP: "
				else:
					ip = "Host IP: " + str(result['ip_str'])
				if not result['hostnames']:
					hostname = "Hostname: "
				else:
					hostname = "Hostname: " + str(result['hostnames'][0])
				if not result['timestamp']:
					timestamp = "Timestamp: "
				else:
					timestamp = "Timestamp: " + str(result['timestamp'])
				if not result['port']:
					port = "Port: "
				else:
					port = "Port: " + str(result['port'])
				shodanresults += ip + '\n'
				shodanresults += hostname + '\n'
				shodanresults += timestamp + '\n'
				shodanresults += port + '\n'
				shodanresults += '---------------------------------------\n'
	
		polycom = api.search(polycom)
		if polycom['matches']:
			shodanresults += "Polycom Phones \n=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=\n"
			for result in polycom['matches']:
				if not result['ip_str']:
					ip = "Host IP: "
				else:
					ip = "Host IP: " + str(result['ip_str'])
				if not result['hostnames']:
					hostname = "Hostname: "
				else:
					hostname = "Hostname: " + str(result['hostnames'][0])
				if not result['timestamp']:
					timestamp = "Timestamp: "
				else:
					timestamp = "Timestamp: " + str(result['timestamp'])
				if not result['port']:
					port = "Port: "
				else:
					port = "Port: " + str(result['port'])
				shodanresults += ip + '\n'
				shodanresults += hostname + '\n'
				shodanresults += timestamp + '\n'
				shodanresults += port + '\n'
				shodanresults += '---------------------------------------\n'
			
		modbus = api.search(modbus)
		if modbus['matches']:
			shodanresults += "Modbus Industrial Systems \n=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=\n"
			for result in modbus['matches']:
				if not result['ip_str']:
					ip = "Host IP: "
				else:
					ip = "Host IP: " + str(result['ip_str'])
				if not result['hostnames']:
					hostname = "Hostname: "
				else:
					hostname = "Hostname: " + str(result['hostnames'][0])
				if not result['timestamp']:
					timestamp = "Timestamp: "
				else:
					timestamp = "Timestamp: " + str(result['timestamp'])
				if not result['port']:
					port = "Port: "
				else:
					port = "Port: " + str(result['port'])
				shodanresults += ip + '\n'
				shodanresults += hostname + '\n'
				shodanresults += timestamp + '\n'
				shodanresults += port + '\n'
				shodanresults += '---------------------------------------\n'
				
		scada = api.search(scada)
		if scada['matches']:
			shodanresults += "SCADA Industrial Systems \n=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=\n"
			for result in scada['matches']:
				if not result['ip_str']:
					ip = "Host IP: "
				else:
					ip = "Host IP: " + str(result['ip_str'])
				if not result['hostnames']:
					hostname = "Hostname: "
				else:
					hostname = "Hostname: " + str(result['hostnames'][0])
				if not result['timestamp']:
					timestamp = "Timestamp: "
				else:
					timestamp = "Timestamp: " + str(result['timestamp'])
				if not result['port']:
					port = "Port: "
				else:
					port = "Port: " + str(result['port'])
				shodanresults += ip + '\n'
				shodanresults += hostname + '\n'
				shodanresults += timestamp + '\n'
				shodanresults += port + '\n'
				shodanresults += '---------------------------------------\n'
			
		iomega_nas = api.search(iomega_nas)
		if iomega_nas['matches']:
			shodanresults += "IOMega NAS Storage Devices \n=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=\n"
			for result in iomega_nas['matches']:
				if not result['ip_str']:
					ip = "Host IP: "
				else:
					ip = "Host IP: " + str(result['ip_str'])
				if not result['hostnames']:
					hostname = "Hostname: "
				else:
					hostname = "Hostname: " + str(result['hostnames'][0])
				if not result['timestamp']:
					timestamp = "Timestamp: "
				else:
					timestamp = "Timestamp: " + str(result['timestamp'])
				if not result['port']:
					port = "Port: "
				else:
					port = "Port: " + str(result['port'])
				shodanresults += ip + '\n'
				shodanresults += hostname + '\n'
				shodanresults += timestamp + '\n'
				shodanresults += port + '\n'
				shodanresults += '---------------------------------------\n'
				
		defaultpasswd = api.search(defaultpasswd)
		if defaultpasswd['matches']:
			shodanresults += "Default Password in Device Banner \n=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=\n"
			for result in defaultpasswd['matches']:
				if not result['ip_str']:
					ip = "Host IP: "
				else:
					ip = "Host IP: " + str(result['ip_str'])
				if not result['hostnames']:
					hostname = "Hostname: "
				else:
					hostname = "Hostname: " + str(result['hostnames'][0])
				if not result['timestamp']:
					timestamp = "Timestamp: "
				else:
					timestamp = "Timestamp: " + str(result['timestamp'])
				if not result['port']:
					port = "Port: "
				else:
					port = "Port: " + str(result['port'])
				shodanresults += ip + '\n'
				shodanresults += hostname + '\n'
				shodanresults += timestamp + '\n'
				shodanresults += port + '\n'
				shodanresults += '---------------------------------------\n'
			
		defaultpasswd2 = api.search(defaultpasswd2)
		if defaultpasswd2['matches']:
			shodanresults += "Default Password 1234 in Device Banner \n=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=\n"
			for result in defaultpasswd2['matches']:
				if not result['ip_str']:
					ip = "Host IP: "
				else:
					ip = "Host IP: " + str(result['ip_str'])
				if not result['hostnames']:
					hostname = "Hostname: "
				else:
					hostname = "Hostname: " + str(result['hostnames'][0])
				if not result['timestamp']:
					timestamp = "Timestamp: "
				else:
					timestamp = "Timestamp: " + str(result['timestamp'])
				if not result['port']:
					port = "Port: "
				else:
					port = "Port: " + str(result['port'])	
				shodanresults += ip + '\n'
				shodanresults += hostname + '\n'
				shodanresults += timestamp + '\n'
				shodanresults += port + '\n'
				shodanresults += '---------------------------------------\n'
		
		anoymous_access = api.search(anoymous_access)
		if anoymous_access['matches']:
			shodanresults += "Anoymous Access Allowed \n=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=\n"
			for result in anoymous_access['matches']:
				if not result['ip_str']:
					ip = "Host IP: "
				else:
					ip = "Host IP: " + str(result['ip_str'])
				if not result['hostnames']:
					hostname = "Hostname: "
				else:
					hostname = "Hostname: " + str(result['hostnames'][0])
				if not result['timestamp']:
					timestamp = "Timestamp: "
				else:
					timestamp = "Timestamp: " + str(result['timestamp'])
				if not result['port']:
					port = "Port: "
				else:
					port = "Port: " + str(result['port'])		
				shodanresults += ip + '\n'
				shodanresults += hostname + '\n'
				shodanresults += timestamp + '\n'
				shodanresults += port + '\n'
				shodanresults += '---------------------------------------\n'
			
		snmp = api.search(snmp)
		if snmp['matches']:
			shodanresults += "Open SNMP Devices \n=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=\n"
			for result in snmp['matches']:
				if not result['ip_str']:
					ip = "Host IP: "
				else:
					ip = "Host IP: " + str(result['ip_str'])
				if not result['hostnames']:
					hostname = "Hostname: "
				else:
					hostname = "Hostname: " + str(result['hostnames'][0])
				if not result['timestamp']:
					timestamp = "Timestamp: "
				else:
					timestamp = "Timestamp: " + str(result['timestamp'])
				if not result['port']:
					port = "Port: "
				else:
					port = "Port: " + str(result['port'])	
				shodanresults += ip + '\n'
				shodanresults += hostname + '\n'
				shodanresults += timestamp + '\n'
				shodanresults += port + '\n'
				shodanresults += '---------------------------------------\n'
				
		cisco = api.search(cisco)
		if cisco['matches']:
			shodanresults += "Open Cisco Devices \n=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=\n"
			for result in cisco['matches']:
				if not result['ip_str']:
					ip = "Host IP: "
				else:
					ip = "Host IP: " + str(result['ip_str'])
				if not result['hostnames']:
					hostname = "Hostname: "
				else:
					hostname = "Hostname: " + str(result['hostnames'][0])
				if not result['timestamp']:
					timestamp = "Timestamp: "
				else:
					timestamp = "Timestamp: " + str(result['timestamp'])
				if not result['port']:
					port = "Port: "
				else:
					port = "Port: " + str(result['port'])
				shodanresults += ip + '\n'
				shodanresults += hostname + '\n'
				shodanresults += timestamp + '\n'
				shodanresults += port + '\n'
				shodanresults += '---------------------------------------\n'
			
		mysql = api.search(mysql)
		if mysql['matches']:
			shodanresults += "Open MySQL Databases \n=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=\n"
			for result in mysql['matches']:
				if not result['ip_str']:
					ip = "Host IP: "
				else:
					ip = "Host IP: " + str(result['ip_str'])
				if not result['hostnames']:
					hostname = "Hostname: "
				else:
					hostname = "Hostname: " + str(result['hostnames'][0])
				if not result['timestamp']:
					timestamp = "Timestamp: "
				else:
					timestamp = "Timestamp: " + str(result['timestamp'])
				if not result['port']:
					port = "Port: "
				else:
					port = "Port: " + str(result['port'])
				shodanresults += ip + '\n'
				shodanresults += hostname + '\n'
				shodanresults += timestamp + '\n'
				shodanresults += port + '\n'
				shodanresults += '---------------------------------------\n'
				
		postgres = api.search(postgres)
		if postgres['matches']:
			shodanresults += "Open PostGres Databases \n=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=\n"
			for result in postgres['matches']:
				if not result['ip_str']:
					ip = "Host IP: "
				else:
					ip = "Host IP: " + str(result['ip_str'])
				if not result['hostnames']:
					hostname = "Hostname: "
				else:
					hostname = "Hostname: " + str(result['hostnames'][0])
				if not result['timestamp']:
					timestamp = "Timestamp: "
				else:
					timestamp = "Timestamp: " + str(result['timestamp'])
				if not result['port']:
					port = "Port: "
				else:
					port = "Port: " + str(result['port'])
				shodanresults += ip + '\n'
				shodanresults += hostname + '\n'
				shodanresults += timestamp + '\n'
				shodanresults += port + '\n'
				shodanresults += '---------------------------------------\n'	
			
		mongo = api.search(mongo)
		if mongo['matches']:
			shodanresults += "Open MongoDB Databases \n=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=\n"
			for result in mongo['matches']:
				if not result['ip_str']:
					ip = "Host IP: "
				else:
					ip = "Host IP: " + str(result['ip_str'])
				if not result['hostnames']:
					hostname = "Hostname: "
				else:
					hostname = "Hostname: " + str(result['hostnames'][0])
				if not result['timestamp']:
					timestamp = "Timestamp: "
				else:
					timestamp = "Timestamp: " + str(result['timestamp'])
				if not result['port']:
					port = "Port: "
				else:
					port = "Port: " + str(result['port'])	
				shodanresults += ip + '\n'
				shodanresults += hostname + '\n'
				shodanresults += timestamp + '\n'
				shodanresults += port + '\n'
				shodanresults += '---------------------------------------\n'	
				
		riak = api.search(riak)
		if riak['matches']:
			shodanresults += "Open Riak Databases \n=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=\n"
			for result in riak['matches']:
				if not result['ip_str']:
					ip = "Host IP: "
				else:
					ip = "Host IP: " + str(result['ip_str'])
				if not result['hostnames']:
					hostname = "Hostname: "
				else:
					hostname = "Hostname: " + str(result['hostnames'][0])
				if not result['timestamp']:
					timestamp = "Timestamp: "
				else:
					timestamp = "Timestamp: " + str(result['timestamp'])
				if not result['port']:
					port = "Port: "
				else:
					port = "Port: " + str(result['port'])
				shodanresults += ip + '\n'
				shodanresults += hostname + '\n'
				shodanresults += timestamp + '\n'
				shodanresults += port + '\n'
				shodanresults += '---------------------------------------\n'	
				
		elastic = api.search(elastic)
		if elastic['matches']:
			shodanresults += "Open Elasticsearch Databases \n=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=\n"
			for result in elastic['matches']:
				if not result['ip_str']:
					ip = "Host IP: "
				else:
					ip = "Host IP: " + str(result['ip_str'])
				if not result['hostnames']:
					hostname = "Hostname: "
				else:
					hostname = "Hostname: " + str(result['hostnames'][0])
				if not result['timestamp']:
					timestamp = "Timestamp: "
				else:
					timestamp = "Timestamp: " + str(result['timestamp'])
				if not result['port']:
					port = "Port: "
				else:
					port = "Port: " + str(result['port'])
				shodanresults += ip + '\n'
				shodanresults += hostname + '\n'
				shodanresults += timestamp + '\n'
				shodanresults += port + '\n'
				shodanresults += '---------------------------------------\n'
				
		redis = api.search(redis)
		if redis['matches']:
			shodanresults += "Open Redis Databases \n=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=\n"
			for result in redis['matches']:
				if not result['ip_str']:
					ip = "Host IP: "
				else:
					ip = "Host IP: " + str(result['ip_str'])
				if not result['hostnames']:
					hostname = "Hostname: "
				else:
					hostname = "Hostname: " + str(result['hostnames'][0])
				if not result['timestamp']:
					timestamp = "Timestamp: "
				else:
					timestamp = "Timestamp: " + str(result['timestamp'])
				if not result['port']:
					port = "Port: "
				else:
					port = "Port: " + str(result['port'])
				shodanresults += ip + '\n'
				shodanresults += hostname + '\n'
				shodanresults += timestamp + '\n'
				shodanresults += port + '\n'
				shodanresults += '---------------------------------------\n'
				
		memcached = api.search(memcached)
		if memcached['matches']:
			shodanresults += "Open MemCached Databases \n=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=\n"
			for result in memcached['matches']:
				if not result['ip_str']:
					ip = "Host IP: "
				else:
					ip = "Host IP: " + str(result['ip_str'])
				if not result['hostnames']:
					hostname = "Hostname: "
				else:
					hostname = "Hostname: " + str(result['hostnames'][0])
				if not result['timestamp']:
					timestamp = "Timestamp: "
				else:
					timestamp = "Timestamp: " + str(result['timestamp'])
				if not result['port']:
					port = "Port: "
				else:
					port = "Port: " + str(result['port'])
				shodanresults += ip + '\n'
				shodanresults += hostname + '\n'
				shodanresults += timestamp + '\n'
				shodanresults += port + '\n'
				shodanresults += '---------------------------------------\n'
				
		cassandra = api.search(cassandra)
		if cassandra['matches']:
			shodanresults += "Open Cassandra Databases \n=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=\n"
			for result in cassandra['matches']:
				if not result['ip_str']:
					ip = "Host IP: "
				else:
					ip = "Host IP: " + str(result['ip_str'])
				if not result['hostnames']:
					hostname = "Hostname: "
				else:
					hostname = "Hostname: " + str(result['hostnames'][0])
				if not result['timestamp']:
					timestamp = "Timestamp: "
				else:
					timestamp = "Timestamp: " + str(result['timestamp'])
				if not result['port']:
					port = "Port: "
				else:
					port = "Port: " + str(result['port'])
				shodanresults += ip + '\n'
				shodanresults += hostname + '\n'
				shodanresults += timestamp + '\n'
				shodanresults += port + '\n'
				shodanresults += '---------------------------------------\n'
			
		couch = api.search(couch)
		if couch['matches']:
			shodanresults += "Open Couch Databases \n=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=\n"
			for result in couch['matches']:
				if not result['ip_str']:
					ip = "Host IP: "
				else:
					ip = "Host IP: " + str(result['ip_str'])
				if not result['hostnames']:
					hostname = "Hostname: "
				else:
					hostname = "Hostname: " + str(result['hostnames'][0])
				if not result['timestamp']:
					timestamp = "Timestamp: "
				else:
					timestamp = "Timestamp: " + str(result['timestamp'])
				if not result['port']:
					port = "Port: "
				else:
					port = "Port: " + str(result['port'])
				shodanresults += ip + '\n'
				shodanresults += hostname + '\n'
				shodanresults += timestamp + '\n'
				shodanresults += port + '\n'
				shodanresults += '---------------------------------------\n'
			
		openvnc = api.search(openvnc)
		if openvnc['matches']:
			shodanresults += "No Password Required VNC \n=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=\n"
			for result in openvnc['matches']:
				if not result['ip_str']:
					ip = "Host IP: "
				else:
					ip = "Host IP: " + str(result['ip_str'])
				if not result['hostnames']:
					hostname = "Hostname: "
				else:
					hostname = "Hostname: " + str(result['hostnames'][0])
				if not result['timestamp']:
					timestamp = "Timestamp: "
				else:
					timestamp = "Timestamp: " + str(result['timestamp'])
				if not result['port']:
					port = "Port: "
				else:
					port = "Port: " + str(result['port'])
				shodanresults += ip + '\n'
				shodanresults += hostname + '\n'
				shodanresults += timestamp + '\n'
				shodanresults += port + '\n'
				shodanresults += '---------------------------------------\n'
				
	except shodan.APIError, e:
			apidown = True
			print "API's DOWN!"
			
	#Send Email Message
	if apidown == False and shodanresults != '':
		msg = MIMEText("Hello, Here's the daily Shodan Digest \n\
See below for discovered devices \n\n\n\n\
" +shodanresults+ " \n\
Sincerely, \n\
Your Friendly Bot")
		msg["From"] = emailfrom
		msg["To"] = emailto
		msg["Subject"] = ("Daily Shodan Digest")
		p = Popen(["/usr/sbin/sendmail", "-t", "-oi"], stdin=PIPE)
		p.communicate(msg.as_string())

if __name__ == '__main__':
	shodansearch()
