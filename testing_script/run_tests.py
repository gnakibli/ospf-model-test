import os
import time
import telnetlib
import re
from scapy.all import *
from parseSymbolicExprs import * 
from shutil import copyfile
import requests
import subprocess
import thread
import ipaddress
import pprint
import json
import pexpect

load_contrib('ospf')

testsdir = 'tests/'

endsection = '#-----------------------'
msgsection = '#Messages sent:'
InitialLSDBSection = '#Initial LSDBs:'
#OutputLSDBSection = '#Output:'
OutputLSDBSection = ['#Output 0 :','#Output 1 :']

stype = 'type='
sdest = 'dest='
sadvrouter = 'AdvertisingRouter='
slsid = 'LSID'
sseqnum = 'sequenceNum='
slinks = 'Links='
ssrc = 'src'


maxSequenceNumCisco = 0x7fffffff
maxSequenceNumModel = 7
initialSequenceNumModel = 0
initialSequenceNumCisco = 0x80000001
#sequence num range : from InitialSequenceNumber (0x80000001) to MaxSequenceNumber (0x7fffffff).

VIRLHostIP = '132.68.39.42'
VIRLGWIP = '172.16.1.254'
LXCIP = "" #This is the node through which we log into the routers, will be fetched when the script runs
LXCName = '~mgmt-lxc'
VIRLUserName = 'BlackBox'
VIRLPassword = 'gabi'
ExternalRouter = 'R0' #This is the router that is attached to the 'cloud'/'flat'/attacker
VIRLExternalIPAdress = "" #will be fetched when the script runs


routerip = {'0':{'0':('10.0.2.10', 'GigabitEthernet0/1')}, '1':{'1':('10.0.1.1', 'GigabitEthernet0/2'), '10':('10.0.2.1', 'GigabitEthernet0/1'), '100':('10.0.0.1', 'GigabitEthernet0/3')}, '2':{'2':('10.0.1.2', 'GigabitEthernet0/1')}, '3':{'3':('10.0.0.3', 'GigabitEthernet0/1')}, '4':{'4':('10.0.0.4', 'GigabitEthernet0/1')}}
routerid = {'0':'10.0.2.10', '1':'10.0.2.1', '2':'10.0.1.2', '3':'10.0.0.3', '4':'10.0.0.4'}
#The console ports of each router0
controlport = {'0':17000, '1':17001, '2':17002, '3':17003, '4':17004}




class Globals:
	def __init__(self):
		self.M_seq = []
		self.M_index = 0
		self.mapMatchingLSAsInitial={}
		self.mapMatchingLSAsFinal={}
		self.might_fail_due_to_chksum_issue = [False]		
		self.chosenDR= '10.0.2.1' #None
		self.chosenDRaddress= '10.0.0.1' #None	
		self.useNewReload = True	
		self.repeatTest = False
		self.foundDuplicateRID = False
		#self.log_db_status = ['']
		return
	
	def clean(self):
		self.M_seq = []
		self.M_index = 0
		self.mapMatchingLSAsInitial={}
		self.mapMatchingLSAsFinal={}
		self.might_fail_due_to_chksum_issue[0] = False
		self.chosenDR= '10.0.2.1' #None
		self.chosenDRaddress= '10.0.0.1' #None	
		self.foundDuplicateRID = False
		#self.useNewReload = False
		#self.log_db_status = 
		return 
	
	



class seqNumChecker:
	def __init__(self, inputFile):
		try:
			self.inputFile = inputFile
			self.parser =  parseSeqNumExpr(inputFile)
			self.parser.parse()
			#self.parser.printParsedVals()
			return 
		except:
			raise
	
	def compare_results(self, globals):	
		#per router - given initial and final seq, make sure it is consistent with symbolic exprs from model
		try:
			if( len(globals.M_seq) <=0):
				raise Exception('error seqNumChecker -- M_seq length is not positive')
			for r in globals.mapMatchingLSAsInitial:			
				res = self.parser.checkConsistency(r,globals.mapMatchingLSAsInitial,globals.mapMatchingLSAsFinal, globals.M_seq, globals.M_index, globals.might_fail_due_to_chksum_issue)
				if(not res):
					return False
	
			return True 
		
		except:
			raise
		


class DebugPrint:
     
    def __init__(self):
        self.isActivated = False
        return
    def Activate(self):
        self.isActivated=True
    def DeActivate(self):
        self.isActivated=False    
    def Print(self,s):
        if self.isActivated:
            print s
            
    

debug = DebugPrint()
debug.Activate()

def findsection(str, file):
	f=open(file)
	lines=f.readlines()
	output = list()
	found = False
	for l in lines:
		if endsection in l:
			found = False
		if found == True:
			output.append(l)
		#if str in l:
		if l.startswith(str):
			found = True
	f.close()
	#print(output)
	return output

def LoginToRouter(r, tn):
	#tn.set_debuglevel(10)
	tn.write("\n\r")
	ret, _, _ = tn.expect(["R"+str(r)+">", "R"+str(r)+"#"])
	if ret == 0: #not enabled yet
		tn.write("en\n\r")
		tn.read_until("Password:")
		tn.write("cisco\n\r")
		tn.read_until("#")
	tn.read_very_eager()
	tn.write("terminal length 0"+"\n\r")
	tn.read_until("#")  
	tn.read_very_eager()


def ExtractRouterLinks(value, lsaid):
	start = value.find("(")
	links = list()
	while start != -1:
		end = value.find(")", start)
		#print value[start:end]
		linkargs = value[start:end].split(';')
		#print linkargs
		for a in linkargs:
			#print a
			avalue = str(a[a.find('=')+1:]).strip()
			#print avalue
			if 'linkID' in a:
				linkid = avalue
			elif 'linkType' in a:
				if avalue == 'p2p':
					linktype = 1
				elif avalue == 'transit':
					linktype = 2
				elif avalue == 'stub':
					linktype = 3
				else:
					print "Error identifying link type " + avalue
			elif 'linkData' in a:
				linkdata = avalue
			elif 'metric' in a:
				cost = int(avalue)
			elif len(a.strip()) != 0:
				print "Error identifying link argument " + a
		#link = OSPF_Link(id=routerid[linkid],data=routerip[lsaid][linkdata],type=linktype)
		link = OSPF_Link(id=routerid[linkid],data=routerip[lsaid][linkdata][0],type=linktype)
		links.append(link)
		start = value.find("(", end)
	# for l in links:
		# print "link details:"
		# print l.id
		# print l.data
		# print l.type
	return links
	
def ExtractNetworkLinks(value):
	strlist = value[1:-1].split(";")
	attachedrouters = list()
	for s in strlist:
		attachedrouters.append(routerid[s])
	return attachedrouters

def readlsa(l,seqChecker,globals):
	ipdest = None
	ipsrc = None
	idsrc = None
	r = re.compile('[\t\n\r,]+')
	parts = r.split(l)
	#print parts, len(parts)
	if len(parts) < 6:
		return None, None, None, None
	ipdest = None
	for p in parts:
		#print p
		ivalue = p.find('=')
		if ivalue == -1:
			break
		value = str(p[p.find('=')+1:]).strip()
		#print value
		#lsa = None
		if stype in p:
			lsatype = value
			if value == 'routerLSA':
				lsa = OSPF_Router_LSA()
			elif value == 'networkLSA':
				lsa = OSPF_Network_LSA()
			else:
				print "unrecognised LSA type " + value
		elif sdest in p:
			if value.isdigit():
				ipdest = routerid[value]
			else:
				ipdest = routerid[str(seqChecker.parser.getSymbolicVal(value))]
		elif ssrc in p:
			src = value.split(':',2)
			ipsrc = routerip[src[0]][src[1]][0]
			idsrc = routerid[src[0]]
		elif sadvrouter in p:
			if value.isdigit():			
				lsa.adrouter = routerid[value]
			else:
				lsa.adrouter = routerid[str(seqChecker.parser.getSymbolicVal(value))]
		elif sseqnum in p:
			if value.isdigit():				
				lsa.seq =   int(value) #0x80001111#				
			else:
				lsa.seq = seqChecker.parser.getSymbolicVal(value)   #0x80001111	
		elif slsid in p:
			if value.isdigit():
				lsaid = value # This is needed to constructs the links argument. See below.
				lsa.id = routerid[value]
			else:
				lsaid = str(seqChecker.parser.getSymbolicVal(value))
				lsa.id = routerid[str(seqChecker.parser.getSymbolicVal(value))]	
		elif slinks in p:
			if lsatype == 'routerLSA':
				links = ExtractRouterLinks(value, lsaid)
				lsa.linklist = links
				lsa.linkcount = len(links)
			elif lsatype == 'networkLSA':
				attachedrouters = ExtractNetworkLinks(value)
				lsa.routerlist = attachedrouters
		else:
			print "unrecognised part " + p + " in line " + l
	
	#fix parts concerning chosen DR extracted from cisco DB
	if lsa.type==2: #network LSA
		lsa.id = globals.chosenDRaddress
		lsa.adrouter = globals.chosenDR
	elif lsa.type==1: #router LSA
		for link in lsa.linklist:
			if link.type==2:  #transit
				link.id = globals.chosenDRaddress
	
	print lsa.adrouter
	print lsa.seq
	print lsa.id
	if lsatype == 'routerLSA':
		print lsa.linkcount
	print lsa.summary()	
	print ipdest
	print ipsrc
	print idsrc
	return lsa, ipdest, ipsrc, idsrc




def calcSeqToSend(lsa,seqChecker,globals,msg_index):
	try:
		#get the seq from symbolic vals
		symbolic_index=0
		for description in seqChecker.parser.m_s_rep_description:
			if ':seq' in description:
				msg_index_descpription = int(description[1])
				if msg_index_descpription == msg_index:
					break
			symbolic_index+=1
		seq = seqChecker.parser.m_s_values[symbolic_index]	
		
		print "calc sequence number to send"			
		if seq == maxSequenceNumModel:
			lsa.seq = maxSequenceNumCisco
			globals.M_seq.append(lsa.seq)
			print 'M_seq = ' + str(globals.M_seq)
			return
		elif seq == maxSequenceNumModel-1:
			lsa.seq = maxSequenceNumCisco-1
			globals.M_seq.append(lsa.seq)
			print 'M_seq = ' + str(globals.M_seq)
			return		
		
		#update seq number for message based on the test and the cisco initial DB 
		lsa_st = getLSAString(lsa)
		if lsa.id != lsa.adrouter: #send seq w.r.t lsid

			lsa_st = str(lsa.type) + ';' + str(lsa.id) + ';' + str(lsa.id)
		data_list = None
		for k in globals.mapMatchingLSAsInitial:
			for st in globals.mapMatchingLSAsInitial[k]:
				if st == lsa_st:
					data_list = globals.mapMatchingLSAsInitial[k][st]
					break
		#assert(data_list!=None and  len(data_list)==2)
		if not (data_list!=None and  len(data_list)==2):
			raise Exception('calcSeqToSend error - data_list error')
		debug.Print('data_list: ' + str(data_list)  )
		if data_list != None:
			initial_model_seq = data_list[0].seq
			initial_cisco_seq = data_list[1].seq
			debug.Print( str(seq) + ' ' +  str(initial_model_seq) + ' ' + str(initial_cisco_seq))
			lsa.seq = (seq - initial_model_seq) + initial_cisco_seq
			if (seq == initial_model_seq):
				globals.might_fail_due_to_chksum_issue[0] = True
			#print 'seq = ' + str(seq)
			#print 'initial_model_seq = ' + str(initial_model_seq)
			#print 'might_fail_due_to_chksum_issue = ' + str(might_fail_due_to_chksum_issue)		
			 	
			print "determined lsa sequence is:"
			print lsa.seq
			globals.M_seq.append(lsa.seq)
			print 'M_seq = ' + str(globals.M_seq)
		else:				
			#assert False
			raise Exception('calcSeqToSend error ') 
			lsa.seq = 0x80001111
			print lsa.seq
			print "using default val for lsa sequence"
		return	
	
	except:
		raise
	
	
	
	
#def runtest(file,mapMatchingLSAs,seqChecker,M_seq,might_fail_due_to_chksum_issue):
def	runtest(file,globals,seqChecker):
	try:
		messagelines = findsection(msgsection, file)
		print messagelines
		messages = list()
		index=0
		for l in messagelines:
			lsa, dest, ipsrc, idsrc = readlsa(l,seqChecker,globals)
			if lsa is not None:
				calcSeqToSend(lsa,seqChecker,globals,index)	#updates the seq of the lsa	
				if not seqChecker.parser.checkConsistentInitialState(globals.mapMatchingLSAsInitial, globals.M_seq , globals.M_index):
					raise Exception('seqChecker.parser.checkConsistentInitialState failed')
				print	lsa		 				
				message=IP(src=VIRLGWIP, dst=VIRLExternalIPAdress)/GRE()/IP(src=ipsrc, dst=dest)/OSPF_Hdr(src=idsrc)/OSPF_LSUpd(lsalist=list(lsa,))
				message.show2()
				print message.command()
				messages.append(message)
			index+=1	
		return messages
	except:
		raise




def ReloadGNS3():
	for r in controlport:
		print "**************** " + r
		tn = telnetlib.Telnet(LXCIP, controlport[r])
		LoginToRouter(r, tn)
		tn.write("clear ip ospf 1 process\n\r")
		tn.read_until("Reset OSPF process 1? [no]:")
		tn.write("yes\n\r")
		tn.close()


def ReloadGNS3_new(SimulationID):
	STOP_ROUTERS_URL = "http://%s:19399/simengine/rest/update/%s/stop" % (VIRLHostIP, SimulationID)
	payload   = {'nodes': ['R'+str(r) for r in controlport]}
	resp = requests.put(STOP_ROUTERS_URL, auth=(VIRLUserName, VIRLPassword), params=payload)
	if resp.status_code != 200:
		print "ReloadGNS3(stop): retruned code %d." % (resp.status_code)
		return None
	print "Routers stopped."
	time.sleep(150)
	START_ROUTERS_URL = "http://%s:19399/simengine/rest/update/%s/start" % (VIRLHostIP, SimulationID)
	#payload   = {'nodes': ['R'+str(r) for r in controlport]}
	resp = requests.put(START_ROUTERS_URL, auth=(VIRLUserName, VIRLPassword))
	if resp.status_code != 200:
		print "ReloadGNS3(start): retruned code %d." % (resp.status_code)
		return None
	print "Routers started."
	time.sleep(150)

	print "Initializing Telnet connections...."
	InitTelnet2Routers()
	'''
	for r in controlport:
		print "**************** " + r

		tn = telnetlib.Telnet(LXCIP, controlport[r])
		LoginToRouter(r, tn)
		tn.write("clear ip ospf 1 process\n\r")
		tn.read_until("Reset OSPF process 1? [no]:")
		tn.write("yes\n\r")
		tn.close()
	'''

'''
def open_console(port):
	subprocess.call(['gnome-terminal', '-t', '', '-e', 'telnet localhost ' + port])
	return


def ReloadGNS3_new():
	for r in controlport:		
		stop_req= 'http://localhost:8000/v1/projects/'+ project_id +'/dynamips/vms/' + routers_vm_id[r] +'/stop'
		start_req = 'http://localhost:8000/v1/projects/'+ project_id +'/dynamips/vms/' + routers_vm_id[r] +'/start'
		sys.stderr.write(r)		
		res = requests.post(stop_req, data = {})  #stop r
		sys.stderr.write(str(res))		
		res = requests.post(start_req, data = {}) #start r
		sys.stderr.write(str(res))		

	time.sleep(120)
	
	thread.start_new_thread( open_console, ('2004',) )
	thread.start_new_thread( open_console, ('2000',) )
	thread.start_new_thread( open_console, ('2001',) )
	thread.start_new_thread( open_console, ('2002',) )
	thread.start_new_thread( open_console, ('2003',) )
	
	time.sleep(300)


	for r in controlport:	
		tn = telnetlib.Telnet("localhost", controlport[r])
		tn.set_debuglevel(15)
		tn.write("\n\r")

	sys.stderr.write('continue -- exit reload function')		
		

		
		


def ReloadGNS3():
	for r in controlport:
		print "**************** " + r
		tn = telnetlib.Telnet("localhost", controlport[r])
		tn.set_debuglevel(15) #added
		tn.write("\n\r")	#added
		tn.read_until("cdsfsf", 0.5) #can be any string
		tn.set_debuglevel(0)
		tn.write("\nen\n\r")
		tn.read_until("#")
		tn.write("clear ip ospf 1 process\n\r")
		tn.read_until("Reset OSPF process 1? [no]:", 0.5)
		tn.write("yes\n\r")
		tn.read_until("dsfdsf", 0.5)
		tn.close()
		
		#time.sleep(60)

'''

def ReadModelLSDB(DBlines,seqChecker,globals):
	LSADB = {}
	r = '-1'
	for l in DBlines:
		index = l.find('LSDB')
		if index != -1: #New router
			r = l[index+len('LSDB')]
			print "********* Reading LSADB of R" + str(r)
			LSADB[r] = list()
			continue	
		else: #New LSA
			lsa, _, _, _ = readlsa(l,seqChecker,globals)
			if lsa == None:
				continue
			print lsa.summary()
			LSADB[r].append(lsa)
	return LSADB


def ParseRouterLink(current, lines):
	#print "starting to parse router link"
	linesnum = len(lines)
	link = OSPF_Link()#(id=routerid[linkid],data=routerip[lsaid][linkdata][0],type=linktype)
	while current < linesnum:
		args = lines[current].split(":",2)
		param = args[0].strip()
		value = args[1].strip()
		#print param, value
		if "Link connected to" in param: #a new lsa is starting
			if "point-to-point" in value:
				link.type = 1
			elif "Transit" in value:
				link.type = 2
			elif "Stub" in value:
				link.type = 3
			else:
				print "Error link type " + str(value)
		elif "Link ID" in param:
			link.id = value
		elif "Link Data" in param: #last link value
			link.data = value
			#link.show()
			return current, link
			
		current = current + 1
	return current, link	
			
	
def ParseRouterLSA(current, lines):
	#print "start to parse router LSA"
	linesnum = len(lines)
	lsa = OSPF_Router_LSA()
	while current < linesnum:	
		args = lines[current].split(":",2)
		if len(args) < 2:
			current = current + 1
			continue
		#print 	lines[current]
		param = args[0].strip()
		value = args[1].strip()
		#print param, value
		if "LS age" in param: #a new lsa is starting
			#lsa.age = int(value)
			lsa.age=0
		elif "Link State ID" in param:
			lsa.id = value
		elif "Advertising Router" in param:
			lsa.adrouter = value
		elif "LS Seq Number" in param:
			lsa.seq = int(value, 16)
		elif "Number of Links" in param:
			lsa.linkcount = int(value)
			linkstoprocess = lsa.linkcount
			if linkstoprocess==0: #finished parsing LSA
				return current,lsa
		elif "Link connected to" in param:
			current, link = ParseRouterLink(current, lines)
			lsa.linklist.append(link)
			linkstoprocess = linkstoprocess - 1
			if linkstoprocess == 0: #finished parsing LSA
				#print lsa.summary()
				return current, lsa
		current = current + 1	
	return current, lsa

def ParseAttachedRouters(current, lines):
	linesnum = len(lines)
	attachedrouters = list()
	while current < linesnum:	
		args = lines[current].split(":",2)
		if len(args) < 2:
			current = current + 1
			return current, attachedrouters
		param = args[0].strip()
		value = args[1].strip()
		#print param, value
		if "Attached Router" in param: 
			attachedrouters.append(value)
		else:
			return current, attachedrouters
		current = current + 1
	return current, attachedrouters
	
def ParseNetworkLSA(current, lines, globals):
	#global chosenDRaddress
	#global chosenDR
	linesnum = len(lines)
	lsa = OSPF_Network_LSA()
	while current < linesnum:	
		args = lines[current].split(":",2)
		if len(args) < 2:
			current = current + 1
			continue
		param = args[0].strip()
		value = args[1].strip()
		#print param, value
		if "LS age" in param: #a new lsa is starting
			lsa.age = int(value)
		elif "Link State ID" in param:
			value = value.split(' ')[0]
			lsa.id = value
			if globals.chosenDRaddress==None:
				globals.chosenDRaddress = lsa.id
				print "chosenDRaddress: " + str(globals.chosenDRaddress)
		elif "Advertising Router" in param:
			lsa.adrouter = value
			if globals.chosenDR==None:
				globals.chosenDR = value	
				print "chosenDR: " + str(globals.chosenDR)
		elif "LS Seq Number" in param:
			lsa.seq = int(value, 16)
		elif "Network Mask" in param:
			current, attachedrouter = ParseAttachedRouters(current+1, lines)
			lsa.routerlist = attachedrouter
			#print lsa.summary()
			return current, lsa
		current = current + 1	
	return current, lsa

def ParseCLIoutput(CLIoutput, globals):
	lines = CLIoutput.split("\n")
	current = 0
	linesnum = len(lines)
	LSADB = list()
	state = None
	while current < linesnum:
		if "Router Link States" in lines[current]:
			state = 'router'
			#print "state  - router"
		elif "Net Link States" in lines[current]:
			state = 'network'
			#print "state  - network"
		elif "LS age" in lines[current]: #start of new LSA
			if state == 'router':
				current, lsa = ParseRouterLSA(current, lines)
				LSADB.append(lsa)				
			elif state == 'network':
				current, lsa = ParseNetworkLSA(current, lines,globals)
				LSADB.append(lsa)
			else:
				print "Error unknown state for line " + lines[current]
		current = current + 1
	return LSADB


def ParseCLIRoute(CLIoutput):
	lines = CLIoutput.split("\n")
	current = 0
	linesnum = len(lines)
	RT = list()
	state = None
	while current < linesnum:
		if len(lines[current]) > 0 and "O" == lines[current][0]: #this is a route derived from the OSPF process
			args = re.split(' |, |\r\n', lines[current])
			print args
			if len(args) < 7:
				current = current + 1
				continue
			#print 	lines[current]
			R = {}
			retlist = args[8].strip().split('/')
			if len(retlist) > 1:
				R["mask"] = int(retlist[1])
			else:
				R["mask"] = 32
			R["ip"] = retlist[0]
			R["cost"] = int(args[9].strip('[]').split('/')[1])
			R["nexthopID"] = args[11]
			R["nexthop"] = args[13].strip()
			RT.append(R)
		current = current + 1
	print "final RT: "
	print RT
	return RT

'''
def FetchCiscoLSDB(globals):
	sys.stderr.write('fetch cisco LSDB')			
	LSADB = {}
	for r in controlport:
		sys.stderr.write('Fetch ' + r + '\n')
		tn = telnetlib.Telnet("localhost", controlport[r])
		tn.set_debuglevel(15) #added
		tn.write("\n\r")	#added
		tn.read_until("cdsfsf", 0.5) #can be any string
		tn.set_debuglevel(10)
		tn.write("\nen\n\r")
		tn.read_until("#", 1)
		tn.write("\nterminal length 0"+"\n\r")
		tn.read_until("#", 1)  
		CLIoutput = ""
		for lsatype in ["router", "network"]:
			print "XXXXXXXXXXXXfetch" + lsatype 
			tn.write("\nshow ip ospf database %s \n\r" % lsatype )
			CLIoutput += tn.read_until("#")
		print "*******************" + str(r) + "**************"
		print CLIoutput
		print "--------------------------------------------"		
		LSADB[r] = ParseCLIoutput(CLIoutput, globals)
		tn.close()
	return LSADB
'''


def FetchCiscoLSDB(globals):	
	sys.stderr.write('fetch cisco LSDB')			
	LSADB = {}
	for r in controlport:
		sys.stderr.write('Fetch ' + r + '\n')
		tn = telnetlib.Telnet(LXCIP, controlport[r])
		LoginToRouter(r, tn)
		CLIoutput = ""
		for lsatype in ["router", "network"]:
			#print "XXXXXXXXXXXXfetch" + lsatype 
			tn.write("show ip ospf database %s \n\r" % lsatype )
			CLIoutput += tn.read_until("#")
			tn.read_very_eager()
		print "*******************" + str(r) + "**************"
		print CLIoutput
		print "--------------------------------------------"
		LSADB[r] = ParseCLIoutput(CLIoutput,globals)
		tn.close()
	return LSADB


def FetchCiscoRoute():	
	RT = {}
	for r in controlport:
		tn = telnetlib.Telnet(LXCIP, controlport[r])
		LoginToRouter(r, tn)
		tn.write("show ip route \n\r" )
		CLIoutput = tn.read_until("#")
		tn.close()
		#print "*******************" + str(r) + "**************"
		print CLIoutput
		#print "--------------------------------------------"
		RT[r] = ParseCLIRoute(CLIoutput)
	return RT


def initializeSeqNumbers(seqChecker,  DBcisco, globals):
	try:
		#sufficient to observe one router to conclude required vals, since all routers begin with the same state 
		initialSeqNums_model = seqChecker.parser.m_initialSeqNums
		currSeqNums_cisco = {}
		seqToInitialize = {}
		r=0
		rLSDBcisco = DBcisco['0']
		print 'rLSDBcisco:'
		print	rLSDBcisco
		for lsa in rLSDBcisco:
			if lsa.type != 1:
				continue
			lsid = lsa.id
			seq = lsa.seq
			r_index = None
			for r in routerid:
				if routerid[r]==lsid:
					r_index = r
					break
			#assert(r_index != None)
			if not (r_index != None):
				raise Exception('initializeSeqNumbers error - r_index ')
			currSeqNums_cisco[r_index] = 	seq
		
		print currSeqNums_cisco
		#find the maximal seqNum to be set as 'zero point'
		max_seq =  0
		for r in range(0,5):
			if currSeqNums_cisco[str(r)] > max_seq:
				max_seq = currSeqNums_cisco[str(r)]
		
		max_seq = max_seq + 2		
		
		#find which seq to initialize per each router , to match the model initial state
		print  initialSeqNums_model
		print 'max_seq= ' + str(max_seq)
		for r in range(0,5):
			#print initialSeqNums_model[r]
			seqToInitialize[r] = max_seq-1 + initialSeqNums_model[str(r)]
			print r, max_seq + initialSeqNums_model[str(r)]
			#assert (seqToInitialize[r] < (2147483647 - 10) )
			
			
		print "seqToInitialize"
		print 	seqToInitialize			
		#send packets to generate the required initial state						
		
		messages=[]
		message=IP(src=VIRLGWIP, dst=VIRLExternalIPAdress)/GRE()/IP(src='10.0.2.10', dst='10.0.2.1')/OSPF_Hdr(src='10.0.2.10')/OSPF_LSUpd(lsalist=[OSPF_Router_LSA(linklist=[], adrouter='10.0.2.1', linkcount=0, id='10.0.2.1', seq=seqToInitialize[1])])
		message.show2()
		messages.append(message)

		message=IP(src=VIRLGWIP, dst=VIRLExternalIPAdress)/GRE()/IP(src='10.0.0.1', dst='10.0.0.3')/OSPF_Hdr(src='10.0.2.1')/OSPF_LSUpd(lsalist=[OSPF_Router_LSA(linklist=[], adrouter='10.0.0.3', linkcount=0, id='10.0.0.3', seq=seqToInitialize[3])])
		message.show2()
		messages.append(message)

		message=IP(src=VIRLGWIP, dst=VIRLExternalIPAdress)/GRE()/IP(src='10.0.0.1', dst='10.0.0.4')/OSPF_Hdr(src='10.0.2.1')/OSPF_LSUpd(lsalist=[OSPF_Router_LSA(linklist=[], adrouter='10.0.0.4', linkcount=0, id='10.0.0.4', seq=seqToInitialize[4])])
		message.show2()
		messages.append(message)

		message=IP(src=VIRLGWIP, dst=VIRLExternalIPAdress)/GRE()/IP(src='10.0.1.1',dst='10.0.1.2')/OSPF_Hdr(src='10.0.2.1')/OSPF_LSUpd(lsalist=[OSPF_Router_LSA(linklist=[], adrouter='10.0.1.2', linkcount=0, id='10.0.1.2', seq=seqToInitialize[2])])
		message.show2()
		messages.append(message)

		message=IP(src=VIRLGWIP, dst=VIRLExternalIPAdress)/GRE()/IP(src='10.0.0.1',dst='10.0.0.4')/OSPF_Hdr(src='10.0.2.1')/OSPF_LSUpd(lsalist=[OSPF_Router_LSA(linklist=[], adrouter='10.0.2.10', linkcount=0, id='10.0.2.10', seq=seqToInitialize[0])])
		message.show2()
		messages.append(message)

		send(messages)
		time.sleep(80)
		

		# check that th router doesn't get stuck
		LSADB = {}
		for r in controlport:
			sys.stderr.write('Fetch ' + r + '\n')
			tn = telnetlib.Telnet(LXCIP, controlport[r])
			LoginToRouter(r, tn)
			CLIoutput = ""
			for lsatype in ["router", "network"]:
				#print "XXXXXXXXXXXXfetch" + lsatype 
				tn.write("show ip ospf database %s \n\r" % lsatype )
				CLIoutput += tn.read_until("#")
				tn.read_very_eager()
			#print "*******************" + str(r) + "**************"
			#print CLIoutput
			#print "--------------------------------------------"
			LSADB[r] = ParseCLIoutput(CLIoutput,globals)
			tn.close()
		

		'''	
	  	LSADB = {}
	  	r='0'
	  	tn = telnetlib.Telnet("localhost", controlport[r])
		tn.write("\n")
	  	tn.read_until("cdsfsf", 0.5) #can be any string
	  	tn.set_debuglevel(10)
	  	tn.write("\nen\n\r")
	  	tn.read_until("#", 1)
	  	tn.write("\nterminal length 0"+"\n\r")
	  	tn.read_until("#", 1)  
	  	CLIoutput = ""
	  	for lsatype in ["router", "network"]:
	  		tn.write("\nshow ip ospf database %s \n\r" % lsatype )
	  		CLIoutput += tn.read_until("#")
	  	LSADB[r] = ParseCLIoutput(CLIoutput, globals)
	  	tn.close()
		'''
	  	rLSDBcisco = LSADB[r]
	  	for lsa in rLSDBcisco:
	  		if  lsa.type == 1 and lsa.adrouter== '10.0.2.1' and lsa.seq != seqToInitialize[1]+1:
	  			#assert False
	  			print "seq of r1 is " +  str(lsa.seq) + " and should be initialized to " + str(seqToInitialize[1]+1)
	  			globals.useNewReload = True
	  			globals.repeatTest = True
	  			raise Exception('initializeSeqNumbers - stuck router')	  			
	  	return 	

	except:
		raise		 
	


		
def CompareDB(DBmodel, DBcisco, isFinalComparison,mapMatchingLSAs,seqChecker):	
	
	try:
	
		comparisonResults = {}
		for r in controlport:
			print "--------------------------------------------"
			print "comparing model LSDB with cisco LSDB for r" + str(r)
			comparisonResults[r] = True
			if not (r in mapMatchingLSAs):
				mapMatchingLSAs[r] = {}

			print 'keys of DBmodel:'
			for key in DBmodel:
				print key

			print 'r is:'
			print r
			
			rLSDBmodel_orig = DBmodel[r]
			rLSDBcisco_orig = DBcisco[r]
			
			rLSDBmodel = list()
			for lsa in rLSDBmodel_orig:
				if lsa.type == 1:
					rLSDBmodel.append(lsa)
					
			rLSDBcisco = list()
			for lsa in rLSDBcisco_orig:
				if lsa.type == 1:
					rLSDBcisco.append(lsa)		
			
			if len(rLSDBmodel) != len(rLSDBcisco):
				print "number of LSAs is different"
				comparisonResults[r] = False
				print 'DBmodel len = ' + str(len(rLSDBmodel)) + ' ,DBcisco len =' +  str(len(rLSDBcisco))
				continue
				
			#check that each LSA in the db model has a matching LSA in the db cisco 	
			for modelLsa in rLSDBmodel:
				debug.Print( "#################################################")
				debug.Print( "model LSA to search for a match:")
				if debug.isActivated:
					modelLsa.show()
				
				found = False
				
				if modelLsa.type==1: #TOOD --- currently adding only router LSAs 
					lsaString = getLSAString(modelLsa)			
					if lsaString in mapMatchingLSAs[r]:
						mapMatchingLSAs[r][lsaString].append(modelLsa)
					else:
						mapMatchingLSAs[r][lsaString]=list()
						mapMatchingLSAs[r][lsaString].append(modelLsa)
						
				for lsa in rLSDBcisco:
					if modelLsa.type==2 and lsa.type == 2 and modelLsa.adrouter == lsa.adrouter :
						debug.Print( "found matching network LSA --verifying other fields")
						found = True						
						#mapMatchingLSAs[r][lsaString].append(lsa)  #add the matching lsa
						if debug.isActivated:
							lsa.show()
							
						if modelLsa.id != lsa.id:
							print "different lsid"
							print modelLsa.id, lsa.id
							comparisonResults[r] = False
						#compare routerlist
						s1 = set(lsa.routerlist)
						s2 = set(modelLsa.routerlist)
						if  not (s1.issubset(s2) and s2.issubset(s1)):
							print "different routerlist"
							print modelLsa.routerlist, lsa.routerlist
							comparisonResults[r] = False
						
						
					elif modelLsa.adrouter == lsa.adrouter and modelLsa.type==lsa.type and modelLsa.id == lsa.id:
						found=True
						mapMatchingLSAs[r][lsaString].append(lsa) #add the matching lsa
						debug.Print ("matching router LSA found on cisco DB --verifying other fields")
						if debug.isActivated:
							lsa.show()
						debug.Print( "checking gaps between 2 LSAs *******************")
						#start the comparison
	
						# if modelLsa.linkcount != lsa.linkcount:
							# print "different linkcount"
							# print modelLsa.linkcount, lsa.linkcount
	
						#compare link list 	--- check that each model link has a matching cisco link
						for modelLink in modelLsa.linklist:
							foundLink=False
							linkType = modelLink.type
							for link in lsa.linklist:								
								if modelLink.id == link.id and modelLink.data == link.data and modelLink.type == link.type and modelLink.metric == link.metric:
									foundLink=True
									debug.Print( "found matching link")
							#silently ignore for now......		
							if 	foundLink==False:
								print "no matching link found"
								print 'link type: ' + str(linkType)
								#currently, if it is a stub link - don't consider it as failure
								if linkType != 'stub' and linkType!=3:
									comparisonResults[r] = False
									modelLink.show()
								else:
									print "stub link --- ignoring..."									
						debug.Print ("finished gaps check *******************")		
						
						
				if found==False:
					print "no matching LSA found"
					modelLsa.show()
					comparisonResults[r] = False
		
	
	
		
		res3 = True
		if isFinalComparison: #compare the expected sequnce numbers at the end w.r.t. the initial ones
			print "comparing sequence numbers of LSAs"		
			res3 = seqChecker.compare_results(globals)
			if(not res3):
				debug.Print("error in seq num check")
			 
			
	
		
		print "finished comparison"
		print comparisonResults
		for k in comparisonResults:
			if comparisonResults[k]==False:
				return False
		return res3
	
	except:
		raise
	
	
	
def getLSAString(lsa):	
	return str(lsa.type) + ';' + str(lsa.id) + ';' + str(lsa.adrouter)
	

def isDBCiscoComplete(db):	
	for r in controlport:
		if len(db[r])==0:
			return False
	return True	



def readroute(l, current_router):
	rt = {}
	r = re.compile(',')
	parts = r.split(l)
	#print parts, len(parts)
	if len(parts) < 5:
		return None
		
	destType = 'destType'
	destID = 'destID'
	cost = 'cost'
	nextHop = 'nextHop'
	nextHopID = 'nexthopID'
	interface = 'interface'
	interfacevalue = None
	destIDvalue = None
		
	for p in parts:
		#print p
		ivalue = p.find('=')
		if ivalue == -1:
			break
		value = str(p[p.find('=')+1:]).strip()
		#print value

		if destType in p:
			if value == 'network':
				#print "network type mask=24"
				rt['mask'] = 24
			elif value == 'stub':
				#print "stub type mask=24"
				rt['mask'] = 24
			else:
				print "unrecognised " + destType + " " + value
		elif destID in p:
			destIDvalue = value
			#print "destIDvalue is " + str(destIDvalue)
			if interfacevalue != None:
				rt['ip'] = routerip[destIDvalue][interfacevalue][0]
				#print "destID is " + rt['ip']
		elif interface in p:
			interfacevalue = value
			#print "interfacevalue is " + str(interfacevalue)
			if destIDvalue != None:
				rt['ip'] = routerip[destIDvalue][interfacevalue][0]
				#print "destID is " + rt['ip']
		elif cost in p:
			rt['cost'] = int(value)
			#print "cost", rt['cost']
		elif nextHop in p:
			rt['nexthop'] = routerip[current_router][value.strip().strip('[]')][1]
			#print "nextHop", routerip[current_router][rt['nextHop']][1]
		elif nextHopID in p:
			rt['nexthopID'] = value.strip().strip('[]')
			#print "nextHopID", rt['nextHopID']
	return rt

def ReadModelRoute(Routelines):
	RT = {}
	r = '-1'
	for l in Routelines:
		#print l
		index = l.find('RT')
		if index != -1: #New router
			r = l[index+len('RT')]
			#print "********* Reading routing table of R" + str(r)
			RT[r] = list()
			continue	
		else: #New route
			rt = readroute(l, r)
			if rt == None:
				continue
			#print lsa.summary()
			RT[r].append(rt)
	return RT

'''	
def CompareRT(ModelRT, CiscoRT):
	for r in CiscoRT:
		if r not in ModelRT:
			print "Router " + r + " not found in the model."
			return False
		for CiscoEntry in CiscoRT[r]:
			#find the corresponding entry in the model
			print "Finding a match for a Cisco entry"
			print CiscoEntry
			FoundMatch = False
			for ModelEntry in ModelRT[r]:
				if ipaddress.IPv4Interface(ModelEntry["ip"]+"/"+str(ModelEntry["mask"])).network == ipaddress.IPv4Interface(CiscoEntry["ip"]+"/"+str(ModelEntry["mask"])).network:
					print "Candidate match in Model"
					print ModelEntry
					#CiscoEntry["cost"] == ModelEntry["cost"] and
					if  CiscoEntry["nexthop"] == ModelEntry["nexthop"]:
						nexthopID_match = False
						for interface in routerip[ModelEntry["nexthopID"]]:
							#print routerip[ModelEntry["nexthopID"]][interface][0]
							if CiscoEntry["nexthopID"] == routerip[ModelEntry["nexthopID"]][interface][0]:
								print "Found a match!"
								nexthopID_match = True
								break
						if nexthopID_match == True:
							FoundMatch = True
							break
						else:
							print "failed on nexthopID"
							break
					else:
						print "failed on cost or nextHop"
						break
			if FoundMatch == False:
				return False
		
	#make sure there is no superfluous routers in the model
	if len(ModelRT) != len(CiscoRT):
		return False
'''		

def GetVIRLSimulationID():
	GET_SIMULATIONID_URL = "http://%s:19399/simengine/rest/list" % (VIRLHostIP)
	resp = requests.get(GET_SIMULATIONID_URL, auth=(VIRLUserName, VIRLPassword))
	if resp.status_code != 200:
		print "GetVIRLSimulationID: retruned code %d." % (resp.status_code)
		return None
	j = resp.json()
	if len(j['simulations']) == 0:
		print "GetVIRLSimulationID: no active simulation."
		return None
	ids = list()
	for id in j['simulations']:
		if id != "~jumphost":
			ids.append(id)
	if len(ids) > 1:
		print "Found more than one active simulations."
		i = 1
		for id in ids:
			print "%d. %s" % (i,id)
			i = i + 1
		choice = int(raw_input('Choose simulation: '))
		return ids[choice-1]
	else:
		return ids[0]



def GetVIRLExternalInterfaces(SimulationID, ExternalRouter):
	GET_INTERFACES_URL = "http://%s:19399/simengine/rest/interfaces/%s" % (VIRLHostIP, SimulationID)
	#payload   = {'nodes': ExternalRouter}
	resp = requests.get(GET_INTERFACES_URL, auth=(VIRLUserName, VIRLPassword))
	if resp.status_code != 200:
		print "GetVIRLExternalInterface: retruned code %d." % (resp.status_code)
		return None
	j = resp.json()	
	DataExternalInterface = None
	interfaces = j[SimulationID][ExternalRouter]
	for inf in interfaces:
		if interfaces[inf]['external-ip-address'] != None:
			DataExternalInterface  = interfaces[inf]['external-ip-address'].split('/')[0]
			break
	LXCExternalInterface = None
	interfaces = j[SimulationID][LXCName]
	for inf in interfaces:
		if interfaces[inf]['external-ip-address'] != None:
			LXCExternalInterface  = interfaces[inf]['external-ip-address'].split('/')[0]
			break
	if DataExternalInterface == None:
		print "GetVIRLExternalInterface: No extrenal interface found for %s." % (ExternalRouter)
	if LXCExternalInterface == None:
		print "GetVIRLExternalInterface: No extrenal interface found for %s." % (LXCName)
	return DataExternalInterface, LXCExternalInterface

#Just to make a Telnet connection to all routers and exit. Somehow Telnetlib does not work otherwise.	
def InitTelnet2Routers():
	for r in controlport:
		sys.stdout.write("%s " % (r))
		sys.stdout.flush()
		t = pexpect.spawn('telnet %s %s' % (LXCIP,str(controlport[r])))
		t.send("\r\n\r\n")
		t.expect([">","#"])
		t.close()


def applyTest(globals, fullpath):
	try:
		seqChecker =  seqNumChecker(fullpath)

		#reload routers
		sys.stderr.write(fullpath + '\n')
		print fullpath
		ReloadGNS3()
		time.sleep(60)
		#=======================================================================
		'''		
		if not globals.useNewReload:
			ReloadGNS3()
			time.sleep(60)			
		else:	
			ReloadGNS3_new(VIRLSimulationID)
			time.sleep(60)
			#time.sleep(180)
			globals.useNewReload = False
		'''	
		
		#=======================================================================
		#fetch and compare initial LSA DB state
		
		#fetching cisco LSDB first, since DR value is extracted from there, and then used in the model LSDB accordingly
		#log_db_status[0]+= 'fetching cisco DB after GNS3 reload'
		print "fetching cisco LSDB"
		print "**************************************"
		InitialDBcisco = FetchCiscoLSDB(globals)
		isOK = isDBCiscoComplete(InitialDBcisco)
		
		#while(len(InitialDBcisco)==0):
		while(not isOK):
			time.sleep(60)
			InitialDBcisco = FetchCiscoLSDB(globals)
			isOK = isDBCiscoComplete(InitialDBcisco)
			
		initializeSeqNumbers(seqChecker,  InitialDBcisco, globals)
		#sys.stderr.write('exiting\n')
		
		time.sleep(60)
		#log_db_status[0]+= 'fetching cisco DB after initializeSeqNumbers'
		
		print "fetching cisco LSDB"
		print "**************************************"
		InitialDBcisco = FetchCiscoLSDB(globals)
		
	
		
		
		print "fetching model LSDB"
		print "**************************************"
		InitialDBlines = findsection(InitialLSDBSection, fullpath)
		InitialDBmodel = ReadModelLSDB(InitialDBlines,seqChecker,globals)
		
		res1 = CompareDB(InitialDBmodel, InitialDBcisco, False,globals.mapMatchingLSAsInitial,seqChecker)
		
		if not (res1):
			#failedTests.append(f)
			sys.stderr.write('failed on initial comparison\n')		
			globals.useNewReload = True
			globals.repeatTest = True
			#copyfile('out.txt', 'out_' + str(testIndex)+'.txt')	
			#with open("log_db_state", "a") as f:
			#	f.write(log_db_status[0])    			
			#sys.stderr.write('exit...')
			#sys.exit()
	
			
			return False
			
		
		#Send test messages		
		#messages = runtest(fullpath,mapMatchingLSAsInitial,seqChecker,M_seq,might_fail_due_to_chksum_issue)
		messages = runtest(fullpath,globals,seqChecker)	
		#sendp(messages, iface="tap0")
		




		msgs_counter = 0	
			
		#per each msg - send it, wait for stable state, and compare expected states	
		for m in messages:
			#sendp(m, iface="tap0")
			send(m)
			sys.stderr.write('sent msg\n')
			#time.sleep(1)	
		
			time.sleep(120)
			
		
			#fetch and compare output LSA DB state
			print "fetching model LSDB"
			print "**************************************"
			OutputDBlines = findsection(OutputLSDBSection[msgs_counter], fullpath)
			OutputDBmodel = ReadModelLSDB(OutputDBlines,seqChecker,globals)
			
			msgs_counter+=1			
			#sys.exit()
			
			#log_db_status[0]+= 'fetching cisco DB after sending test message'
			print "fetching cisco LSDB"
			print "**************************************"
			OutputDBcisco = FetchCiscoLSDB(globals)
			
			res2 = CompareDB(OutputDBmodel, OutputDBcisco, True,globals.mapMatchingLSAsFinal,seqChecker)
			
			
			#prepare for next iteration
			globals.M_index+=1
			globals.mapMatchingLSAsFinal = {}
			
			#sys.stderr.write('might_fail_due_to_chksum_issue = ' + str(might_fail_due_to_chksum_issue[0]))
			if not(res1 and res2):
				#test failed
				#failedTests.append(f)
				
				#copyfile('out.txt', 'out_' + str(testIndex)+'.txt')
				if(globals.might_fail_due_to_chksum_issue[0] ):
					#sys.stderr.write('might_fail_due_to_chksum_issue\n')
					print "test passed"
					sys.stderr.write('passed\n')
					return True
				elif(globals.foundDuplicateRID):
					sys.stderr.write('found duplicate RID\n')	
					sys.stderr.write('failed\n')		
				else:
					sys.stderr.write('failed\n')		
				#else:
					#with open("log_db_state", "a") as f:
					#	f.write(log_db_status[0])    		
					#sys.stderr.write('exit...')
					
				return False
			

		print "test passed"
		sys.stderr.write('passed\n')
		return True		

	except  Exception as inst:  
		#failedTests.append(f)
		sys.stderr.write('failed due to exception\n')
		globals.useNewReload = True
		globals.repeatTest = True
		#sys.stderr.write(inst)	
		print(inst)			
		raise
		#pass		
		return False
				


#begin tests



print "Getting VIRL simulation ID"
VIRLSimulationID = GetVIRLSimulationID()
if VIRLSimulationID == None:
	sys.exit(1)	
print VIRLSimulationID
print "Getting VIRL extrenal IP address"
VIRLExternalIPAdress, LXCIP = GetVIRLExternalInterfaces(VIRLSimulationID, ExternalRouter)
if VIRLExternalIPAdress == None:
	sys.exit(1)	
print VIRLExternalIPAdress
print LXCIP
print "Initializing Telnet connections...."
InitTelnet2Routers()




globals = Globals()

testsToRun = []

if len(sys.argv) > 1:
	testsToRun = sys.argv
	del testsToRun[0]
	
'''
for x in range(7,21):
	testsToRun.append(('test'+str(x)+'.txt'))
for x in range(22,25):
	testsToRun.append(('test'+str(x)+'.txt'))	
'''	
print "tests to run " 
print testsToRun
	
	
	
failedTests = list()
numOfTests =  len([name for name in os.listdir(testsdir) if os.path.isfile(os.path.join(testsdir,name))])

minTestIndex = 0
	

#main tests loop 	
for testIndex in range(minTestIndex,numOfTests):
	f = 'test' + str(testIndex) + '.txt'	
	fullpath = os.path.join(testsdir,f)	
	if (not os.path.isfile(fullpath)) :# or ("test4.txt" not in f):
		continue
	currfile = 	fullpath.split("/")
	if len(testsToRun)>0  and  currfile[len(currfile)-1] not in testsToRun:
		continue
	print "run " + str(fullpath)
	'''
	if os.path.isfile('out.txt'): 
		os.remove('out.txt')
	sys.stdout = open('out.txt', 'w')	
	'''
	outName = 'out' + str(testIndex) + '.txt'
	if os.path.isfile(outName): 
		os.remove(outName)
	sys.stdout = open(outName, 'w')	
	
	
	res = applyTest(globals, fullpath)
	
	if globals.repeatTest :
		globals.clean()
		res = applyTest(globals, fullpath)
		globals.repeatTest = False
		
	if not res:
		failedTests.append(f)
		
		
		
	globals.clean()
	

	#os.remove('out.txt')
	sys.stdout = sys.__stdout__
	
	

	
print "list of failed tests:"		
print 	failedTests
