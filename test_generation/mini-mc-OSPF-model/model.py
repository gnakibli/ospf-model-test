from mc import *
import sys
from logger import Logger
from logger import OutLogger
import re
import shutil
#from configurationManager import  * 



from Tkinter import *
master = Tk()


Label(master, text="Choose options :").grid(row=0, sticky=W)
isDebugPrintOn = IntVar()
Checkbutton(master, text="apply debug print", variable=isDebugPrintOn).grid(row=1, sticky=W)

Label(master, text="Choose symbolic vars :").grid(row=2, sticky=W)
seqVarOn = IntVar()
Checkbutton(master, text="seq", variable=seqVarOn).grid(row=3, sticky=W)
destVarOn = IntVar()
Checkbutton(master, text="dest", variable=destVarOn).grid(row=4, sticky=W)
ARvarOn = IntVar()
lsidVarOn = IntVar()
chksumVarOn = IntVar()
Checkbutton(master, text="AR", variable=ARvarOn).grid(row=5, sticky=W)
Checkbutton(master, text="lsid", variable=lsidVarOn).grid(row=6, sticky=W)
Checkbutton(master, text="chksum", variable=chksumVarOn).grid(row=7, sticky=W)

useSymbolicnitialSeqNumbers=IntVar()
Checkbutton(master, text="use symbolic initial seq nums", variable=useSymbolicnitialSeqNumbers).grid(row=8, sticky=W)


Label(master, text="num of msgs:").grid(row=9)
e1 = Entry(master)
e1.insert(10, '1')
e1.grid(row=10, sticky=W)


runOriginal = IntVar()
Checkbutton(master, text="run original model ref w/o fixes", variable=runOriginal).grid(row=11, sticky=W)

Button(master, text='OK', command=master.quit).grid(row=12, sticky=W, pady=4)

mainloop()
   
#----------------------------------------------------------------------------------------        


dest_router = 1

MINLSINTERVAL = 2
m_routers_num = 5
attacker = 0
min_counter=10
loop_bound=15
maxSequenceNumber = 7
isRunOriginal = (runOriginal.get()==1)


class Age:
    max = 1
    not_max = 0
    
#linkType : 'p2p', 'transit', 'stub'    

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
if isDebugPrintOn.get()==1:
    debug.Activate()


totalMsgs = int(e1.get())
debug.Print( "totalMsgs " + str(totalMsgs))

msg_symbolic_params = []
mapSymbolicVarsOn = {}
domains = []
initialVals = []

symbolicVarIndex=0
if seqVarOn.get()==1:
    mapSymbolicVarsOn["seq"]=symbolicVarIndex
    msg_symbolic_params.append("seq")
    symbolicVarIndex+=1
    #domains["seq"] = (0,maxSequenceNumber)
    domains.append((0,maxSequenceNumber))
    initialVals.append(0)
if destVarOn.get()==1:
    mapSymbolicVarsOn["dest"]=symbolicVarIndex
    msg_symbolic_params.append("dest")
    symbolicVarIndex+=1     
    #domains["dest"] = (1,4)
    domains.append((1,4))
    initialVals.append(1)
if ARvarOn.get()==1:
    mapSymbolicVarsOn["AR"]=symbolicVarIndex
    msg_symbolic_params.append("AR")
    symbolicVarIndex+=1   
    #domains["AR"] = (0,5)
    domains.append((0,4))
    initialVals.append(0)
if lsidVarOn.get()==1:
    mapSymbolicVarsOn["lsid"]=symbolicVarIndex
    msg_symbolic_params.append("Lsid")
    symbolicVarIndex+=1  
    #domains["LSID"] = (0,5)
    domains.append((0,4))
    initialVals.append(0) 
if chksumVarOn.get()==1:
    mapSymbolicVarsOn["chksum"]=symbolicVarIndex
    msg_symbolic_params.append("chksum")
    symbolicVarIndex+=1   
    #domains["chksum"] = (0,1)
    domains.append((0,1))
    initialVals.append(0)
    
totalSymbolicVars = symbolicVarIndex 



               
class LSA:

    
    
    def __init__(self,interface, src, dest, msg_type, LSID, AR, seqNum, links, isOriginatedByAttacker, isMarked, counter):
        self.interface =  interface
        self.src = src
        self.dest = dest
        self.type = msg_type
        self.LSID = LSID
        self.AR = AR
        self.seqNum=seqNum
        self.links=links        
        self.isOriginatedByAttacker = isOriginatedByAttacker
        self.isMarked=isMarked
        self.counter=counter        
        self.age = Age.not_max
        self.chksum=0
        
    def getLSAString(self):
        if self.type == 'routerLSA':        
            return 'type= routerLSA, AdvertisingRouter= '+ str(self.AR) + ' , LSID= '  + str(self.LSID) + ', sequenceNum= '  + str(self.seqNum) + ', Links= [' + " ".join(x.getLinkString() for x in self.links ) + ']'
        elif self.type == 'networkLSA':
            return 'type= networkLSA, AdvertisingRouter= '+ str(self.AR) + ' , LSID= '  + str(self.LSID) + ', sequenceNum= '  + str(self.seqNum) + ', Links= [' + ";".join(str(x) for x in self.links ) + ']'        
            
        
    def printLSA(self):        
        print (self.getLSAString())
        return
    
    def duplicate(self):        
        m=LSA(self.interface, self.src, self.dest, self.type, self.LSID, self.AR, self.seqNum, self.links, self.isOriginatedByAttacker, self.isMarked, self.counter)
        m.age = self.age
        m.chksum = self.chksum
        return m
        
        


class RoutingTable:
    
    def __init__(self ):
        self.RT = {}
        self.RT1={}
        
    def addEntry(self, destType,destID, pathType, cost, nextHop, nextHopID, interface ):
        self.RT[(destType,destID)] = (pathType,cost, nextHop ,nextHopID, interface )
        self.RT1[(destType,destID)] = (pathType,cost, nextHop ,nextHopID, interface )
    
    def clear(self):
        self.RT = {}
        self.RT1 = {}
        return
    
   
    
    #returns the interface for the next hop
    def getNextHop(self,idr, dest):        
        if idr ==1:
            if dest ==2 :
                return 1
            elif dest==0:
                return 10
            elif dest==3 or dest==4:
                return 100
 
        elif idr==2:
            if dest==1 or dest==3 or dest==4:
                return 2;
             
        elif idr==3:
            if dest==1 or dest==2 or dest==4:
                return 3
 
             
        elif idr==4:    
            if dest==1 or dest==2 or dest==3:
                return 4
 
        return -1
        
        
       
    
    #returns the idr of the next hop 
    def getNextHopID(self,idr, dest): 
        if idr ==1:
            if dest ==2 or dest==3 or dest==4:
                return dest
 
        elif idr==2:
            if dest==1 or dest==3 or dest==4:
                return 1;
             
        elif idr==3:
            if dest==1 or dest==2:
                return 1
            if dest==4:
                return 4
             
        elif idr==4:    
            if dest==1 or dest==2:
                return 1
            if dest==3:
                return 3
         
        return -1
               
   
        
    


class RTEntry:
    def __init__(self,destID,destType, metric,nextHop, nextHopID, interface ):
        self.metric=metric
        self.nextHop=nextHop
        self.destType = destType
        self.destID = destID
        self.nextHopID = nextHopID
        self.interface = interface #DR interface, relevant for network dest



class Router:

    def __init__(self, ID ):
        self.queue = []
        self.DB = []
        self.originalDB = []
        self.ID = ID 
        self.timer = 0                
        self.delayedFB = []
        self.lookup_policy = 0
        self.routingTable = RoutingTable()
    
    
        
    def updateTimer(self):
        if self.timer>0:
            self.timer-=1
        return
    
    def addLSA(self,lsa):
        self.DB.append(lsa)
        return
    
    
  
    
    def flood(self,m,topology):        
        debug.Print("flood function ---self.ID=  " + str(self.ID) + " src = " + str(m.src))
        src = m.src
        m.src = self.ID
        rlinks = topology.links[self.ID]
        for l in rlinks:
            if (src == l.linkID and  l.linkType!='transit') or l.linkType=='stub':
                debug.Print('continue')
                continue
            if (self.ID==3 and src==1):
                continue
            if (self.ID==4 and src==1):
                continue
            if l.linkID==self.ID and l.linkType=='transit': 
                debug.Print('transit link')
                for n in topology.transitNetworks:
                    if n[1]==self.ID:
                        index=0
                        for rID in n[0]:
                            if rID == self.ID : 
                                index+=1
                                continue
                            m2=m.duplicate()
                            m2.dest = rID
                            m2.interface = n[4][index]
                            topology.routers[m2.dest].queue.append(m2)
                            debug.Print("flood to " + str(m2.dest) + "  at interface " + str(m2.interface) + ", seq = " + str(m2.seqNum)  + ", age = " + str(m2.age))                            
                            index+=1
                    else :  
                        m2 = m.duplicate()
                        m2.dest = n[1]
                        m2.interface = n[2]
                        topology.routers[m2.dest].queue.append(m2)
                        debug.Print("flood to " + str(m2.dest) + "  at interface " + str(m2.interface) + ", seq = " + str(m2.seqNum)  + ", age = " + str(m2.age))
                        
                                
                            
            else:
                m2=m.duplicate()
                m2.dest = l.linkID
                m2.interface = topology.getLinkInterface(m2.dest,self.ID)
                topology.routers[m2.dest].queue.append(m2)
                debug.Print("flood to " + str(m2.dest) + "  at interface " + str(m2.interface) + ", seq = " + str(m2.seqNum)  + ", age = " + str(m2.age)) 
                
                
        if self.ID==3:            
            m2 = m.duplicate()
            m2.dest = 4    
            m2.interface = 4
            topology.routers[m2.dest].queue.append(m2)
            debug.Print("flood to " + str(m2.dest) + "  at interface " + str(m2.interface) + ", seq = " + str(m2.seqNum)  + ", age = " + str(m2.age))    


        if self.ID==4:            
            m2 = m.duplicate()
            m2.dest = 3    
            m2.interface = 3
            topology.routers[m2.dest].queue.append(m2)
            debug.Print("flood to " + str(m2.dest) + "  at interface " + str(m2.interface) + ", seq = " + str(m2.seqNum)  + ", age = " + str(m2.age))
            
        return


    
    def FB(self,topology):
        
        m = self.delayedFB.pop(0)
        m.src = self.ID
        
        
        self_index=0
        for l in self.DB:
            if l.AR == self.ID and l.LSID == m.LSID and l.type == m.type:
                break
            self_index = self_index+1
        if self.DB[self_index].seqNum < m.seqNum  or (self.DB[self_index].seqNum==maxSequenceNumber and m.seqNum==0  ):    
            self.DB[self_index]=m
        
        rlinks = topology.links[self.ID]
        for l in rlinks:
            
            if l.linkType=='stub':
                continue
            
            if l.linkID==self.ID and l.linkType=='transit': 
                for n in topology.transitNetworks:
                    if n[1]==self.ID:
                        index=0
                        for rID in n[0]:
                            if rID == self.ID:
                                index+=1
                                continue
                            m2=m.duplicate()
                            m2.dest = rID
                            m2.interface = n[4][index]
                            topology.routers[m2.dest].queue.append(m2)
                            debug.Print("FB to " + str(m2.dest) + "  at interface " + str(m2.interface) + ", seq = " + str(m2.seqNum)  + ", age = " + str(m2.age))                                                                            
                            index+=1
                            
            else:
                m2=m.duplicate()
                m2.dest = l.linkID
                m2.interface = topology.getLinkInterface(m2.dest,self.ID)
                topology.routers[m2.dest].queue.append(m2)
                debug.Print("FB to " + str(m2.dest) + "  at interface " + str(m2.interface) + ", seq = " + str(m2.seqNum) + ", age = " + str(m2.age))               
                
                
                
        return
    
    
    
   
    
    def handelLSAMsg(self,m,topology):
        debug.Print("handle LSA msg for r" + str(self.ID))
                

        debug.Print("check src and interface")
        debug.Print("m.src=" + str(m.src) + " self.ID = " + str(self.ID) + " m.interface = "+ str(m.interface))
        if topology.hasLink(m.src, self.ID, m.interface)==False:
            debug.Print("drop m due to non-matching interface and src")                
            return  #drop M
        
        
        should_ignore = m.AR!=m.LSID
        
        if should_ignore:
            debug.Print('ignoring LSA for different LSID and AR')
            return
        
        should_flush = False
        if m.age == Age.max and m.AR != self.ID:
            should_flush = True
                        
        
        
        found = False        
        foundLSA = LSA(-1, -1, 'NA', -1, -1, -1, -1, -1, False, False, 0)        
        prevCounter=0
        prevIsFake=False
        index = 0 #index of the LSA in the DB
        for lsa in self.DB:
            if ( isRunOriginal and lsa.LSID == m.LSID and lsa.AR ==m.AR and lsa.type==m.type ) or (not isRunOriginal and lsa.LSID == m.LSID and lsa.type==m.type ):
                found = True
                foundLSA = lsa                
                prevCounter = lsa.counter
                prevIsFake = lsa.isOriginatedByAttacker 
                break
            index+=1
            
        if found==False and should_flush:
            debug.Print("LSA not found and should be flushed")
            return
        
        isNewerInstance = False
        if  foundLSA.seqNum < m.seqNum:
            isNewerInstance = True
        elif foundLSA.seqNum == m.seqNum :
            if cmp(m.links,foundLSA.links)!=0:
                if m.chksum==1:
                    debug.Print("chksum considers LSA newer")
                    isNewerInstance = True   
                else:    
                    debug.Print("chksum considers LSA older")
        if isNewerInstance:
            debug.Print("LSA is considered newer instance")
        else:
            debug.Print("LSA is considered older instance")        
            
            
        if found==True and should_flush:

            self.flood(m,topology)
            del self.DB[index]
            debug.Print("flush LSA from DB")
        

        

        elif (found==False or ((found==True) and isNewerInstance)) and (not should_flush) : 
            
                        
            
            if found==False and m.AR != self.ID:                 
                self.DB.append(m)  
                self.flood(m,topology)
            
                
            if m.AR == self.ID :
                
                for lsa in self.DB:
                    if lsa.AR==self.ID and lsa.age==1:                 
                        return

                                
                LSID = -1
                links = []
                for L in self.originalDB:
                    if L.AR == self.ID and L.type == m.type:
                        LSID = L.LSID
                        links = L.links
                
                self.timer = MINLSINTERVAL
               
               
                new_seq_num = m.seqNum+1
               
                if m.seqNum == maxSequenceNumber-1 or  m.seqNum == maxSequenceNumber  :
               
                    FlushingLSA = LSA(-1,-1,-1, m.type, m.AR, m.AR, maxSequenceNumber, links, False, False, 0)
                    FlushingLSA.age = Age.max
                    
               
                    debug.Print("push flushing LSA")
                    self.delayedFB.append(FlushingLSA)
                    for lsa in self.DB:
                            if lsa.AR==self.ID and lsa.type==m.type and lsa.LSID==self.ID:
                                lsa.seqNum = maxSequenceNumber
                                lsa.age = Age.max
                    
                     
                    new_seq_num = 0
                    
                
                if (isRunOriginal or new_seq_num>0 or (self.ID!= 1000)):                     
                    FBM = LSA(-1,-1,-1, m.type, m.AR, m.AR, new_seq_num, links, False, False, 0)
                    self_index=0
                    for l in self.DB:
                        if l.AR == self.ID and l.LSID == self.ID and l.type == m.type:
                            break
                        self_index = self_index+1
                
                
                    
                    self.delayedFB.append(FBM)
                    
                    
                    if(self.DB[self_index].age==0 and self.DB[self_index].seqNum <= FBM.seqNum): 
                        self.DB[self_index]=FBM
                        debug.Print("no re-update the FB msg ")                                
                    elif self.DB[self_index].age==0:  
                        debug.Print( "self DB seq num is " + str(self.DB[self_index].seqNum) + " , and prev FB seq is : " + str(FBM.seqNum))
                        debug.Print("re-update the FB msg ")
                        new_FBM = LSA(-1,-1,-1, m.type, m.AR, m.AR, self.DB[self_index].seqNum+1, links, False, False, 0)
                        self.delayedFB.append(new_FBM)
                        
                        
                    
                        
                        
            
            else:
                if prevIsFake and m.isOriginatedByAttacker: 
                    m.counter=prevCounter
                    m.counter=0         
                           
                self.DB[index]=m 
                if found:
                    self.flood(m,topology) 
                
                
                

        
        return
    
    

    
    def processRouterMessage(self,topology):
               
        for lsa in self.DB:
            if lsa.isOriginatedByAttacker :
                lsa.counter = lsa.counter+1
        
        
        if len(self.queue) >0 :
            m = self.queue.pop(0)
            debug.Print("process router msg for r" + str(self.ID))
            debug.Print(m.getLSAString())           
            
            if m.dest != self.ID :           
                nextHopInterface = self.routingTable.getNextHop(self.ID, m.dest)
                if(nextHopInterface!= -1):
                    nextHopID = self.routingTable.getNextHopID(self.ID, m.dest)
                    m.interface = topology.getLinkInterface(nextHopID,self.ID)
                    topology.routers[nextHopID].queue.append(m)
                    debug.Print(str(self.ID) + " forward to " + str(nextHopID) + "  at interface " + str(m.interface) + ", seq = " + str(m.seqNum)  + ", age = " + str(m.age))                    
                else:
                    debug.Print("issue with next hop interface")  
                    debug.Print("nextHopInterface = "+str(nextHopInterface))
                    debug.Print("m.dest=" + str(m.dest))
                    
                    

            else:                              
                self.handelLSAMsg(m,topology)
    
        if self.timer==0 and  len(self.delayedFB)>0 :   
            self.FB(topology)
            self.timer = MINLSINTERVAL


            
        return            
    
    
    
    def printLSADB(self):
        for lsa in self.DB:
            lsa.printLSA()
        return
    
    def getLSDBString(self):
        st = ""
        for lsa in self.DB:
            st = st + '(' + lsa.getLSAString() + ')'
        return st     
                    
                
                


class RouterLink:
    #structure of each link: #(linkID, linkType, metric,  linkData )  
    def __init__(self,linkID, linkType, metric,  linkData):
        self.linkID = linkID
        self.linkType = linkType
        self.metric = metric
        self.linkData = linkData
    def getLinkString(self):
        return '(' + 'linkID=' + str(self.linkID) + '; linkType=' + self.linkType + '; linkData=' + str(self.linkData) + '; metric= ' + str(self.metric) + ')'     
    def printLink(self):
        print self.getLinkString()        
            


class Topology:
    #describes the links between routers: types, interfaces
    def __init__(self, routers):
        self.routers = routers
        self.transitNetworks=[]     #for network LSAs
        self.links={}  #maps for each router its list of routerLinks  #structure of each link: #(linkID, linkType, metric,  linkData )      #for router LSAs
        
    def addTransitNetwork(self, network_routers, DR, DR_interface, metric ,routers_interfaces ):
        self.transitNetworks.append((network_routers, DR, DR_interface, metric ,routers_interfaces))
        index=0
        for rID in network_routers:  #add the links of the routers to the transit network
            r_link = RouterLink(DR,'transit', metric,routers_interfaces[index])
            rlinks=[]
            if rID in self.links:
                rlinks= self.links[rID]
            rlinks.append( r_link  ) #(linkID, linkType, metric,  linkData )    
            self.links[rID]=rlinks
            index+=1    
        return 
        
    # adding a p2p link + stub link    
    def addLink(self, routerAID, routerBID, interfaceA, interfaceB, linkType, metric):
        Alink = RouterLink(routerBID,linkType, metric,interfaceA)
        Blink = RouterLink(routerAID,linkType, metric,interfaceB)
        if routerAID in self.links:
            self.links[routerAID].append(Alink)
        else:
            self.links[routerAID] = [Alink]    
        if routerBID in self.links:
            self.links[routerBID].append(Blink)
        else:
            self.links[routerBID] = [Blink]
        Alink1 = RouterLink(routerBID,'stub', metric,interfaceA)
        Blink1 = RouterLink(routerAID,'stub', metric,interfaceB)
        self.links[routerAID].append(Alink1)
        self.links[routerBID].append(Blink1)

    
    def printTopology(self):
        for elem in self.links:
            print "links of router " + str(elem)
            for l in self.links[elem]:
                l.printLink()
        return
    
    
    def setLookupPloicy(self, p):
        for r in self.routers:
            r.lookup_policy = p
        return
    
    '''
    def calcRoutingTables(self):
        for r in self.routers:
            r.calcRoutingTable(self)
    '''        
            
         
    
    def initializeDBs(self, arr):
        for r in self.routers:  #add the router LSAs
            #src, dest, msg_type, LSID, AR, seqNum, (linkID, linkData(interface), linkType), , isOriginatedByAttacker, isMarked, counter
            r_links=[]
            r_links2=[]
            seq = arr[r.ID]
            if r.ID in self.links:
                r_links = self.links[r.ID]
                r_links2=self.links[r.ID]                      
            lsa1 = LSA(-1,'NA','NA','routerLSA',r.ID ,r.ID ,seq , r_links, False,True,0)            
            lsa2 = LSA(-1,'NA','NA','routerLSA',r.ID ,r.ID ,seq , r_links2, False,True,0)
            for r2 in self.routers:
                r2.addLSA(lsa1)
                r2.originalDB.append(lsa2)
                
                
        for n in self.transitNetworks: #add the network LSAs
            #src, dest, msg_type, LSID=DR_interface, AR=DR, seqNum, network_routers_list, , isOriginatedByAttacker, isMarked, counter
            #n = (network_routers, DR, DR_interface, metric ,routers_interfaces)
            lsa1 = LSA(-1,'NA','NA','networkLSA',n[1] ,n[1] ,0 , n[0], False,True,0)
            lsa2 = LSA(-1,'NA','NA','networkLSA',n[1] ,n[1] ,0 , n[0], False,True,0)                        
            for r2 in self.routers:
                r2.addLSA(lsa1)     
                r2.originalDB.append(lsa2)
        
        return 
    

    
    def printLSADBs(self):
        for r in self.routers:
            #print "database of r" + str(r.ID)
            print "LSDB" + str(r.ID) + ":"
            r.printLSADB()        
        return
    
    def hasLink(self, To, From, interface):
        for l in self.links[From]:  #(linkID, linkType, metric,  linkData )  
            if l.linkID == To and l.linkData==interface:
                return True
            elif l.linkType=='transit' :# and l.linkID==From:
                for n in self.transitNetworks:
                    #if n[1]==From and To in n[0]:
                    if From in n[0] and To in n[0]:
                        for ind in range(len(n[0])):
                            if n[0][ind] == From and n[4][ind]==interface:
                                return True
        return False
    
    def getLinkInterface(self,From,To):
        for l in self.links[From]:  #(linkID, linkType, metric,  linkData )  
            if l.linkID == To :
                return l.linkData
            elif l.linkType=='transit' :#and l.linkID==From:                
                for n in self.transitNetworks:
                    if To in n[0]:
                        for ind in range(len(n[0])):
                            if n[0][ind]==From:
                                return n[4][ind]

        return -1
    
    
    

#input param s : array of symbolic vars  
def runModel(s): #Array params: s[0] = seq, s[1] = 
    
    #msg_symbolic_params=[]
     
    s_index=0
    print "symbolic vals represent:"
    for i in range(totalMsgs):
        for j in range(len(msg_symbolic_params)):
            print "s["+str(s_index)+"] => " + "M" + str(i) + ":" +   msg_symbolic_params[j]
            s_index+=1
    if  useSymbolicnitialSeqNumbers.get()==1:       
        for r in range(m_routers_num):
            print  "s["+str(s_index)+"] => initial_seq_of_LSA_by r" +str(r) 
            s_index+=1
    
    print('end symbolic vars info')
    
    atackerRouter = Router(0)
    victimRouter = Router(1)
    t = Topology([atackerRouter, victimRouter,Router(2), Router(3), Router(4)])
    #addLink(self, routerA, routerB, interfaceA, interfaceB, linkType, metric):
    t.addLink(1, 2, 1, 2, 'p2p', 3) #1-2 p2p
    t.addLink(1, 0, 10, 0, 'p2p', 3) #0-1 p2p    
    #t.addTransitNetwork([1,3,4],3, 3, 5, [100,3,4])
    t.addTransitNetwork([1,3,4],1, 100, 5, [100,3,4])
    #addTransitNetwork(self, network_routers, DR, DR_interface, metric ,routers_interfaces ):
    
    policy = 1
    t.setLookupPloicy(policy)     
    initialSeqNumbers =[0,0,0,0,0] 
    
    if  useSymbolicnitialSeqNumbers.get()==1:
        initialSeqNumbers = s[-m_routers_num:]
    
    t.initializeDBs(initialSeqNumbers)   
    
    #t.calcRoutingTables()
    
    print "#Initial LSDBs:"
    t.printLSADBs()
    print "#-----------------------------------------"
    #print "#Initial Routing Tables:"
    #t.printRoutingTables()
    
  

    
    
    
    fakeMsgs = []
    
    for i in range(totalMsgs):
        #default msg param values
        msgType = 'routerLSA'
        seq= 1 #0
        dest= dest_router #
        AR=  1 #2
        lsid=1
        links=[]
        chksum=0
        interface=10
        src=0
        
        if "seq" in  mapSymbolicVarsOn:
            seq = s[mapSymbolicVarsOn["seq"] + totalSymbolicVars*i]
        if "dest" in  mapSymbolicVarsOn:
            dest = s[mapSymbolicVarsOn["dest"]+ totalSymbolicVars*i]
        if "AR" in  mapSymbolicVarsOn:
            AR = s[mapSymbolicVarsOn["AR"]+ totalSymbolicVars*i]
        if "lsid" in  mapSymbolicVarsOn:
            lsid = s[mapSymbolicVarsOn["lsid"]+ totalSymbolicVars*i]    
        if "chksum" in  mapSymbolicVarsOn:
            chksum = s[mapSymbolicVarsOn["chksum"]+ totalSymbolicVars*i]
            
        if dest == 1:
            src=0
        elif dest==2:
            src=1
        elif dest==3:
            src=1
        elif dest==4:
            src = 1    
    
        src_interface = t.getLinkInterface(src,dest)
        #debug.Print("src interface = " + str(src_interface))              
    

        fakeLSA = LSA(interface,src ,dest ,msgType,lsid,AR,seq,links,True,False,0)
        fakeLSA.chksum = chksum
        fakeMsgs.append(fakeLSA)
       
    
                

   

    print "#-----------------------------------------"
    print "#Messages sent: "

    for k in range(0,loop_bound):
        for r in t.routers:
            r.processRouterMessage(t)
      
        
        if k==0:        
            
            for fakeLSA in fakeMsgs:            
                victimRouter.queue.append(fakeLSA)
                print "src = " + str(src) + ":" + str(src_interface) +   " , dest=" + str(fakeLSA.dest) + ", " + fakeLSA.getLSAString()
    
        
        
        for r in t.routers:
            r.updateTimer()
            
            
     
    for r in t.routers:
        if(len(r.queue)>0):
            print('last configuration remains with non-empty queue for r' + str(r.ID))
        if(len(r.delayedFB)>0):
            print('last configuration remains with non-empty delayedFB for r'+str(r.ID))    
            
            
 
    
    
    print "#-----------------------------------------" 
    print "#Output 0 :" 
    t.printLSADBs()    
    #print "#-----------------------------------------"
    #print "Routing Tables:"
    #t.printRoutingTables()
    
  
    
    return



  
       
#run CONCOLIC EXECUTIN:
#=======================


if os.path.isfile('tests.txt'):      
    os.remove('tests.txt')      
      
sys.setrecursionlimit(10000)        
sys.stderr = Logger("tests.txt")

if  os.path.exists('generated_tests'):
    shutil.rmtree('generated_tests')
os.makedirs('generated_tests')


n = totalSymbolicVars * totalMsgs

initialSymbolicSeqNumVals =[]
initialSymbolicSeqNumDomains=[]    
if  useSymbolicnitialSeqNumbers.get()==1:
    n = n + m_routers_num
    initialSymbolicSeqNumVals = [0]*m_routers_num
    initialSymbolicSeqNumDomains=[(0,3)]*m_routers_num
    
if n<1:
    print "at least one symbolic var is required"
    exit()    
    
names = " ".join(["s[%s]" % (i,) for i in range(n)])
s = BitVecs(names, 4) 

res = mc_fuzz(lambda: runModel(s), s, initialVals * totalMsgs + initialSymbolicSeqNumVals, domains*totalMsgs + initialSymbolicSeqNumDomains)
      
sys.stderr = sys.__stderr__

'''      
if res > 15:
    print "exceeded limit of test files to generate : " + str(res)
    exit()
'''    



          
exit()      
      
#run with generated tests: - with concrete values
#==========================

if  os.path.exists('generated_tests'):
    shutil.rmtree('generated_tests')
os.makedirs('generated_tests')
      
      
f = open('tests.txt', 'r')
        
for line in f:
    m = re.search("\#\d+", line)
    if m:
        num = str(m.group(0)[1:])
        testname = "test" + num + ".txt"
        print  testname
        #n = re.search("\= \d+", line)
        s=[]
        n = re.findall("\= \d+", line)
        for k in n:
            #print k[2:]
            s.append(int(k[2:]))
                 
                 
                 
        #val = int(str(n.group(0)[2:]))
        ##print val
        sys.stdout = OutLogger('generated_tests\\' + testname)
        runModel(s)
        sys.stdout = sys.__stdout__
            
      
     
     






