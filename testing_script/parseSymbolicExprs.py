import re

class parseSeqNumExpr:
    def __init__(self, fileName):
        self.m_fileName = fileName
        self.m_routers_num=5
        #conventions:
        #lsa_string => pair : (s_index(int) , addition(int))
        #if seq==maxSeq : pair = (-1,'MaxSeq')
        #if seq==initSeq : pair - (-1,'MinSeq')
        self.m_initialSeqNums={}
        
        self.m_routers_initial_seq = []
        self.m_routers_expected_seq = [[],[],[]] #currently support up to 3 messages 
        for _ in range(self.m_routers_num):
            self.m_routers_initial_seq.append({})
            self.m_routers_expected_seq[0].append({})
            self.m_routers_expected_seq[1].append({})
            self.m_routers_expected_seq[2].append({})
        
        self.m_s_values=[]  #symbolic values by order
        self.m_s_rep_description=[]  #description of symbolic values by order
        
        return
    

    
    def getSymbolicVal(self,val):
        #print val
        if '+' in val:
            ind = val.find('s')                 
            s_index = int(val[ind+2]) 
            addition = val.count('+')
            return self.m_s_values[s_index]+addition
            
        else:    
            index = int(val[2:-1])               
        return  self.m_s_values[index]
    
    
    def convertLSAstringTOModel(self, lsaString):
        routerip = {'0':{'0':'10.0.2.10','11':'10.0.4.10'}, '1':{'1':'10.0.1.1', '10':'10.0.2.1', '100':'10.0.0.1'}, '2':{'2':'10.0.1.2','20':'10.0.5.1'}, '3':{'3':'10.0.0.3','30':'10.0.4.1'}, '4':{'4':'10.0.0.4','40':'10.0.5.2'}}
        parts = lsaString.split(';')
        lstype = parts[0]
        lsid = parts[1]
        adrouter = parts[2]
        modellsid = None
        modeladrouter = None
        for key in routerip:
            if lsid in routerip[key].values():
                modellsid = key
                break
        for key in routerip:
            if adrouter in routerip[key].values():
                modeladrouter = key
                break
        conversion = 'routerLSA' + ';' + str(modellsid) + ';' + str(modeladrouter)
        if not(str(modellsid).isdigit() and  str(modeladrouter).isdigit()):
            raise Exception('convertLSAstringTOModel error')
        return conversion
    
    
    def updateLSAstring(self,lsaString, routerID):
        routerip = {'0':{'0':'10.0.2.10','11':'10.0.4.10'}, '1':{'1':'10.0.1.1', '10':'10.0.2.1', '100':'10.0.0.1'}, '2':{'2':'10.0.1.2','20':'10.0.5.1'}, '3':{'3':'10.0.0.3','30':'10.0.4.1'}, '4':{'4':'10.0.0.4','40':'10.0.5.2'}}
        parts = lsaString.split(';')
        lstype = parts[0]
        lsid = parts[1]
        adrouter = parts[2]
        for k in routerip:
            if k==routerID:
                if lsid != routerip[k][k] or adrouter != routerip[k][k]:
                    
                    return lstype + ';' + str(routerip[routerID][routerID]) + ';' + str(routerip[routerID][routerID])
        return lsaString         
        

        
    
    def checkConsistentInitialState(self, LSAsMapInitial, M_seq, M_index ):
        routerid = {'0':'10.0.2.10', '1':'10.0.2.1', '2':'10.0.1.2', '3':'10.0.0.3', '4':'10.0.0.4'}
        index=0
        
        delta_arr = []
        for description in self.m_s_rep_description:
            if ':seq' in description:
                print description
                msg_index_description = int(description[1])
                if msg_index_description!= M_index or M_seq[M_index]==0x7fffffff or M_seq[M_index]==0x7fffffff-1:
                    index+=1
                    continue 
                print 'M seq concrete val = ' + str(M_seq[M_index])
                print 'M seq model val = ' + str(self.m_s_values[index])
                delta_arr.append(M_seq[M_index] - self.m_s_values[index])
            elif   'initial_seq_of' in  description:
                desc_size = len(description)
                routerIndex = int(description[desc_size-1])
                lsaString = '1' + ';' + routerid[str(routerIndex)] + ';' + routerid[str(routerIndex)]
                check1 = (LSAsMapInitial['0'][lsaString][1].seq == LSAsMapInitial['1'][lsaString][1].seq)
                check2 = (LSAsMapInitial['0'][lsaString][1].seq == LSAsMapInitial['2'][lsaString][1].seq)
                check3 = (LSAsMapInitial['0'][lsaString][1].seq == LSAsMapInitial['3'][lsaString][1].seq)
                check4 = (LSAsMapInitial['0'][lsaString][1].seq == LSAsMapInitial['4'][lsaString][1].seq)
                if not(check1 and check2 and check3 and check4):
                    raise Exception('checkConsistentInitialState error ')
                
                model_val = self.m_s_values[index]
                
                print 'lsa sting = ' + str(lsaString)
                print 'model seq val = ' + str(model_val)
                print 'cisco seq val = ' + str(LSAsMapInitial['0'][lsaString][1].seq)                
                delta_arr.append(LSAsMapInitial['0'][lsaString][1].seq - model_val)                        
            index+=1
            
        
        print delta_arr
        delta_arr_len = len(delta_arr)
        delta_0 = delta_arr[0]
        for ind in range(1,delta_arr_len):
            if delta_arr[ind]!= delta_0:
                return False
        
                                       
        return True    
    
    
    def checkConsistency(self,r,LSAsMapInitial,LSAMapFinal,M_seq,M_index,might_fail_due_to_chksum_issue):
        
        print "check consistency function:"
        print "arguments:"
        print "r = " + str(r)
        print "M_seq = " + str(M_seq[M_index])
        
        print "printing initial mapMatchingLSAs:"
        for k in LSAsMapInitial:
            print k
            for st in LSAsMapInitial[k]:
                print st
                print LSAsMapInitial[k][st]
                
                
        print "printing final mapMatchingLSAs:"
        for k in LSAMapFinal:
            print k
            for st in LSAMapFinal[k]:
                print st
                print LSAMapFinal[k][st]   
                
                     
        
        #check fot each lsa string from LSAMapFinal          
        for lsaString in LSAMapFinal[r]: #per each LSA in the DB of r
            print('lsaString = ' + lsaString)
            if(might_fail_due_to_chksum_issue[0] and len(LSAMapFinal[r][lsaString])!=2):
                return False
            #assert(len(LSAMapFinal[r][lsaString])==2)
            if not (len(LSAMapFinal[r][lsaString])==2):
                raise Exception('checkConsistency error - len(LSAMapFinal[r][lsaString])!=2 ') 
            if len(LSAMapFinal[r][lsaString])!=2: #cannot check if no matching lsa was found 
                continue
            #extract the values from the cisco run:    
            #initialCiscoSeq =     LSAsMap[r][lsaString][1].seq
            finalCiscoSeq =     LSAMapFinal[r][lsaString][1].seq
            
            #extract the expr of the final seq num from the model 
            modelLSAstring = self.convertLSAstringTOModel(lsaString)
            
            #get the expr of the expceted seq number from the model
            print r, self.m_routers_expected_seq[M_index]
            print  self.m_routers_expected_seq[M_index][int(r)]           
            stringLSAsArr = self.m_routers_expected_seq[M_index][int(r)]
            
            print "modelLSAstring = " + modelLSAstring
            print "stringLSAsArr = " + str(stringLSAsArr)
            #assert(modelLSAstring in stringLSAsArr)
            if not (modelLSAstring in stringLSAsArr):
                raise Exception('checkConsistency error - modelLSAstring not in stringLSAsArr')
            #if modelLSAstring in stringLSAsArr:
            expr = stringLSAsArr[modelLSAstring]
            symbolic_index = expr[0]
            addition = expr[1]
            
            concreteVal = None
            
            if symbolic_index == -1 and addition=='MaxSeq':
                concreteVal = 0x7fffffff
                addition = 0            
            elif symbolic_index == -1 and addition=='MinSeq':
                concreteVal = 0x80000001
                addition = 0                
            
            #get the value on which the final exp depends from cisco
            elif  ':seq' in self.m_s_rep_description[symbolic_index]:
                msg_index = int(self.m_s_rep_description[symbolic_index][1])
                concreteVal = M_seq[msg_index]
                print 'first' , M_seq[msg_index]
            elif 'initial_seq_of' in  self.m_s_rep_description[symbolic_index]:
                strlen = len(self.m_s_rep_description[symbolic_index])
                r_index = int(self.m_s_rep_description[symbolic_index][strlen-1])
                lsa_str  = self.updateLSAstring(lsaString,r_index)
                print 'lsa_str = ' + lsa_str
                concreteVal = LSAsMapInitial[r][lsa_str][1].seq
                print 'second', LSAsMapInitial[r][lsa_str][1].seq, r, lsa_str
                
            else:
                #assert False
                raise Exception('checkConsistency error')    
            print 'modelLSAstring = ' + modelLSAstring
                
            print 'finalCiscoSeq = ' + str(finalCiscoSeq)
            print 'concreteVal = ' + str(concreteVal)
            print 'addition = ' + str(addition)
            print  'expr = ' + str(expr)   
            
            print 'routerID = ' + str(r)
            print     concreteVal, addition, finalCiscoSeq
            if     int(concreteVal) + int(addition) != finalCiscoSeq:
                print "inconsistent"
                return False 

        
        return True
    
    
    
    
    
    def parse(self):
        
        f=open(self.m_fileName)
        lines=f.readlines()
        states = [0]*self.m_routers_num   #1 for initial state, 2 for final state


        if not (lines[0].count('symbolic values:')>0):
            raise Exception('parse error - symbolic values string on test file ')
        
        msg_index=0
        parseSymbolicVals=False
        parseSymbolicReps=False
        r=-1 #current router 
        for l in lines:
            if l.find('symbolic values:')==0:
                parseSymbolicVals = True
            elif l.find('symbolic vals represent:')==0:     
                parseSymbolicVals=False
                parseSymbolicReps=True
            elif l.find('end symbolic vars info')==0:
                parseSymbolicVals=False
                parseSymbolicReps=False    
            elif parseSymbolicVals:
                value = str(l[l.find('=')+1:]).strip()
                lp_ind = l.find('[')
                rp_ind = l.find(']')
                s_ind  = int(l[lp_ind+1:rp_ind])
                self.m_s_values.append(int(value))
                #assert(len(self.m_s_values)==s_ind+1)
                if not (len(self.m_s_values)==s_ind+1):
                    raise Exception('parse error')
            elif  parseSymbolicReps:
                value = str(l[l.find('=>')+2:]).strip()
                lp_ind = l.find('[')
                rp_ind = l.find(']')
                s_ind  = int(l[lp_ind+1:rp_ind])   
                self.m_s_rep_description.append(value)
                #assert(len(self.m_s_values)==s_ind+1)
                
            #Output 0 :
            index = l.find('Output')
            if index!= -1: #new index of final state (for multiple messages)
                msg_index = int(l[8]) #index location of string 
            index = l.find('LSDB')    
            if index != -1  and l.find('#')!=0 : #New router        
                r = int(l[index+len('LSDB')])
                states[r]+=1
            elif l.find('type')==0: #DB line
                reg = re.compile('[\t\n\r,]+')
                parts = reg.split(l)
                lasString=''
                Ltype = ''
                LSID = ''
                AdvertisingRouter = ''
                for p in parts:
                    #print p
                    ivalue = p.find('=')
                    if ivalue == -1:
                        break
                    value = str(p[p.find('=')+1:]).strip()            
                    if 'type' in p:                                
                        Ltype = value
                        if value == 'networkLSA':
                            break
                    if 'LSID' in p:
                        if value.isdigit():
                            LSID = value
                        else:
                            LSID =  str(self.getSymbolicVal(value))
                    if  'AdvertisingRouter' in p:   
                        if value.isdigit():
                            AdvertisingRouter = value
                        else:
                            AdvertisingRouter =  str(self.getSymbolicVal(value))
                    #print value
                    if 'sequenceNum' in p:               
                        lasString = Ltype + ';' + LSID + ';' + AdvertisingRouter
                        expr_seq = value
                        #print expr_seq
                        #print expr_seq
                        ind = expr_seq.find('s')
                        if ind<0 : 
                            if expr_seq=='7' :
                                s_index=-1
                                addition = 'MaxSeq'
                            elif expr_seq=='0' :
                                s_index =-1    
                                addition = 'MinSeq'
                            else:
                                break     
                        #print ind
                        else:
                            s_index = int(expr_seq[ind+2])  #TODO currently only ONE digit for s_index!!!
                            addition = expr_seq.count('+')
                        if states[r]==1:
                            self.m_routers_initial_seq[r][lasString] = (s_index,addition)
                            self.m_initialSeqNums[LSID] = self.m_s_values[s_index]
                        else:
                            self.m_routers_expected_seq[msg_index][r][lasString] = (s_index,addition)
                             
         
         
        f.close()        
        #print "print parsed vals:"
        #self.printParsedVals()                 
        return
    


    def printParsedVals(self):
        #print self.m_routers_initial_seq
        #print self.m_routers_expected_seq
        #print self.m_s_rep_description
        #print self.m_s_values
        return

        















 


