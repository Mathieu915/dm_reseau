#!/usr/bin/python
##
#  PROXY doh to dns
##
from socket import *
from select import select
from sys import argv 
import base64
import struct

s=socket(AF_INET, SOCK_STREAM)
s.bind(('0.0.0.0', 80))
s.listen(3)
print ("\nPROXY doh to dns : Lance en ecoute sur le port 80\n") 


###############################
#                             #
#         Exception           #
#                             #
###############################  

class ProtocolNotGet(Exception):
    pass
class VariableNotDns(Exception):
    pass

###############################
#                             #
#        Def fonction         #
#                             #
###############################  

def ctlProtocolGet(protocol):
    """Verifie que le protocole soit bien du GET"""
    try :
        if protocol <> 'GET':
            raise ProtocolNotGet("Protocole n'est pas GET")
        print("OK protocole = GET")
    except ProtocolNotGet :
        print("Protocole utiniser est incorect, le seul autorise est GET")	

def ctlVariableDns(var):
    """Verifie que la variable soit dns"""
    try :
        if var <> 'dns':
            raise VariableNotDns("Variable n'est pas dns")
        print("OK variable = dns")
    except VariableNotDns :
        print("La variable est incorect, la seul autorise est dns")	

def getNameDomaine(data):
    """Retourner le nom de dommaine"""
    print("dsn ="+data)

    header=struct.unpack(">HBBHHHH",data[:12])
    qdcount=header[3]
    ancount=header[4]
    nscount=header[5]
    arcount=header[6]
    print("\nqdcount = "+str(qdcount)+"\t"+"ancount = "+str(ancount)+"\t"+"nscount = "+str(nscount)+"\t"+"arcount = "+str(arcount)+"\n")

    pos,name,typ,clas=retrquest(data,12)
    pos=12

    return name,typ,clas

def retrquest(string,pos):
  """decrit une section question presente dans la reponse DNS string a la position pos"""
  p=pos
  p,name=getname(string,p)
  typ = struct.unpack(">H",string[p:p+2])[0]
  p=p+2
  clas = struct.unpack(">H",string[p:p+2])[0]
  p=p+2
  return p,name,typ,clas

def getname(string,pos):
  """recupere le nom de domaine encode dans une reponse DNS a la position p, en lecture directe ou en compression"""
  p=pos
  save=0
  name=""
  l=1
  if l==0:
    return p+1,""
  while l:
    l=struct.unpack("B",string[p])[0]
    if l>=192:
      #compression du message : les 2 premiers octets sont les 2 bits 11 puis le decalage depuis le debut de l'ID sur 14 bits
      if save == 0:
        save=p
      p=(l-192)*256+(struct.unpack("B",string[p+1])[0])
      l=struct.unpack("B",string[p])[0]
    if len(name) and l:
      name=name+'.'
    p=p+1
    name=name+tupletostring(struct.unpack("c"*l,string[p:(p+l)]))
    p=p+l
  if save > 0:
    p=save+2
  return p,name

def tupletostring(t):
  """concatene un tuple de chaines de caracteres en une seule chaine"""
  print("\n\tenter : tupletostring : t="+str(t)+"\n")
  s=""
  for c in t:
    s=s+c
  print("\n\tsortie : tupletostring ; s= "+str(s)+"\n")
  return s

def numbertotype(typ):
  """associe son type a un entier"""
  print("\n\tenter : numbertotype : typ= "+str(typ)+"\n")
  if typ==1:
    print("\n\tsortie : numbertotype ; (1) return= 'A'\n")
    return 'A'
  if typ==15:
    print("\n\tsortie : numbertotype ; (15) return= 'MX'\n")
    return 'MX'
  if typ==2:
    print("\n\tsortie : numbertotype ; (2) return= 'NS'\n")
    return 'NS'

def typenumber(typ):
  """associe un entier a un nom de type"""
  print("\n\tenter : typenumber : typ= "+str(typ)+"\n")
  if typ=='A':
    print("\n\tsortie : typenumber ; ('A') return= 1\n")
    return 1
  if typ=='MX':
    print("\n\tsortie : typenumber ; ('MX') return= 15\n")
    return 15
  if typ=='NS':
    print("\n\tsortie : typenumber ; ('NS')return= 2\n")
    return 2

def contructDnsRequest(name,typ):
  """"contruction de la requet dns"""
  print("\n\tenter : contructDnsRequest : name= "+str(name)+" typ= "+str(typ)+"\n")
  data=""
  print("data 1= "+str(data))
  #id sur 2 octets
  data=data+struct.pack(">H",0)
  print("data 2= "+str(data)+" remarq= id sur 2octets")
  # octet suivant : Recursion Desired
  data=data+struct.pack("B",1)
  print("data 3= "+str(data)+" remarq= octet suivant : Recursion Desired")
  #octet suivant : 0
  data=data+struct.pack("B",0)
  print("data 4= "+str(data)+" remarq= octet suivant : 0")
  #QDCOUNT sur 2 octets
  data=data+struct.pack(">H",1)
  print("data 5= "+str(data)+" remarq= QDCOUNT sur 2 octets")
  data=data+struct.pack(">H",0)
  print("data 6= "+str(data))
  data=data+struct.pack(">H",0)
  print("data 7= "+str(data))
  data=data+struct.pack(">H",0)
  print("data 8= "+str(data))
  print("\nDATA = "+str(data)+"\n")

  splitname=name.split('.')
  for c in splitname:
    print("splitname c= "+str(c))
    data=data+struct.pack("B",len(c))
    print("data 9= "+str(data))
    for l in c:
      print("for l in c ; l= "+str(l))
      data=data+struct.pack("c",l)
      print("data 10= "+str(data))

  data=data+struct.pack("B",0)
  print("data 11= "+str(data))
  #TYPE
  data=data+struct.pack(">H",typenumber(typ))
  print("data 12= "+str(data)+" remarq = TYPE")
  #CLASS 1 (IN) par defaut
  data=data+struct.pack(">H",1)
  print("data 13= "+str(data)+" remarq = CLASS 1 (IN) par defaut")

  # ttp sur 2 octet

  # longueur 1 octet

  # data sur x octet

  print("\n\tsortie : contructDnsRequest : DATA= "+str(data)+"\n")
  return data

def sendToAlice(data,s,leng):
  """"""
  print("\n\tenter : sendToAlice : data="+str(data)+"\n")
  s.send("""HTTP/1.0 200 OK
Content-Type: application/dns-message
Content-Length: %s

%s
""" % (leng,data,))
  print("\n\tsortie : sendToAlice ; s.send \n")




while True:
    (data,addr)=s.accept()
    print ("Data : " + str(data) + "addr : "+str(addr) )

    requete=data.recv(1024)
    print("requete : "+str(requete))    

    protocol=requete.split(' ')[0]
    print("protocole = "+protocol)
    ctlProtocolGet(protocol)

    varible=requete.split('?')[1][:3]
    print("variable = "+varible)
    ctlVariableDns(varible)

    dns_b64encode=requete.split('dns=')[1].split(' ')[0]
    print("dns encode64 = "+dns_b64encode)
    dns_b64decode = base64.b64decode(dns_b64encode,'-_')
    print("dns decode64 = "+dns_b64decode)

    name,typ,clas = getNameDomaine(dns_b64decode);
    print("name ="+name+"   "+"type = "+numbertotype(typ)+" ; type number = "+str(typ)+"   "+"class ="+str(clas))


    t=socket(AF_INET, SOCK_DGRAM)
    t.connect(('1.2.3.4',53))
    print("\nConnected to ispA = 1.2.3.4 port 53")

    requete_dns=contructDnsRequest(name,numbertotype(typ))
  
    t.send(requete_dns)
    print("-> envoie requete dns")
    
    data_recv=t.recv(1024)
    print("<- rep requete dns : data ="+str(data_recv))

    leng=len(data_recv)
    print("lenght ="+str(leng))
    sendToAlice(data_recv,s,leng)
    print("-> envoie reponse to alice")


    exit()



