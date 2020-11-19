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

    s.close()

    name,typ,clas = getNameDomaine(dns_b64decode);
    print("name ="+name+"   "+"type ="+numbertotype(typ)+"   "+"class ="+str(clas))


    exit()

    print("connect a ispa")
    t=socket()
    t.connect(("1.2.3.4",53))
    print("Connected to ispA = 1.2.3.4 port 53")



    requete_dns = "ping 8.8.8.8"
    t.send(requete_dns)
    print("-> envoie requete dns")
    data_recv=t.recv(1024)
    print("<- rep requete dns : data ="+str(data_recv))



