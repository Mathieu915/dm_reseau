#!/usr/bin/python
##
# Simple DNS client 
##
from socket import *
from sys import argv
import base64
import struct

if len(argv)<>4 or argv[1]<> '-t':
  print("usage: %s -t type domain-name") % argv[0]
  exit(1)

reqtype=argv[2]
name=argv[3]

print("\n######################\n#       Etape 1      #\n######################\n")
print("\nARG= \targ2 (=reqtype) : "+reqtype+"\targ3 (=name) : "+name+"\n")


# recuperere addr du server = 1.2.3.54 qui correspond a BoxA en eth1
def findaddrserver():
  """recupere l'adresse de couche transport du proxy DoH depuis le fichier /etc/resolv.conf"""
  print("\n\tenter : findaddrserver\n")
  resolvconf = open("/etc/resolv.conf", "r")
  lines = resolvconf.readlines()
  i=0
  while lines[i].split()[0]<>'nameserver':
    i=i+1
  server = lines[i].split()[1]
  resolvconf.close()
  print("\n\tsortie : findaddrserver ; server= "+server+"\n")
  return (server,80)

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

def dnsrequete(name, typ):
  """construction de la requete demandant les enregistrements de type typ pour le nom de domaine name"""
  print("\n\tenter : dnsrequete : name= "+str(name)+" typ= "+str(typ)+"\n")
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

  print("\n\tsortie : dnsrequete : DATA= "+str(data)+"\n")
  return data




#encodage en base64url : base64 avec les 2 derniers caracteres - et _
print("\n\tencodage en base64url : base64 avec les 2 derniers caracteres - et _\n")
bdata = base64.b64encode(dnsrequete(name,reqtype),'-_')
print("\n\tfin encodage64 : bdata= "+str(bdata)+"\n")

print("\nDebut socket\n")
s=socket()
server,port=findaddrserver()
print("\n\tserver= "+str(server)+" , port="+str(port)+"\n")
s.connect((server,port))
print("\n\tsocket connecter\n")




print("\n######################\n#       Etape 2      #\n######################\n")

def senddoh(data,s):
  """envoie sur la socket s la requete DoH data au format base64url"""
  print("\n\tenter : senddoh : data="+str(data)+"\n")
  path="?dns="+data
  s.send("""GET /%s HTTP/1.0
Host: %s
Accept: application/dns-message

""" % (path,server,))
  print("\n\tenter : senddoh ; s.send ; path= "+str(path)+"\n")

def tupletostring(t):
  """concatene un tuple de chaines de caracteres en une seule chaine"""
  print("\n\tenter : tupletostring : t="+str(t)+"\n")
  s=""
  for c in t:
    s=s+c
  print("\n\tsortie : tupletostring ; s= "+str(s)+"\n")
  return s

def listtostring(l):
  """concatene une liste de chaines de caracteres en une seule chaine"""
  print("\n\tenter : listtostring : l="+str(l)+"\n")
  s=""
  for c in l:
    s=s+c
  print("\n\tsortie : listtostring ; s= "+str(s)+"\n")
  return s
  
def recvdoh(s):
  """recoit une reponse DoH sur la socket s et la retourne au format DNS standard (bytes)"""
  print("\n\tenter : recvdoh\n")
  r=''
  data=s.recv(4096)
  while data:
    r=r+data
    data=s.recv(4096)
    #pos calcule la position de debut de la reponse DNS en comptant les caracteres de retour a la ligne
  pos=0
  l=r.splitlines()
  if l[0].split(' ')[1] <> "200":
    print("Erreur : code "+ l[0].split(' ')[1])
    exit(1)
  pos=len(l[0])+1
  i=1
  while l[i].split(': ')[0]<> 'Content-Type':
    pos=pos+len(l[i])+1
    i=i+1
  if l[i].split(': ')[1] <> 'application/dns-message':
    print("Erreur : mauvais type "+ l[i].split(' ')[1])
    exit(1)
  while l[i]<>'':
    pos=pos+len(l[i])+1
    i=i+1
  return r[pos+1:]




senddoh(bdata,s)
data=recvdoh(s)




print("\n")
header=struct.unpack(">HBBHHHH",data[:12])
qdcount=header[3]
ancount=header[4]
nscount=header[5]
arcount=header[6]

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

i=12
def retrquest(string,pos):
  """decrit une section question presente dans la reponse DNS string a la position pos"""
  p=pos
  p,name=getname(string,p)
  typ = struct.unpack(">H",string[p:p+2])[0]
  p=p+2
  clas = struct.unpack(">H",string[p:p+2])[0]
  p=p+2
  return p,name,typ,clas

def retrrr(string,pos):
  """decrit une section resource record presente dans la reponse DNS string a la position pos"""
  p=pos
  p,name=getname(string,p)
  typ = struct.unpack(">H",string[p:p+2])[0]
  p=p+2
  clas = struct.unpack(">H",string[p:p+2])[0]
  p=p+2
  ttlcpl = struct.unpack(">HH",string[p:p+4])
  p=p+4
  datalen = struct.unpack(">H",string[p:p+2])[0]
  p=p+2
  if typ == 1:
    aux = struct.unpack("B"*datalen,string[p:(p+datalen)])
    dat = str(aux[0])+'.'+str(aux[1])+'.'+str(aux[2])+'.'+str(aux[3])
  if typ == 2:
    x,dat = getname(string,p)
  if typ == 15:
    pref = struct.unpack(">H",string[p:p+2])[0]
    x,name = getname(string,p+2)
    dat = (pref,name)
  if typ not in [1,2,15]:
    dat = struct.unpack("B"*datalen,string[p:(p+datalen)])
  p=p+datalen
  return p,name,typ,clas,ttlcpl[0]*256+ttlcpl[1],datalen,dat

#Affichage de la reponse, section par section
print("QUERY: "+str(qdcount)+", ANSWER: "+str(ancount)+", AUTHORITY: "+str(nscount)+", ADDITIONAL: "+str(arcount)+'\n')
if qdcount:
  print("QUERY SECTION :\n")
  for j in range(qdcount):
    pos,name,typ,clas=retrquest(data,i)
    i=pos
    print(name+"   "+numbertotype(typ)+"   "+str(clas))
  print("\n")

if ancount:
  print("ANSWER SECTION :\n")
  for j in range(ancount):
    pos,name,typ,clas,ttl,datalen,dat=retrrr(data,i)
    i=pos
    if typ == 15:
      print(name+"   "+numbertotype(typ)+"   "+str(clas)+"   "+str(ttl)+"   "+str(dat[0])+"   "+dat[1])
    else:
      print(name+"   "+numbertotype(typ)+"   "+str(clas)+"   "+str(ttl)+"   "+str(dat))
  print("\n")

if nscount:
  print("AUTHORITY SECTION :\n")
  for j in range(nscount):
    pos,name,typ,clas,ttl,datalen,dat=retrrr(data,i)
    i=pos
    print(name+"   "+numbertotype(typ)+"   "+str(clas)+"   "+str(ttl)+"   "+str(dat))
  print("\n")

if arcount:
  print("ADDITIONAL SECTION :\n")
  for j in range(arcount):
    pos,name,typ,clas,ttl,datalen,dat=retrrr(data,i)
    i=pos
    print(name+"   "+numbertotype(typ)+"   "+str(clas)+"   "+str(ttl)+"   "+str(dat))
  print("\n")
