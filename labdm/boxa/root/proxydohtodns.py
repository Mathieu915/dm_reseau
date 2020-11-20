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

['www.lexique.com\tIN  A\t9.9.9.9\n', 'cold.net\tIN  MX\t5 smtp.cold.net\n', 'smtp.cold.net\tIN  A\t213.186.33.5\n']

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
  s=""
  for c in t:
    s=s+c
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

def clasnumber(clas):
  """associe un entier a un nom une classe"""
  if clas=='IN':
    return 1
  if clas=='CS':
    return 2
  if clas=='CH':
    return 3
  if clas=='HS':
    return 4

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


def Isknown(name,typ):
  file = open("/etc/bind/db.static","r")
  tab=file.readlines()
  file.close()
  #['www.lexique.com\tIN  A\t9.9.9.9\n', 'cold.net\tIN  MX\t5 smtp.cold.net\n', 'smtp.cold.net\tIN  A\t213.186.33.5\n']

  for ligne in tab:
    print(ligne)
    domain=ligne.split("\t")[0]
    typee=ligne.split("\t")[1].split("  ")[1]
    clas=ligne.split("\t")[1].split("  ")[0]
    result=ligne.split("\t")[2]

    print("domain = "+domain+" name = "+name+" ; typee = "+typee+" type = "+typ)
    if domain==name and typee==typ:
      print(">deja connu")
      return True,domain,clas,typee,result
    else:
      print(">inconnu")
  return False,"","","",""

def stock(name, typ, clas, data):
  print("\n enter : stock")
  file = open("/etc/bind/db.static","a")
  if clas==1:
    file.write(name+"\t"+"IN"+"  "+numbertotype(typ)+"\t"+str(data)+"\n")
  elif clas==2:
    file.write(name+"\t"+"CS"+"  "+numbertotype(typ)+"\t"+str(data)+"\n")
  elif clas==3:
    file.write(name+"\t"+"CH"+"  "+numbertotype(typ)+"\t"+str(data)+"\n")
  elif clas==4:
    file.write(name+"\t"+"HS"+"  "+numbertotype(typ)+"\t"+str(data)+"\n")
  else:
    pass
  file.close();
  print("\n sortie : stock")

def contructDnsReply(domain,clas,typ,result):
  """"""
  print("\nenter : contructDnsReply")

  data=""
  #id sur 2 octets
  data=data+struct.pack(">H",0)
  # octet suivant : Recursion Desired
  data=data+struct.pack("B",1)
 
  #octet suivant : 0
  data=data+struct.pack("B",0)
 
  #QDCOUNT sur 2 octets
  data=data+struct.pack(">H",1)
  #ANCOUNT sur 2 octets
  data=data+struct.pack(">H",1)
  #NScount su 2 octets
  data=data+struct.pack(">H",0) # ToDo quand type = NS ou MX
  #ARcount su 2 octets
  data=data+struct.pack(">H",0) # ToDo quand type = NS ou MX
  
  nb_octet=12

  # non de domaine su x octets
  splitname=domain.split('.')
  for c in splitname:
    data=data+struct.pack("B",len(c))
    nb_octet=nb_octet+1
    for l in c:
      data=data+struct.pack("c",l)
      nb_octet=nb_octet+1

  # 1 octet = 00 pr dire la fin du nom de dommaine
  data=data+struct.pack("B",0)

  #TYPE
  data=data+struct.pack(">H",typenumber(typ))

  #CLASS 
  data=data+struct.pack(">H",clasnumber(clas))


  # ttl sur 2 octet
  data=data+struct.pack(">H",0)
  data=data+struct.pack("H",60)

  nb_octet=nb_octet+6 # en comptant l'octet de la longueur
  # splitip1=result.split('.')
  # for x in splitip1:
  #   nb_octet=nb_octet+1

  print("longueur ====>"+str(nb_octet))
  # longueur 1 octet
  data=data+struct.pack(">B",nb_octet)

  # data sur x octet
  splitip=result.split('.')
  for x in splitip:
    data=data+struct.pack(">H",int(x))
  data=data+struct.pack(">H",0)
  data=data+struct.pack(">H",0)
  data=data+struct.pack(">H",0)
  data=data+struct.pack(">H",0)



  print("\n\tsortie : contructDnsRequest : DATA= "+str(data)+"\n")
  return data




def getname(string,pos):
  """recupere le nom de domaine encode dans une reponse DNS a la position p, en lecture directe ou en compression"""
  print("\n\tenter : getname : string= "+str(string)+" pos= "+str(pos)+"\n")
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
  print("\n\tsortie : getname : p= "+str(p)+" name = "+str(name)+"\n")
  return p,name

i=12
def retrquest(string,pos):
  """decrit une section question presente dans la reponse DNS string a la position pos"""
  print("\n\tenter : retrquest : string= "+str(string)+" pos= "+str(pos)+"\n")
  p=pos
  p,name=getname(string,p)
  typ = struct.unpack(">H",string[p:p+2])[0]
  p=p+2
  clas = struct.unpack(">H",string[p:p+2])[0]
  p=p+2
  print("\n\tsortie : retrquest : p= "+str(p)+" name = "+str(name)+" typ= "+str(typ)+" clas= "+str(clas)+"\n")
  return p,name,typ,clas

def retrrr(string,pos):
  """decrit une section resource record presente dans la reponse DNS string a la position pos"""
  print("\n\tenter : retrrr : string= "+str(string)+" pos= "+str(pos)+"\n")
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
  print("\n\tsortie : retrrr : p= "+str(p)+" name = "+str(name)+" typ= "+str(typ)+" clas= "+str(clas)+" ttl ="+str(ttlcpl[0]*256+ttlcpl[1])+" datalenght= "+str(datalen)+" dat= "+str(dat)+"\n")
  return p,name,typ,clas,ttlcpl[0]*256+ttlcpl[1],datalen,dat









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
    
    print('\n\n##############################\n')

    is_known,domain,clas,typee,result=Isknown(name,numbertotype(typ))

    print('\n##############################\n\n')

    test=0
    if is_known and test==0 :
      print("Ligne : domaine = "+domain+" clas = "+clas+" type = "+typee+" result = "+result)

      requete_dns=contructDnsReply(domain,clas,typee,result)

      leng=90
      sendToAlice(requete_dns,data,leng)
      print("--------> envoie reponse to alice\n")
      data.close()
      
    else:
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
      sendToAlice(data_recv,data,leng)
      print("-> envoie reponse to alice\n")

      data.close()


      print("\n######################\n#       Descrip      #\n######################\n")

      # decriptage pour le metre dans la bdd
      data=data_recv
      print("\n")
      header=struct.unpack(">HBBHHHH",data[:12])
      qdcount=header[3]
      ancount=header[4]
      nscount=header[5]
      arcount=header[6] 

      #Affichage de la reponse, section par section
      print("QUERY: "+str(qdcount)+", ANSWER: "+str(ancount)+", AUTHORITY: "+str(nscount)+", ADDITIONAL: "+str(arcount)+'\n')

      i=12
      data_answer="null"
      if qdcount:
        print("QUERY SECTION :\n")
        for j in range(qdcount):
          pos,name,typ,clas=retrquest(data,i)
          i=pos
          name_bdd=name
          typ_bdd=typ
          clas_bdd=clas
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
        data_answer=dat

      if nscount:
        print("AUTHORITY SECTION :\n")
        for j in range(nscount):
          pos,name,typ,clas,ttl,datalen,dat=retrrr(data,i)
          i=pos
          print("...")
          #print(name+"   "+numbertotype(typ)+"   "+str(clas)+"   "+str(ttl)+"   "+"str(dat)=...")
        print("\n")

      if arcount:
        print("ADDITIONAL SECTION :\n")
        for j in range(arcount):
          pos,name,typ,clas,ttl,datalen,dat=retrrr(data,i)
          i=pos
          print(name+"   "+numbertotype(typ)+"   "+str(clas)+"   "+str(ttl)+"   "+str(dat))
        print("\n")

      print("\n----------------------------------------------\n")
      if data_answer!="null":
        print("\n A STOCKE : "+name_bdd+"\t"+numbertotype(typ_bdd)+"  "+str(clas_bdd)+"\t"+str(data_answer)+"\n")
        stock(name_bdd, typ_bdd, clas_bdd, data_answer)
      print("\n----------------------------------------------\n")
      
      t.close()
    
    print ("\n|-------------------------|\n|                         |\n|        THE END !        |\n|                         |\n|-------------------------|")

    print("\n\n---------------------------------------------------------------------------\n")
    print ("\nPROXY doh to dns : Lance en ecoute sur le port 80\n") 
    