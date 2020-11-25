#!/usr/bin/python
# -*- coding: utf-8 -*-

##
#  	
#	Titre : PROXY doh to dns
#   URL   : https://github.com/Mathieu915/dm_reseau
#   Date édition     : 10/11/2020  
#   Date mise à jour : 24/11/2020 
#   Rapport de la maj :
#   	- ...
#	
#	ToDo :
#		- envoie rep a Alice deuis le cache
# 		- gestion de la rep a Alice depuis le cache quand requete dns est MX et NS
#  		- toute les def de fonction
##

print("\n\n")
print("========================== Starting proxy ==========================\n")
print("Author:        CLAVIE Mathieu & CHEVALIER Thomas")
print("Email:         mathieu.clavie@etu.univ-orleans.fr ")
print("               & thomas.chevalier1@etu.univ-orleans.fr")
print("Web:           https://github.com/Mathieu915/dm_reseau")
print("Description:   ")
print("     Proxy DOH to DNS")
print("\n====================================================================")


from socket import *
from select import select
from sys import argv
import base64
import struct

# Socket TCT pour une liaison avec Alice
s = socket(AF_INET, SOCK_STREAM)
s.bind(('0.0.0.0', 80))
s.listen(3)

print ("\n\n+-----------------------------------+\n|                                   |\n|         PROXY : Listen 80         |\n|                                   |\n+-----------------------------------+\n\n")




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
    try:
        if protocol != 'GET':
            raise ProtocolNotGet("Protocole n'est pas GET")
    except ProtocolNotGet:
        print('Protocole utiniser est incorect, le seul autorise est GET')


def ctlVariableDns(var):
    """Verifie que la variable soit dns"""
    try:
        if var != 'dns':
            raise VariableNotDns("Variable n'est pas dns")
    except VariableNotDns:
        print('La variable est incorect, la seul autorise est dns')


def getNameDomaine(data):
    """Retourner le nom de dommaine"""

    header = struct.unpack('>HBBHHHH', data[:12])
    qdcount = header[3]
    ancount = header[4]
    nscount = header[5]
    arcount = header[6]

    (pos, name, typ, clas) = retrquest(data, 12)
    pos = 12

    return (name, typ, clas)


def retrquest(string, pos):
    """decrit une section question presente dans la reponse DNS string a la position pos"""

    p = pos
    (p, name) = getname(string, p)
    typ = struct.unpack('>H', string[p:p + 2])[0]
    p = p + 2
    clas = struct.unpack('>H', string[p:p + 2])[0]
    p = p + 2
    return (p, name, typ, clas)


def getname(string, pos):
    """recupere le nom de domaine encode dans une reponse DNS a la position p, en lecture directe ou en compression"""

    p = pos
    save = 0
    name = """"""
    l = 1
    if l == 0:
        return (p + 1, """""")
    while l:
        l = struct.unpack('B', string[p])[0]
        if l >= 192:
        # compression du message : les 2 premiers octets sont les 2 bits 11 puis le decalage depuis le debut de l'ID sur 14 bits
            if save == 0:
                save = p
            p = (l - 192) * 256 + struct.unpack('B', string[p + 1])[0]
            l = struct.unpack('B', string[p])[0]
        if len(name) and l:
            name = name + '.'
        p = p + 1
        name = name + tupletostring(struct.unpack('c' * l, string[p:(p+l)]))
        p = p + l
    if save > 0:
        p = save + 2
    return (p, name)


def tupletostring(t):
    """concatene un tuple de chaines de caracteres en une seule chaine"""

    s = """"""
    for c in t:
        s = s + c
    return s


def numbertotype(typ):
    """associe son type a un entier"""
    if typ == 1:
        return 'A'
    if typ == 15:
        return 'MX'
    if typ == 2:
        return 'NS'


def typenumber(typ):
    """associe un entier a un nom de type"""
    if typ == 'A':
        return 1
    if typ == 'MX':
        return 15
    if typ == 'NS':
        return 2


def clasnumber(clas):
    """associe un entier a un nom une classe"""
    if clas == 'IN':
        return 1
    if clas == 'CS':
        return 2
    if clas == 'CH':
        return 3
    if clas == 'HS':
        return 4


def numbertoclas(clas):
    """associe un entier a un nom une classe"""
    if clas == 1:
        return 'IN'
    if clas == 2:
        return 'CS'
    if clas == 3:
        return 'CH'
    if clas == 4:
        return 'HS'


def contructDnsRequest(name, typ):
    """"contruction de la requet dns"""

    data = ""

  # id sur 2 octets

    data = data + struct.pack('>H', 0)

  # octet suivant : Recursion Desired

    data = data + struct.pack('B', 1)

  # octet suivant : 0

    data = data + struct.pack('B', 0)

  # QDCOUNT sur 2 octets

    data = data + struct.pack('>H', 1)

    data = data + struct.pack('>H', 0)
    data = data + struct.pack('>H', 0)
    data = data + struct.pack('>H', 0)

    splitname = name.split('.')
    for c in splitname:
        data = data + struct.pack('B', len(c))
        for l in c:
            data = data + struct.pack('c', l)

    data = data + struct.pack('B', 0)

  # TYPE

    data = data + struct.pack('>H', typenumber(typ))

  # CLASS 1 (IN) par defaut

    data = data + struct.pack('>H', 1)

  # ttp sur 2 octet

  # longueur 1 octet

  # data sur x octet

    return data


def sendToAlice(data, s, leng):
    """"""
    s.send("""HTTP/1.0 200 OK
Content-Type: application/dns-message
Content-Length: %s

%s
"""
           % (leng, data))


def Isknown(name, typ):
    file = open('/etc/bind/db.static', 'r')
    tab = file.readlines()
    file.close()

  # ['www.lexique.com\tIN  A\t9.9.9.9\n', 'cold.net\tIN  MX\t5 smtp.cold.net\n', 'smtp.cold.net\tIN  A\t213.186.33.5\n']
    # file = open('/etc/bind/db.static', 'r')
    # print(file.readlines())
    # file.close()


    for ligne in tab:
        domain = ligne.split('\t')[0]
        typee = ligne.split('\t')[1].split('  ')[1]
        clas = ligne.split('\t')[1].split('  ')[0]
        result = ligne.split('\t')[2]
        
        #print('>'+domain+'<=>'+name+'< ; >'+typee+'<=>'+typ+'<')
        if domain == name and typee == typ:
            return (True, domain, clas, typee, result)
        else:
            pass

    return (False, """""", """""", """""", """""")


def stock(name, typ, clas, data):
    """"""

    file = open('/etc/bind/db.static', 'a')
    if typ == 1: # A
        file.write(name + '\t' + numbertoclas(clas) + '  ' + numbertotype(typ) + '\t' + str(data) + '\n')
    elif typ == 15: # MX 
        preference=data[0]
        answer=data[1]
        file.write(name + '\t' + numbertoclas(clas) + '  ' + numbertotype(typ) + '\t' + str(preference) + ' ' + str(answer) + '\n')
    elif typ == 2: # NS
        file.write(name + '\t' + numbertoclas(clas) + '  ' + numbertotype(typ) + '\t' + str(data) + '\n')
    else:
        pass
    file.close()



def contructDnsReplyTypA(domain, clas, typ, result):
    """"""

    print('\n\tenter : contructDnsReply')

    data = ""

  # id sur 2 octets
    data = data + struct.pack('>H', 0)

  # flag 2 octet 
    data = data + struct.pack('>H', 0x8180)

  # QDCOUNT sur 2 octets
    data = data + struct.pack('>H', 1)

  # ANCOUNT sur 2 octets
    data = data + struct.pack('>H', 1)

  # NScount su 2 octets
    data = data + struct.pack('>H', 0)  # ToDo quand type = NS ou MX

  # ARcount su 2 octets
    data = data + struct.pack('>H', 0)  # ToDo quand type = NS ou MX

    nb_octet = 12

  # non de domaine su x octets
    splitname = domain.split('.')
    for c in splitname:
        data = data + struct.pack('B', len(c))
        nb_octet = nb_octet + 1
        for l in c:
            data = data + struct.pack('c', l)
            nb_octet = nb_octet + 1

  # 1 octet = 00 pr dire la fin du nom de dommaine
    data = data + struct.pack('B', 0)

  # TYPE
    data = data + struct.pack('>H', typenumber(typ))

  # CLASS
    data = data + struct.pack('>H', clasnumber(clas))

    # DONNES
    data += struct.pack('>HHHIH4B', 0xc00c, typenumber(typ), clasnumber(clas), 60000, 4, *(int(x) for x in result.split('.')) )
    

    print ('\n\tsortie : contructDnsRequest : DATA= ' + str(data) + '\n')
    return data


def contructDnsReplyTypMX(domain, clas, typ, result, pref, add):
    """"""

    print('\n\tenter : contructDnsReplyMX')

    data = ""

  # id sur 2 octets
    data = data + struct.pack('>H', 0)

  # flag 2 octet 
    data = data + struct.pack('>H', 0x8180)

  # QDCOUNT sur 2 octets
    data = data + struct.pack('>H', 1)

  # ANCOUNT sur 2 octets
    data = data + struct.pack('>H', 1)

  # NScount su 2 octets
    data = data + struct.pack('>H', 0)  # ToDo quand type = NS ou MX

  # ARcount su 2 octets
    data = data + struct.pack('>H', add)  # ToDo quand type = NS ou MX

    nb_octet = 12

  # non de domaine su x octets
    splitname = domain.split('.')
    for c in splitname:
        data = data + struct.pack('B', len(c))
        nb_octet = nb_octet + 1
        for l in c:
            data = data + struct.pack('c', l)
            nb_octet = nb_octet + 1

  # 1 octet = 00 pr dire la fin du nom de dommaine
    data = data + struct.pack('B', 0)

  # TYPE
    data = data + struct.pack('>H', typenumber(typ))

  # CLASS
    data = data + struct.pack('>H', clasnumber(clas))

    # DONNES
    data_len=2+len(result.split('.')[0])+1+2
    data = data + struct.pack('>HHHIHH', 0xc00c, typenumber(typ), clasnumber(clas), 60000, data_len, pref )

    data = data + struct.pack('B', len(result.split('.')[0]))
    for char in result.split('.')[0]:
        data = data + struct.pack('c', char)
    data = data + struct.pack('>H', 0xc00c)

    print ('\n\tsortie : contructDnsRequestMX : DATA= ' + str(data) + '\n')
    return data



def contructDnsReplyTypNS(domain, clas, typ, result, add):
    """"""

    print('\n\tenter : contructDnsReplyNS')

    data = ""

  # id sur 2 octets
    data = data + struct.pack('>H', 0)

  # flag 2 octet 
    data = data + struct.pack('>H', 0x8180)

  # QDCOUNT sur 2 octets
    data = data + struct.pack('>H', 1)

  # ANCOUNT sur 2 octets
    data = data + struct.pack('>H', 1)

  # NScount su 2 octets
    data = data + struct.pack('>H', 0)  # ToDo quand type = NS ou MX

  # ARcount su 2 octets
    data = data + struct.pack('>H', add)  # ToDo quand type = NS ou MX

    nb_octet = 12

  # non de domaine su x octets
    splitname = domain.split('.')
    for c in splitname:
        data = data + struct.pack('B', len(c))
        nb_octet = nb_octet + 1
        for l in c:
            data = data + struct.pack('c', l)
            nb_octet = nb_octet + 1

  # 1 octet = 00 pr dire la fin du nom de dommaine
    data = data + struct.pack('B', 0)

  # TYPE
    data = data + struct.pack('>H', typenumber(typ))

  # CLASS
    data = data + struct.pack('>H', clasnumber(clas))

    # DONNES
    data_len=2+len(result.split('.')[0])+1+2
    data = data + struct.pack('>HHHIH', 0xc00c, typenumber(typ), clasnumber(clas), 60000, data_len )

    data = data + struct.pack('B', len(result.split('.')[0]))
    for char in result.split('.')[0]:
        data = data + struct.pack('c', char)
    data = data + struct.pack('>H', 0xc00c)

    print ('\n\tsortie : contructDnsRequestNS : DATA= ' + str(data) + '\n')
    return data


def contructDnsReplyTypMXAdd(clas_add, typee_add, result_add):
    """"""

    #0xc028 car vus sur le wireshark
    return struct.pack('>HHHIH4B', 0xc028, typenumber(typee_add), clasnumber(clas_add), 60000, 4, *(int(x) for x in result_add.split('.')) )


def contructDnsReplyTypNSAdd(clas_add, typee_add, result_add):
    """"""

    #0xc028 car vus sur le wireshark
    return struct.pack('>HHHIH4B', 0xc028, typenumber(typee_add), clasnumber(clas_add), 60000, 4, *(int(x) for x in result_add.split('.')) )


i = 12

def retrquest(string, pos):
    """decrit une section question presente dans la reponse DNS string a la position pos"""

    p = pos
    (p, name) = getname(string, p)
    typ = struct.unpack('>H', string[p:p + 2])[0]
    p = p + 2
    clas = struct.unpack('>H', string[p:p + 2])[0]
    p = p + 2
    
    return (p, name, typ, clas)


def retrrr(string, pos):
    """decrit une section resource record presente dans la reponse DNS string a la position pos"""

    p = pos
    (p, name) = getname(string, p)
    typ = struct.unpack('>H', string[p:p + 2])[0]
    p = p + 2
    clas = struct.unpack('>H', string[p:p + 2])[0]
    p = p + 2
    ttlcpl = struct.unpack('>HH', string[p:p + 4])
    p = p + 4
    datalen = struct.unpack('>H', string[p:p + 2])[0]
    p = p + 2
    if typ == 1:
        aux = struct.unpack('B' * datalen, string[p:p + datalen])
        dat = str(aux[0]) + '.' + str(aux[1]) + '.' + str(aux[2]) + '.' \
            + str(aux[3])
    if typ == 2:
        (x, dat) = getname(string, p)
    if typ == 15:
        pref = struct.unpack('>H', string[p:p + 2])[0]
        (x, name) = getname(string, p + 2)
        dat = (pref, name)
    if typ not in [1, 2, 15]:
        dat = struct.unpack('B' * datalen, string[p:p + datalen])
    p = p + datalen
    print ('\n\tsortie : retrrr : p= ' + str(p) + ' name = ' + str(name) + ' typ= ' + str(typ) + ' clas= ' + str(clas) + ' ttl =' + str(ttlcpl[0] * 256 + ttlcpl[1]) + ' datalenght= ' + str(datalen) + ' dat= ' + str(dat) + '\n')
    return (p,name,typ,clas,ttlcpl[0] * 256 + ttlcpl[1],datalen,dat)


def printTheEnd():
    """affichage de la fin"""
    print('\n\n=========================== The end ... ===========================')
    print('\n\n+-----------------------------------+') 
    print('|                                   |')
    print('|         PROXY : Listen 80         |')
    print('|                                   |')
    print('+-----------------------------------+\n\n')


def infoToStock(data,qdcount,ancount,nscount,arcount):

    i = 12
    data_answer = 'null'
    if qdcount:
        print('QUERY SECTION :\n')
        for j in range(qdcount):
            (pos, name_answer, typ_answer, clas_answer) = retrquest(data, i)
            i = pos
            print (name_answer + '   ' + numbertotype(typ_answer) + '   ' + str(clas_answer))
        print ('\n')

    if ancount:
        print('ANSWER SECTION :\n')
        for j in range(ancount):
            (pos,name,typ,clas,ttl,datalen,data_answer) = retrrr(data, i)
            i = pos
            if typ == 15:
                print(name + '   ' + numbertotype(typ) + '   ' + str(clas) + '   ' + str(ttl) + '   ' + str(data_answer[0]) + '   ' + data_answer[1])
            else:
                print(name + '   ' + numbertotype(typ) + '   ' + str(clas) + '   ' + str(ttl) + '   ' + str(data_answer))
        print ('\n')

    if nscount:
        print('AUTHORITY SECTION :\n')
        for j in range(nscount):
            (pos,name_authority,typ_authority,clas_authority,ttl,datalen,data_authority) = retrrr(data, i)
            i = pos
            print ('...... data_autorytity = >'+data_authority+'<')
            # print(name+"   "+numbertotype(typ)+"   "+str(clas)+"   "+str(ttl)+"   "+"str(dat)=...")
        stock(name_authority, typ_authority, clas_authority, data_authority)
        print ('\n')

    if arcount:
        print ('ADDITIONAL SECTION :\n')
        for j in range(arcount):
            (pos,name_additional,typ_additional,clas_additional,ttl,datalen,data_additional,) = retrrr(data, i)
            i = pos
            print(name_additional + '   ' + numbertotype(typ_additional) + '   ' + str(clas_additional) + '   ' + str(ttl) + '   ' + str(data_additional))
        stock(name_additional, typ_additional, clas_additional, data_additional)
        print ('\n')
    
    return (name_answer, typ_answer, clas_answer, data_answer)



while True:
    (data, addr) = s.accept()
    print ('Data : ' + str(data) + 'addr : ' + str(addr))

    requete = data.recv(1024)

    protocol = requete.split(' ')[0]
    ctlProtocolGet(protocol)

    varible = (requete.split('?')[1])[:3]
    ctlVariableDns(varible)

    dns_b64encode = requete.split('dns=')[1].split(' ')[0]
    dns_b64decode = base64.b64decode(dns_b64encode, '-_')

    (name, typ, clas) = getNameDomaine(dns_b64decode)
    print ('\nRequete : ' + name + '\t' + numbertoclas(clas) + '  ' + numbertotype(typ) + '\n')

    (is_known, domain, clas, typee, result) = Isknown(name,numbertotype(typ))
    print("iskown result : "+result)

    test = 0
    if is_known and test == 0:
        print ('db.static : ' + domain + '\t' + clas + '  ' + typee + '\t' + result)

        if typee=='A':
            requete_dns = contructDnsReplyTypA(domain, clas, typee, result)
        elif typee=='MX':
            pref=int(result.split(' ')[0])
            result=result.split(' ')[1][:-1]
            add=0

            # recher si dans le cache partie additional
            print("recherche add ? >"+str(result)+'< '+numbertotype(1))
            (is_known_add, domain_add, clas_add, typee_add, result_add) = Isknown(str(result),'A')
            if is_known_add:
                print('>oui')
                add=1
                requete_dns = contructDnsReplyTypMX(domain, clas, typee, result, pref, add)
                requete_dns = requete_dns + contructDnsReplyTypMXAdd(clas_add, typee_add, result_add)
            else :
                requete_dns = contructDnsReplyTypMX(domain, clas, typee, result, pref, add)
        elif typee=='NS':
            print("recherche add NS ? >"+str(result)+'< '+numbertotype(1))
            result=result[:-1]
            add=0
            (is_known_add, domain_add, clas_add, typee_add, result_add) = Isknown(str(result),'A')
            if is_known_add: 
                print('>oui = '+result_add)
                #add=1
                requete_dns = contructDnsReplyTypNS(domain, clas, typee, result, add)

                # pb dans la construction du contructDnsReplyTypNSAdd
                #requete_dns = requete_dns + contructDnsReplyTypNSAdd(clas_add, typee_add, result_add)
            else :
                requete_dns = contructDnsReplyTypNS(domain, clas, typee, result, add)
        else: 
            pass
        
        leng = len(requete_dns)
        print('\n\n=====>len req cree ='+str(leng))
        sendToAlice(requete_dns, data, leng)

        print ('\n/-------------------------\              |~~\_____/~~\__  |')
        print ('|     REPLY TO ALICE      |______________ \______====== )-+')
        print ('| whith data in db.static |                      ~~~|/~~  |')
        print ('\-------------------------/                         ()\n')

        data.close()
        printTheEnd()

    else:
        t = socket(AF_INET, SOCK_DGRAM)
        t.connect(('1.2.3.4', 53))
        print ('\nConnected to ispA = 1.2.3.4 port 53')

        requete_dns = contructDnsRequest(name, numbertotype(typ))

        t.send(requete_dns)

        print('   _____________ _')
        print(' _/_|[][][][][] |--')
        print('(  ask IspA dns |--- -')
        print('=--OO-------OO--=-- ---\n')

        data_recv = t.recv(1024)
        leng = len(data_recv)
        sendToAlice(data_recv, data, leng)

        print ('\n/-------------------------\              |~~\_____/~~\__  |')
        print ('|     REPLY TO ALICE      |______________ \______====== )-+')
        print ('|        tk IspA          |                      ~~~|/~~  |')
        print ('\-------------------------/                         ()\n')

        data.close()

        print("\n######################\n#       Descrip      #\n######################\n")
      # decriptage pour le metre dans la bdd

        data = data_recv
        header = struct.unpack('>HBBHHHH', data[:12])
        qdcount = header[3]
        ancount = header[4]
        nscount = header[5]
        arcount = header[6]

      # Affichage de la reponse, section par section
        print ('QUERY: ' + str(qdcount) + ', ANSWER: ' + str(ancount) + ', AUTHORITY: ' + str(nscount) + ', ADDITIONAL: ' + str(arcount) + '\n')

        (name_answer, typ_answer, clas_answer, data_answer) = infoToStock(data,qdcount,ancount,nscount,arcount)

        if data_answer != 'null':
            print('\n A STOCKE : ' + name_answer + '\t' + numbertotype(typ_answer) + '  ' + str(clas_answer) + '\t' + str(data_answer) + '\n')
            stock(name_answer, typ_answer, clas_answer, data_answer)

            

        t.close()
        printTheEnd()





##
#  	
#	
#
#
#
##