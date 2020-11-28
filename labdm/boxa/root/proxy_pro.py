#!/usr/bin/python
# -*- coding: utf-8 -*-

##
#  	
#	Titre : PROXY doh to dns
#   URL   : https://github.com/Mathieu915/dm_reseau
#   Date édition     : 10/11/2020  
#   Date mise à jour : 29/11/2020 
#   Rapport de la maj :
#   	- correction dans ctlVariableDns(requete) pour bien recuperer la var et pas que les 3 premiers char
#	
#	ToDo :
# 		- fini
#
##


print("\n\n")
print("=========================== Starting proxy ============================\n")
print("Author:        CLAVIE Mathieu & CHEVALIER Thomas")
print("Email:         mathieu.clavie@etu.univ-orleans.fr ")
print("               & thomas.chevalier1@etu.univ-orleans.fr")
print("Web:           https://github.com/Mathieu915/dm_reseau")
print("Description:   ")
print("     Proxy DOH to DNS\n")
print("     /!\ Parie bonus : on a implementé l'ajout de nouveaux ")
print("     enregistrement dans le cache (=/etc/bind/db.static)... \n")
print("     Donc on ne pose que une seule fois la question dns à IspA")
print("     si IspA ramene une section réponse.")
print("\n=======================================================================")


from socket import *
import base64
import struct

# Socket TCP pour une liaison avec Alice
s = socket(AF_INET, SOCK_STREAM)
s.bind(('0.0.0.0', 80)) 
s.listen(3)


print ("\n\n+-----------------------------------+\n|                                   |\n|         PROXY : Listen 80         |\n|                                   |\n+-----------------------------------+\n\n")


###############################
#                             #
#    Exception/code erreur    #
#                             #
###############################

class ProtocolNotGet(Exception):
    #code erreur: 801 : Le protocole est incorect, le seul autorise est GET.
    pass

class VariableNotDns(Exception):
    #code erreur: 802 : La variable est incorect, la seul autorise est dns.
    pass

class CannotIdentifyProtocol(Exception):
    #code erreur: 803 : Le protocole n'est pas identifiable.
    pass

class CannotIdentifyVarible(Exception):
    #code erreur: 803 : La variable n'est pas identifiable.
    pass

###############################
#                             #
#     Def fonction : PROF     #     c'est les fonctions du clien que l'on repri mais pas modifié
#                             #
###############################

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

# copie de dnsrequete(name, typ)
def contructDnsRequest(name, typ):
    """"construction de la requete demandant les enregistrements de type typ pour le nom de domaine name"""

    data = ""

    data = data + struct.pack('>H', 0)
    data = data + struct.pack('B', 1)
    data = data + struct.pack('B', 0)
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
    data = data + struct.pack('>H', typenumber(typ))
    data = data + struct.pack('>H', 1)

    return data


##
#   Fonction utilisé pour stocker dans le cache (=db.static) les nouveaux enregistrement ramner par IspA
##
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
    return (p,name,typ,clas,ttlcpl[0] * 256 + ttlcpl[1],datalen,dat)



###############################
#                             #
#     Def fonction : NOUS     #
#                             #
###############################

def ctlProtocolGet(requete):
    """Verifie que le protocole soit bien du GET"""
    try:
        protocol = requete.split(' ')[0]
    except:
        raise CannotIdentifyProtocol("Protocole ne peux etre identifié")
    if protocol != 'GET':
        raise ProtocolNotGet("Protocole n'est pas GET")


def ctlVariableDns(requete):
    """ Verifie que la variable soit dns"""
    try:
        varible = (requete.split('?')[1]).split('=')[0]
    except:
        raise CannotIdentifyVarible("Variable ne peux etre identifié")
    if varible != 'dns':
        raise VariableNotDns("Variable n'est pas dns")


def sendToCustomerError(s, num_error):
    """envoie sur la socket s un code erreur"""
    s.send("""HTTP/1.0 %s ERROR
""" % (num_error,) ) 


def getNameDomaine(data):
    """Retourner le nom de dommaine, le type et la classe de la requete"""

    #header = struct.unpack('>HBBHHHH', data[:12])
    (pos, name, typ, clas) = retrquest(data, 12)
    return (name, typ, clas)


def sendToCustomer(data, s, leng):
    """envoie sur la socket s la requete Dns"""
    s.send("""HTTP/1.0 200 OK
Content-Type: application/dns-message
Content-Length: %s

%s
""" % (leng, data))


def Isknown(name, typ):
    """ Verircation dans le cache(= le fichier db.static) si un enregistrement avec le nom de domaine (=name) et le type (=typ) est deja present dans le fichier. Retourne vrai/faux puis l'enregistre si il existe sous forme d'un tuple."""

    # stock les lignes du ficher db.static dans un tableau
    file = open('/etc/bind/db.static', 'r')
    tab = file.readlines()
    file.close()

    for ligne in tab:
        # on extrait pour chaque ligne le nom de domaine, le type, la classe et le resultat
        domain = ligne.split('\t')[0]
        typee = ligne.split('\t')[1].split('  ')[1]
        clas = ligne.split('\t')[1].split('  ')[0]
        result = ligne.split('\t')[2]
        
        if domain == name and typee == typ:
            return (True, domain, clas, typee, result)
        else:
            pass
    return (False, """""", """""", """""", """""")


def contructDnsReplyHeader(domain, clas, typ, add=0):
    """ construction de l'entete de la requete de la reponse pour les enregistrements du nom de domaine (=domain), de la classe (=clas), du type (=typ) et add correspond à l'octet pour la section additionel par defaut il n'y en aura pas donc (=0)"""

    data = ""

    # id sur 2 octets
    data = data + struct.pack('>H', 0)

    # flag 2 octet : reponse correcte
    data = data + struct.pack('>H', 0x8180)

    # QDCOUNT sur 2 octets : question
    data = data + struct.pack('>H', 1)

    # ANCOUNT sur 2 octets : section reponse est bien presente
    data = data + struct.pack('>H', 1)

    # ARcount su 2 octets : section additionel depends de add qui prend les valeurs 0 (=pas de section) et 1 (= une section additionel)
    data = data + struct.pack('>H', add)   

    # ARcount su 2 octets : pas de section additionelle
    data = data + struct.pack('>H', 0)  

    # decoupage du nom de domaine selon les '.'
    splitname = domain.split('.')
    for c in splitname:
        data = data + struct.pack('B', len(c)) # on dit de combien de character est le prochain mot
        for l in c:
            data = data + struct.pack('c', l) # ajoute à data le charactere c codé en octet

    # 1 octet = 00 pour dire que c'est la fin du nom de dommaine
    data = data + struct.pack('B', 0)

    # type sous le format numerique
    data = data + struct.pack('>H', typenumber(typ))

    # CLASS 1 (IN) par defaut
    data = data + struct.pack('>H', clasnumber(clas))

    return data


def contructDnsReplyHeaderData(typ, clas, result):
    """constrie le debut de la section reponse de la requete dns selon le type et la classe"""

    data = ""

    # nom de domaine compreser : sur 16bits: le pointeur sur 2 bits: 11 suivie de la position du nom de domaine dans la requete dns, toujours a la meme place, apres l'entête qui fait 12 octets, les 14 bit suivant sont : 00 0000  0000 0000 1100 (= c00c en octet)
    data += struct.pack('>H', 0xc00c)

    # type sous le format numerique
    data += struct.pack('>H', typenumber(typ))

    # class 1 (IN) par defaut
    data += struct.pack('>H', clasnumber(clas))

    # ttl sur 4 octets = 16h 40min 00sec 
    data += struct.pack('>I', 60000)

    return data


def contructDnsReplyDataResult(result):
    """constri le nom de domaine de la question"""

    data = ""

    # on dit de combien de character est le prochain mot
    data = data + struct.pack('B', len(result.split('.')[0]))
    for char in result.split('.')[0]:
        data = data + struct.pack('c', char) # ajoute à data le charactere c codé en octet
    
    # nom de domaine compreser 
    data = data + struct.pack('>H', 0xc00c)

    return data


def contructDnsReplyTypA(domain, clas, typ, result):
    """construction de la requete de reponse pour les enregistrements du nom de domaine (=domain), de la classe (=clas), du type (=typ=A) et du resultat (=result)"""

    # entête de la requete dns
    data = contructDnsReplyHeader(domain,clas,typ)

    # données : nom de domaine compresé, le type, la classe et le ttl de 60 000sec
    data += contructDnsReplyHeaderData(typ, clas, result)

    # data lenght = 4 car ipV4 x.y.z.t
    data += struct.pack('>H', 4)

    # reponse de la requete, addr ipV4
    for x in result.split('.'):
        data += struct.pack('>B', int(x))
    
    return data


def contructDnsReplyTypMX(domain, clas, typ, result, pref, add):
    """construction de la requete de reponse pour les enregistrements du nom de domaine (=domain), de la classe (=clas), du type (=typ=MX), resultat (=result), preference (=pref) et add correspond à l'octet pour la section additionel"""

    # entête de la requete dns
    data = contructDnsReplyHeader(domain,clas,typ,add)

    # données : nom de domaine compresé, le type, la classe et le ttl de 60 000sec
    data += contructDnsReplyHeaderData(typ, clas, result)

    # data lenght = 2 (= 2 octets pour la preference) + 1 (= octet pour décrir la taille du mot) + x (= octets pour le mot) + 2 (= )
    data_len = 2 + 1 + len(result.split('.')[0]) + 2
    data += struct.pack('>H', data_len)

    # preference sur 2 octets
    data += struct.pack('>H', pref )

    # la reponse : ecriture du nom de domaine de reponse comprésé
    data += contructDnsReplyDataResult(result)

    return data


def contructDnsReplyTypNS(domain, clas, typ, result, add):
    """construction de la requete de reponse pour les enregistrements du nom de domaine (=domain), de la classe (=clas), du type (=typ=MX), resultat (=result), preference (=pref) et add correspond à l'octet pour la section additionel"""

    # entête de la requete dns
    data = contructDnsReplyHeader(domain, clas, typ, add)

    # données : nom de domaine compresé, le type, la classe et le ttl de 60 000sec
    data += contructDnsReplyHeaderData(typ, clas, result)

    data_len = 2 + 1 + len(result.split('.')[0]) + 2
    data += struct.pack('>H', data_len)

    # la reponse : ecriture du nom de domaine de reponse comprésé
    data += contructDnsReplyDataResult(result)

    return data


def contructDnsReplyTypMXAdd(clas_add, typee_add, result_add, position_name_add):
    """contruction de la partie additionel pour un enregistre de type MX"""

    data = ""

    # on dit où se situe le nom de domaine de la partie additionel
    data += struct.pack('>H', position_name_add)

    # comme pour une requete dns de type A ...
    data += struct.pack('>H', typenumber(typee_add))
    data += struct.pack('>H', clasnumber(clas_add))
    data += struct.pack('>I', 60000)
    data += struct.pack('>H', 4)
    for x in result_add.split('.'):
        data += struct.pack('>B', int(x))
    
    return data


def getPositionNameAdd(domain_add, requete_dns):
    """retourne la position (décimal) du nom de domaine dans la requete dns"""

    # le nom de domaine pour la partie additionel est la reponse de la requete dns, du-coup ce nom se situe juste a la fin de la requete_dns
    len_request = len(requete_dns) 
    len_domain_add = len(domain_add.split(".")[0]) # on ne recupere que la permiere partie du nom de domaine, celle qui a ete rajouter lors de la reponse ex: smtp par rapport a smtp.cold.net

    # 1 = 1 octet ou l'on code la longeur du mot, 2 = 2 octets qui correspond au nom de domaine de la question compresé (qui indique qu'il est situer en position 12 de la requete dns)
    len_domain_extension = 1 + 2

    position_name_add = len_request - (len_domain_add + len_domain_extension)

    # c000 en decimal = 49152
    # compresion du nom de domaine, les 2 premiers octets sont les 2 bits 11 sur 16 bits donc en décimal cela fait : 49152
    position_name_add += 49152

    return position_name_add



###############################
#                             #
#     Def fonction : bonus    #     les fonctions utilisé pour écrire dans db.static
#                             #
###############################


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


def stock(name, typ, clas, data):
    """on stock dans le cache (db.static) les nouvelles enter selon le type"""

    file = open('/etc/bind/db.static', 'a')
    if typ == 1 or typ == 2: # A ou NS
        file.write(name + '\t' + numbertoclas(clas) + '  ' + numbertotype(typ) + '\t' + str(data) + '\n')
        print(name + '\t' + numbertoclas(clas) + '  ' + numbertotype(typ) + '\t' + str(data))
    elif typ == 15: # MX 
        preference=data[0]
        answer=data[1]
        file.write(name + '\t' + numbertoclas(clas) + '  ' + numbertotype(typ) + '\t' + str(preference) + ' ' + str(answer) + '\n')
        print(name + '\t' + numbertoclas(clas) + '  ' + numbertotype(typ) + '\t' + str(preference) + ' ' + str(answer))
    else:
        # pour le dm on ne traitre pas les autre types
        pass
    file.close()
    

def infoToStock(data,qdcount,ancount,nscount,arcount):
    """stock en fonction des sections que ramene IspA lors d'une requete dns"""

    # reprise sous forme de fonction la fin du client qui permetait d'interpreter la reponse dns renvoyé par boxA

    i = 12 # on commence apres l'entete de la requete dns
    data_answer = 'null' # ini la raponse pour ne pas stocker les autres section si jamais pas de section reponse

    # partie de la question : on recupere le nom de domaine (=name_answer), le type (=typ_answer) et la classe (=clas_answer)
    if qdcount:
        for j in range(qdcount):
            (pos, name_answer, typ_answer, clas_answer) = retrquest(data, i)
            i = pos

    # partie reponse : on recupere la reponse de la requete dns (=data_answer) et sous forme de tuple si jamais le type est MX
    if ancount:
        for j in range(ancount):
            (pos,name,typ,clas,ttl,datalen,data_answer) = retrrr(data, i)
            i = pos

    # partie autoriter :
    if nscount:
        for j in range(nscount):
            (pos,name_authority,typ_authority,clas_authority,ttl,datalen,data_authority) = retrrr(data, i)
            i = pos

    # partie additionel : 
    if arcount:
        for j in range(arcount):
            (pos,name_additional,typ_additional,clas_additional,ttl,datalen,data_additional,) = retrrr(data, i)
            i = pos
    
    if data_answer != 'null':
        print('\nNouvelle(s) ligne(s) dans le cache : \n')

        # on stock les dans un nouveau enregistrement la reponse de la requete dns
        stock(name_answer, typ_answer, clas_answer, data_answer)

        # on stock en fonction de la presence des different autres sections 
        if nscount:
            stock(name_authority, typ_authority, clas_authority, data_authority)
        if arcount:    
            stock(name_additional, typ_additional, clas_additional, data_additional)


# on n'a pas traiter les section additionel pour un type = NS
def contructDnsReplyTypNSAdd(clas_add, typee_add, result_add, position_name_add):
    """"""
    # comme la fonction : contructDnsReplyTypMXAdd(...)
    pass

#i = 12


###############################
#                             #
#   Def fonction : affichage  #
#                             #
###############################

def printTheEnd():
    print('\n\n============================= The end ... =============================\n\n\n+-----------------------------------+\n|                                   |\n|         PROXY : Listen 80         |\n|                                   |\n+-----------------------------------+\n\n')

def printError():
    print('\n\n _____________________________\n/                             \\\n!    ERREUR requete client    !\n\_____________________________/\n')

def printErrorGet():
    print('\n\n _____________________________\n/                             \\\n!  Le protocole est incorect, !\n!  le seul autorise est GET   !\n\_____________________________/\n')


def printErrorDns():
    print('\n\n _____________________________\n/                             \\\n!  La variable est incorect,  !\n!  la seul autorise est dns   !\n\_____________________________/\n')

def printsendCustomer():
    print ('\n/-------------------------\              |~~\_____/~~\__  |\n|     REPLY TO CLIENT     |______________ \______====== )-+\n|        tk IspA          |                      ~~~|/~~  |\n\-------------------------/                         ()\n')

def printsendCustomerCache():
    print ('\n/-------------------------\              |~~\_____/~~\__  |\n|     REPLY TO CLIENT     |______________ \______====== )-+\n| whith data in db.static |                      ~~~|/~~  |\n\-------------------------/                         ()\n')

def printAskIspa():
    print('\n   _____________ _\n _/_|[][][][][] |--\n(  ask IspA dns |--- -\n=--OO-------OO--=-- ---\n')



while True:

    # accepte une socket à la fois puis stock la donnee dans requete
    (data, addr) = s.accept()
    requete = data.recv(1024)

    # Controle que le protocole de la requete soit bien du GET
    isCorretProtocol=True
    try:
        ctlProtocolGet(requete)
    except ProtocolNotGet:
        isCorretProtocol=False
        sendToCustomerError(data, 801)
        printErrorGet()
    except CannotIdentifyProtocol:
        isCorretProtocol=False
        sendToCustomerError(data, 803)
        printError()


    # Controle que la variable de la requete soit bien dns
    isCorretVariable=True
    try:
        ctlVariableDns(requete)
    except VariableNotDns:
        isCorretVariable=False
        sendToCustomerError(data, 802)
        printErrorDns()
    except CannotIdentifyVarible:
        isCorretVariable=False
        sendToCustomerError(data, 804)
        printError()

    if isCorretProtocol and isCorretVariable :

        # extrai le corps de la requete, puis on decode celui-ci de la basse 64
        dns_b64encode = requete.split('dns=')[1].split(' ')[0]
        dns_b64decode = base64.b64decode(dns_b64encode, '-_')

        # on recupere le nom de domaine le type et la classe pour ensuite aller verifier si l'on a pas deja un enregistrement dans le cache avec ces infos
        (name, typ, clas) = getNameDomaine(dns_b64decode)
        (is_known, domain, clas, typee, result) = Isknown(name,numbertotype(typ))

        if is_known :

            if typee=='A':
                requete_dns = contructDnsReplyTypA(domain, clas, typee, result)

            elif typee=='MX':
                pref=int(result.split(' ')[0])
                result=result.split(' ')[1][:-1] # 2eme partie de resultat et on suprime le retour à la linge
                add=0 # init de la section additionel vide

                # recherche si dans le cache il y a la partie additional (~ ip de serveur smtp)
                (is_known_add, domain_add, clas_add, typee_add, result_add) = Isknown(str(result),'A')
                if is_known_add:
                    add=1
                    requete_dns = contructDnsReplyTypMX(domain, clas, typee, result, pref, add)
                    position_name_add = getPositionNameAdd(domain_add, requete_dns)
                    requete_dns = requete_dns + contructDnsReplyTypMXAdd(clas_add, typee_add, result_add, position_name_add)
                else :
                    requete_dns = contructDnsReplyTypMX(domain, clas, typee, result, pref, add)

            elif typee=='NS':
                result=result[:-1] 
                add=0

                (is_known_add, domain_add, clas_add, typee_add, result_add) = Isknown(str(result),'A')
                if is_known_add:
                    pass 

                    ##
                    #   dans la config du lab actuel nous n'avons pas de partie aditionnel
                    #   pour une demande de type NS, donc pas de traitement
                    #   sinon un taitement du meme style que pour le type MX
                    ##

                    #requete_dns = contructDnsReplyTypNS(domain, clas, typee, result, add)
                    #position_name_add = getPositionNameAdd(domain_add, requete_dns)
                    #requete_dns = requete_dns + contructDnsReplyTypNSAdd(clas_add, typee_add, result_add, position_name_add)

                else :
                    requete_dns = contructDnsReplyTypNS(domain, clas, typee, result, add)
            else: 
                # pour le dm on ne traitre pas les autre types
                pass
            
            # on envoie au client la reponse que nous avons contruit sous la forme d'une requete dns
            leng = len(requete_dns)
            sendToCustomer(requete_dns, data, leng)

            printsendCustomerCache()

            # ferme la connexion avec le client
            data.close()
            printTheEnd()

        else:

            # Socket UDP pour contacter IspA 
            t = socket(AF_INET, SOCK_DGRAM)
            t.connect(('1.2.3.4', 53))
            # Connected to ispA = 1.2.3.4 port 53

            # on contruit puis envoie a IspA une requete dns
            requete_dns = contructDnsRequest(name, numbertotype(typ))
            t.send(requete_dns)

            printAskIspa()

            # on recoit la reponse de IspA puis on le renvoit directement au client
            data_recv = t.recv(1024)
            leng = len(data_recv)
            sendToCustomer(data_recv, data, leng)

            printsendCustomer()

            # ferme la connexion avec le client et avec IspA
            data.close()
            t.close()
            


            ##
            #   Partie bonnus :
            #   on va stocker en fonction des sections que ramene IspA lors d'une requete dns
            #   des nouvelles lignes dans le cache (=db.static)
            ##

            # décriptage pour reuperer savoir si il y a ses sections
            header = struct.unpack('>HBBHHHH', data_recv[:12])
            qdcount = header[3]
            ancount = header[4]
            nscount = header[5]
            arcount = header[6]
            infoToStock(data_recv,qdcount,ancount,nscount,arcount)

            printTheEnd()    
        
    else :
        # erreur dans la requete du client, donc on ferme sa connexion 
        data.close()
        printTheEnd()

