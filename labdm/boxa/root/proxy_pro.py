#!/usr/bin/python
# -*- coding: utf-8 -*-

##
#  	
#	Titre : PROXY doh to dns
#   URL   : https://github.com/Mathieu915/dm_reseau
#   Date édition     : 10/11/2020  
#   Date mise à jour : 27/11/2020 
#   Rapport de la maj :
#   	- ...
#	
#	ToDo :
# 		- section additional quand rep depuis cache typ=NS
#  		- toute les def de fonction
#       - compression des noms de domaine dans db.static
##

print("\n\n")
print("========================== Starting proxy ==========================\n")
print("Author:        CLAVIE Mathieu & CHEVALIER Thomas")
print("Email:         mathieu.clavie@etu.univ-orleans.fr ")
print("               & thomas.chevalier1@etu.univ-orleans.fr")
print("Web:           https://github.com/Mathieu915/dm_reseau")
print("Description:   ")
print("     Proxy DOH to DNS")
print("     /!\ Parie bonus : on a implementé l'ajout de nouveaux enregistrement dans le cache (=/etc/bind/db.static)... ")
print("\n====================================================================")


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

    # id sur 2 octets
    data = data + struct.pack('>H', 0)

    # octet suivant : Recursion Desired
    data = data + struct.pack('B', 1)

    # octet suivant : 0
    data = data + struct.pack('B', 0)

    # QDCOUNT sur 2 octets : question 
    data = data + struct.pack('>H', 1)

    # pas les autres champs, car question
    data = data + struct.pack('>H', 0)
    data = data + struct.pack('>H', 0)
    data = data + struct.pack('>H', 0)

    # decoupage du nom de domaine selon les '.'
    splitname = name.split('.')
    for c in splitname:
        data = data + struct.pack('B', len(c)) # on dit de combien de character est le prochain mot
        for l in c:
            data = data + struct.pack('c', l) # ajoute à data le charactere c codé en octet

    # fin de l'ecriture du nom de domaine
    data = data + struct.pack('B', 0)

    # type sous le format numerique
    data = data + struct.pack('>H', typenumber(typ))

    # CLASS 1 (IN) par defaut
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
    print ('\n\tsortie : retrrr : p= ' + str(p) + ' name = ' + str(name) + ' typ= ' + str(typ) + ' clas= ' + str(clas) + ' ttl =' + str(ttlcpl[0] * 256 + ttlcpl[1]) + ' datalenght= ' + str(datalen) + ' dat= ' + str(dat) + '\n')
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
    varible = (requete.split('?')[1])[:3]
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



def contructDnsReplyTypA(domain, clas, typ, result):
    """construction de la requete de reponse pour les enregistrements du nom de domaine (=domain), de la classe (=clas), du type (=typ=A) et du resultat (=result)"""

    print ('\n\enter : contructDnsRequest')

    data = ""

    # id sur 2 octets
    data = data + struct.pack('>H', 0)

    # flag 2 octet : reponse correcte
    data = data + struct.pack('>H', 0x8180)

    # QDCOUNT sur 2 octets : question
    data = data + struct.pack('>H', 1)

    # ANCOUNT sur 2 octets : section reponse est bien presente
    data = data + struct.pack('>H', 1)

    # NScount su 2 octets : pas de section d'autorité
    data = data + struct.pack('>H', 0)  

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

    # DONNES
    data += struct.pack('>HHHIH4B', 0xc00c, typenumber(typ), clasnumber(clas), 60000, 4, *(int(x) for x in result.split('.')) )
    

    print ('\n\tsortie : contructDnsRequest : DATA= ' + str(data) + '\n')
    return data



def contructDnsReplyTypMX(domain, clas, typ, result, pref, add):
    """construction de la requete de reponse pour les enregistrements du nom de domaine (=domain), de la classe (=clas), du type (=typ=MX), resultat (=result), preference (=pref) et add correspond à l'octet pour la section additionel"""

    print('\n\tenter : contructDnsReplyMX')

    # meme expliction que pour la fonction contructDnsReplyTypA...

    data = ""
    data = data + struct.pack('>H', 0)
    data = data + struct.pack('>H', 0x8180)
    data = data + struct.pack('>H', 1)

    # ANCOUNT sur 2 octets : section reponse est bien presente
    data = data + struct.pack('>H', 1)
    data = data + struct.pack('>H', 0)  

    # ARcount su 2 octets : section additionel depends de add qui prend les valeurs 0 (=pas de section) et 1 (= une section additionel)
    data = data + struct.pack('>H', add)  

    splitname = domain.split('.')
    for c in splitname:
        data = data + struct.pack('B', len(c)) 
        for l in c:
            data = data + struct.pack('c', l) 

    data = data + struct.pack('B', 0)
    data = data + struct.pack('>H', typenumber(typ))
    data = data + struct.pack('>H', clasnumber(clas))

    # DONNEES

    data_len=2+len(result.split('.')[0])+1+2
    data = data + struct.pack('>HHHIHH', 0xc00c, typenumber(typ), clasnumber(clas), 60000, data_len, pref )

    data = data + struct.pack('B', len(result.split('.')[0]))
    for char in result.split('.')[0]:
        data = data + struct.pack('c', char)
    data = data + struct.pack('>H', 0xc00c)

    print ('\n\tsortie : contructDnsRequestMX : DATA= ' + str(data) + '\n')
    return data



def contructDnsReplyTypNS(domain, clas, typ, result, add):
    """construction de la requete de reponse pour les enregistrements du nom de domaine (=domain), de la classe (=clas), du type (=typ=MX), resultat (=result), preference (=pref) et add correspond à l'octet pour la section additionel"""

    print('\n\tenter : contructDnsReplyNS')

    # meme expliction que pour la fonction contructDnsReplyTypMX...

    data = ""
    data = data + struct.pack('>H', 0)
    data = data + struct.pack('>H', 0x8180)
    data = data + struct.pack('>H', 1)
    data = data + struct.pack('>H', 1)
    data = data + struct.pack('>H', 0)  # ToDo quand type = NS ou MX
    data = data + struct.pack('>H', add)  # ToDo quand type = NS ou MX

    splitname = domain.split('.')
    for c in splitname:
        data = data + struct.pack('B', len(c))
        for l in c:
            data = data + struct.pack('c', l)


    data = data + struct.pack('B', 0)
    data = data + struct.pack('>H', typenumber(typ))
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
    """contruction de la partie additionel pour un enregistre de type MX"""

    #0xc028 car vus sur le wireshark
    return struct.pack('>HHHIH4B', 0xc028, typenumber(typee_add), clasnumber(clas_add), 60000, 4, *(int(x) for x in result_add.split('.')) )



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
    if typ == 1: # A
        file.write(name + '\t' + numbertoclas(clas) + '  ' + numbertotype(typ) + '\t' + str(data) + '\n')
    elif typ == 15: # MX 
        preference=data[0]
        answer=data[1]
        file.write(name + '\t' + numbertoclas(clas) + '  ' + numbertotype(typ) + '\t' + str(preference) + ' ' + str(answer) + '\n')
    elif typ == 2: # NS
        file.write(name + '\t' + numbertoclas(clas) + '  ' + numbertotype(typ) + '\t' + str(data) + '\n')
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
        
        # on stock les dans un nouveau enregistrement la reponse de la requete dns
        stock(name_answer, typ_answer, clas_answer, data_answer)

        # on stock en fonction de la presence des different autres sections 
        if nscount:
            stock(name_authority, typ_authority, clas_authority, data_authority)
        if arcount:    
            stock(name_additional, typ_additional, clas_additional, data_additional)








# a supprimer !!!
def contructDnsReplyTypNSAdd(clas_add, typee_add, result_add):
    """"""

    #0xc028 car vus sur le wireshark
    return struct.pack('>HHHIH4B', 0xc028, typenumber(typee_add), clasnumber(clas_add), 60000, 4, *(int(x) for x in result_add.split('.')) )


i = 12








###############################
#                             #
#   Def fonction : affichage  #
#                             #
###############################

def printTheEnd():
    print('\n\n=========================== The end ... ===========================\n\n\n+-----------------------------------+\n|                                   |\n|         PROXY : Listen 80         |\n|                                   |\n+-----------------------------------+\n\n')

def printErrorGet():
    print('\n\n _____________________________\n/                             \\\n!  Le protocole est incorect, !\n!  le seul autorise est GET   !\n\_____________________________/\n')

def printErrorDns():
    print('\n\n _____________________________\n/                             \\\n!  La variable est incorect,  !\n!  la seul autorise est dns   !\n\_____________________________/\n')

def printsendCustomer():
    print ('\n/-------------------------\              |~~\_____/~~\__  |\n|     REPLY TO CLIENT     |______________ \______====== )-+\n|        tk IspA          |                      ~~~|/~~  |\n\-------------------------/                         ()\n')

def printsendCustomerCache():
    print ('\n/-------------------------\              |~~\_____/~~\__  |\n|     REPLY TO CLIENT     |______________ \______====== )-+\n| whith data in db.static |                      ~~~|/~~  |\n\-------------------------/                         ()\n')

def printAskIspa():
    print('   _____________ _\n _/_|[][][][][] |--\n(  ask IspA dns |--- -\n=--OO-------OO--=-- ---\n')



while True:

    # accepte une socket à la fois puis stock la donnee dans requete
    (client, addr) = s.accept()
    requete = client.recv(1024)

    # Controle que le protocole de la requete soit bien du GET
    isCorretProtocol=True
    try:
        ctlProtocolGet(requete)
    except ProtocolNotGet:
        isCorretProtocol=False
        sendToCustomerError(client, 801)
        printErrorGet()
    except CannotIdentifyProtocol:
        print('\n\n==========> CannotIdentifyProtocol \n\n')


    # Controle que la variable de la requete soit bien dns
    isCorretVariable=True
    try:
        ctlVariableDns(requete)
    except VariableNotDns:
        isCorretVariable=False
        sendToCustomerError(client, 802)
        printErrorDns()


    if isCorretProtocol and isCorretVariable :

        # extrai le corps de la requete, puis on decode celui-ci de la basse 64
        dns_b64encode = requete.split('dns=')[1].split(' ')[0]
        dns_b64decode = base64.b64decode(dns_b64encode, '-_')

        # on recupere le nom de domaine le type et la classe pour ensuite aller verifier si l'on a pas deja un enregistrement dans le cache avec ces infos
        (name, typ, clas) = getNameDomaine(dns_b64decode)
        #print ('\nRequete : ' + name + '\t' + numbertoclas(clas) + '  ' + numbertotype(typ) + '\n')
        (is_known, domain, clas, typee, result) = Isknown(name,numbertotype(typ))
        #print("iskown result : "+result)

        if is_known :
            #print ('db.static : ' + domain + '\t' + clas + '  ' + typee + '\t' + result)

            if typee=='A':
                requete_dns = contructDnsReplyTypA(domain, clas, typee, result)

            elif typee=='MX':
                pref=int(result.split(' ')[0])
                result=result.split(' ')[1][:-1] # 2eme partie de resultat et on suprime le retour à la linge
                add=0 # init de la section additionel vide

                # recherche si dans le cache il y a la partie additional (~ ip de serveur smtp)
                #print("recherche add ? >"+str(result)+'< '+numbertotype(1))
                (is_known_add, domain_add, clas_add, typee_add, result_add) = Isknown(str(result),'A')
                if is_known_add:
                    #print('>oui')
                    add=1
                    requete_dns = contructDnsReplyTypMX(domain, clas, typee, result, pref, add)
                    requete_dns = requete_dns + contructDnsReplyTypMXAdd(clas_add, typee_add, result_add)
                else :
                    requete_dns = contructDnsReplyTypMX(domain, clas, typee, result, pref, add)

            elif typee=='NS':
                #print("recherche add NS ? >"+str(result)+'< '+numbertotype(1))
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
                    #requete_dns = requete_dns + contructDnsReplyTypNSAdd(clas_add, typee_add, result_add)

                else :
                    requete_dns = contructDnsReplyTypNS(domain, clas, typee, result, add)
            else: 
                # pour le dm on ne traitre pas les autre types
                pass
            
            # on envoie au client la reponse que nous avons contruit sous la forme d'une requete dns
            leng = len(requete_dns)
            sendToCustomer(requete_dns, client, leng)

            printsendCustomerCache()

            # ferme la connexion avec le client
            client.close()
            printTheEnd()

        else:

            # Socket UDP pour contacter IspA 
            t = socket(AF_INET, SOCK_DGRAM)
            t.connect(('1.2.3.4', 53))
            print ('\nConnected to ispA = 1.2.3.4 port 53')

            # on contruit puis envoie a IspA une requete dns
            requete_dns = contructDnsRequest(name, numbertotype(typ))
            t.send(requete_dns)

            printAskIspa()

            # on recoit la reponse de IspA puis on le renvoit directement au client
            data_recv = t.recv(1024)
            leng = len(data_recv)
            sendToCustomer(data_recv, client, leng)

            printsendCustomer()

            # ferme la connexion avec le client et avec IspA
            client.close()
            t.close()
            printTheEnd()


            ##
            #   Partie bonnus :
            #   on va stocker en fonction des sections que ramene IspA lors d'une requete dns
            #   des nouvelles lignes dans le cache (=db.static)
            ##

            # CAHNGEMENT !! data = data_recv
            # decriptage pour reuperer savoir si il y a ses sections
            header = struct.unpack('>HBBHHHH', data_recv[:12])
            qdcount = header[3]
            ancount = header[4]
            nscount = header[5]
            arcount = header[6]
            infoToStock(data_recv,qdcount,ancount,nscount,arcount)    

#
#   /!\ stock diretement dans infoToStock
#
            #infoToStock(data_recv,qdcount,ancount,nscount,arcount)

            # Affichage de la reponse, section par section
            # print ('QUERY: ' + str(qdcount) + ', ANSWER: ' + str(ancount) + ', AUTHORITY: ' + str(nscount) + ', ADDITIONAL: ' + str(arcount) + '\n')

            # (name_answer, typ_answer, clas_answer, data_answer) = infoToStock(data,qdcount,ancount,nscount,arcount)

            # if data_answer != 'null':
            #     print('\n A STOCKE : ' + name_answer + '\t' + numbertotype(typ_answer) + '  ' + str(clas_answer) + '\t' + str(data_answer) + '\n')
            #     stock(name_answer, typ_answer, clas_answer, data_answer)

                

            
    else :
        # erreur dans la requete du client, donc on ferme sa connexion 
        client.close()
        printTheEnd()




##
#   TEST :  	
#	
# 1)   ./senddns.py -t A www.perdu.com
#      ---> ... 
#
# 2)   ./senddns.py -t MX cold.net
#      ---> IspA : OK Question/Answer/Autority/Additional
#      ---> Cache : OK Question/Answer/Additional
#
# 3)   ./senddns.py -t NS cold.net
#      ---> IspA : OK Question/Answer
#      ---> Cache : OK Question/Answer
#
# test si pas get
# test si pas dns
# 
#
#
##