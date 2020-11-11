#!/usr/bin/python
##
#  PROXY doh to dns
##
from socket import *
from select import select
from sys import argv 

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

def ctlGet(protocol):
    """verifie que le protocole soit bien du GET"""
    try :
        if protocol <> 'GET':
            raise ProtocolNotGet("Protocole n'est pas GET")
        print("OK protocole = GET")
    except ProtocolNotGet :
        print("Protocole utiniser est incorect, le seul autorise est GET")	

def ctlVariableDns(var):
    """verifie que la variable soit dns"""
    try :
        if var <> 'dns':
            raise VariableNotDns("Variable n'est pas dns")
        print("OK variable = dns")
    except VariableNotDns :
        print("La variable est incorect, la seul autorise est dns")	







while True:
    (data,addr)=s.accept()
    print ("Data : " + str(data) + "addr : "+str(addr) )

    requete=data.recv(1024)
    print("requete : "+str(requete))    

    protocol=requete.split(' ')[0]
    print("protocole = "+protocol)
    ctlGet(protocol)

    varible=requete.split('?')[1][:3]
    print("variable = "+varible)
    ctlVariableDns(varible)

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



