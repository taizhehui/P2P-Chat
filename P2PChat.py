#!/usr/bin/python3

# Student name and No.: Chin Cheuk Wing (3035239595)
# Student name and No.: Tai Zhe Hui (3035244239)
# Development platform: Sublime
# Python version: 3.7.1
# Version: 1.0

# PLEASE OPEN IT WITH SUBLIME SO THAT THE COMMENT IS NICE AND NEAT!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

# PLEASE NOTE THAT Tai Zhe Hui DID 80% OF THE WORK SO PLEASE GIVE THE MARK ACCORDINGLY!!!!!!!!!!!!!!!!!!!!!!

from tkinter import *
import sys
import socket
import _thread
import time
import threading

#
# Global variables
#

username = ""                   # store username
roomname = ""                   # store roomname
status = "not joined"           # initial status is not joined
membershipHashID = ""           # use this to check whether need to update membership list during keepalive procedure
membershipList = []             # membershipList = [ [username,IP,Port] , ......]
hashList = []                   # hashList = [ ( [username,IP,Port] , hash value),.........]
forwardLink = ()                # forward link = ( ( [username,IP,Port] , hash value), socket )
backwardLinks = []              # backward link = [ ( ( [username,IP,Port] , hash value), socket ),....... ]
sync_msg = threading.Lock()
messages = []                   # messages = [ (hash ID, msg ID) , .........] to check whether it is the new message
msgID = 0                       # message ID
myHashID = 0                    # my hash ID calculated by hash(username+myIP+myPort)

#Assume the server program also runs in the same machine as localhost chat program (same IP)
roomServerIP = sys.argv[1]
roomServerPort = sys.argv[2]
myIP = sys.argv[1]
myPort = sys.argv[3]

# create socket and connect to server
try:
        sockfd = socket.socket()
                # argv[1] = server IP; argv[2] = server port
        sockfd.connect((sys.argv[1], int(sys.argv[2])))
except socket.error as emsg:
        print("Socket error: ", emsg)
        sys.exit(1)

# create UDP socket to receive poke
try:
        sockUDP = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        sockUDP.bind((myIP,int(myPort)))
        # CmdWin.insert(1.0, "\nstart UDP server")
except socket.error as emsg:
        print("Socket error: ", emsg)
        sys.exit(1)

#
# This is the hash function for generating a unique
# Hash ID for each peer.
# Source: http://www.cse.yorku.ca/~oz/hash.html
#
# Concatenate the peer's username, str(IP address), 
# and str(Port) to form a string that be the input 
# to this hash function
#
def sdbm_hash(instr):
    hash = 0
    for c in instr:
        hash = int(ord(c)) + (hash << 6) + (hash << 16) - hash
    return hash & 0xffffffffffffffff


#
# Functions to handle user input
#

def do_User():
        outstr = "\n[User] username: "+userentry.get()

        # For modification of global variable "username"
        global username
        global sockfd

        # Get the user input for checking its validity
        temp = userentry.get()

        # only do the username change whenever status is neither "connected" or "joined" (not yet entered to a chatroom)
        if status != "connected" and status != "joined":
            # Check empty string
                # Empty string case
                if temp == "":
                        # Cmd display error
                        CmdWin.insert(1.0, "\nUsername cannot be empty string!")
                # Valid string case
                else:
                        # System display for successful registration
                        CmdWin.insert(1.0, outstr)
                        #display own ip addess and listening port
                        CmdWin.insert(1.0, "\nMy IP address: "+myIP+" My listening port: "+myPort)

                # Clear the textfield
                userentry.delete(0, END)

                # Store the valid username
                username = temp

        # cases when status is either "connected" or "joined" (user already entered to a chatroom) -> disapprove username change
        else:
                CmdWin.insert(1.0, "\nYou have been actively connected to a chatroom. Username cannot be changed!")


def do_List():
    msg = "L::\r\n"                             # create msg
    sockfd.send(msg.encode('ascii'))            # send msg
    rmsg = sockfd.recv(1024).decode('ascii')    # receive msg

    if rmsg[0] == 'G':                          # if success
        if rmsg[2] != ':':                          # if there is chatroom  
            rmsg = rmsg[2:-4]
            chatrooms = rmsg.split(":")                 # separate all the chatrooms
            for chatroom in chatrooms:                  # print active chatroom
                CmdWin.insert(1.0, "\n\t"+chatroom)
            CmdWin.insert(1.0, "\nActive chatrooms:")
        else:  
            CmdWin.insert(1.0, "\nNo active chatrooms")  
    elif rsmg[0] == 'F':
        CmdWin.insert(1.0, "\nError")

def do_Join():
    global status
    global membershipHashID
    global membershipList
    global roomname

    userEntry = userentry.get()
    if username == "":                                  # if no username, error
        CmdWin.insert(1.0, "\nEmpty username! Please enter your username before joining.")      
    elif userEntry == "":                               # if no entry, error
        CmdWin.insert(1.0, "\nEmpty chatroom name! Please enter chatroom name")
    elif status == "connected" or status == "joined":   # if already connected/joined to a chatroom, error
        CmdWin.insert(1.0, "\nAlready connected/joined a chatroom")
    else:                                               # if not yet connected to a chatroom
        roomname = userEntry
        msg = "J:"+roomname+":"+username+":"+ myIP+":"+myPort+"::"+"\r\n"   
        sockfd.send(msg.encode('ascii'))                    # send join request
        rmsg = sockfd.recv(1024).decode('ascii')            # receive response

        if rmsg[0] =='M':                                   # if response is membership list
            rmsg = rmsg[2:-4]
            members = rmsg.split(":")
            membershipHashID = members[0]                       # save membership hash ID
            for n in range(0, len(members[1:]), 3):
                member = members[1:][n:n+3]                     # member = [username, IP, Port]
                membershipList.append(member)                   # save member to membership list
                CmdWin.insert(1.0, "\n\t"+member[0])
            CmdWin.insert(1.0, "\nMembers in the chatroom:")
            CmdWin.insert(1.0, "\nJoined chatroom: "+roomname)
            status = "joined"

            findPeerToForwardLink()
            _thread.start_new_thread (keepListenIncomingConnection, ()) # keep listening to incoming TCP connection     
            _thread.start_new_thread (keepAliveProcedure, ())           # start keep alive procedure
            _thread.start_new_thread (start_UDP_server, ())
            
            userentry.delete(0, END)    

        elif rmsg[0] == 'F':
            CmdWin.insert(1.0, "\nFail to join")

def keepListenIncomingConnection():
    listeningSocket = socket.socket()                                               # create listening socket
    listeningSocket.bind(('',int(myPort)))                                          # bind
    listeningSocket.listen(5)                                                       # listen
    while listeningSocket:                                                          # while
        initiatingPeerSocket, addr = listeningSocket.accept()                           # new connection
        _thread.start_new_thread (acceptP2PHandShake, (initiatingPeerSocket, addr))     # start a thread to accept P2P handshake

def acceptP2PHandShake(initiatingPeerSocket, addr):
    global status
    # CmdWin.insert(1.0, "\nIncoming connection from "+str(addr))
    try:
        rmsg = initiatingPeerSocket.recv(1024).decode('ascii')
        if rmsg[0] == 'P':                                                              # receive P2P handshake message from initiating peer
            rmsg = rmsg[2:-4]
            initiatingPeerInfo = rmsg.split(":")
            initiatingPeerRoomname = initiatingPeerInfo[0]
            initiatingPeerUsername = initiatingPeerInfo[1]
            initiatingPeerIP = initiatingPeerInfo[2]
            initiatingPeerPort = initiatingPeerInfo[3]
            initiatingPeerMsgID =initiatingPeerInfo[4]

            exist = False
            for member in membershipList:
                if initiatingPeerInfo[1:4] == member:
                    exist = True
            if exist == False:                                                          # if unknown peer is not in member list
                updateMembershipListHashList()                                          # update member list
                for member in membershipList:
                    if initiatingPeerInfo[1:4] == member:
                        exist = True

            if exist:                                                                   # if unknown peer is in member list
                msg = "S:"+str(msgID)+"::\r\n"
                initiatingPeerSocket.send(msg.encode("ascii"))                              # send success message to initiating peer

                CmdWin.insert(1.0, "\n"+"[Backward] "+initiatingPeerUsername+" -> "+username)
                combine = initiatingPeerUsername + initiatingPeerIP + initiatingPeerPort
                backwardLinks.append(((initiatingPeerInfo[1:4],sdbm_hash(combine)),initiatingPeerSocket)) # add to backward link array
                status = "connected"                                                        # status = connected
                _thread.start_new_thread (checkPeerStatus, ("backward", initiatingPeerSocket, ))                                                      
            else:
                initiatingPeerSocket.close()
        else:
            initiatingPeerSocket.close()
    except:
        initiatingPeerSocket.close()


def keepAliveProcedure():
    while True:
        time.sleep(20)                                  # every 20 seconds
        updateMembershipListHashList()                  # resend join request
        if forwardLink == ():                           # if still does not have forward link
            findPeerToForwardLink()                     # find peer to forward link
            #CmdWin.insert(1.0, "\nfind peer to forwardLink")

def updateMembershipListHashList():
    global membershipHashID
    global membershipList
    global hashList

    msg = "J:"+roomname+":"+username+":"+myIP+":"+myPort+"::\r\n"
    sockfd.send(msg.encode('ascii'))                    # send join request
    rmsg = sockfd.recv(1024).decode('ascii')            # receive response
    if rmsg[0] =='M':                                   # if response is membership list
        rmsg = rmsg[2:-4]
        members = rmsg.split(":")
        if membershipHashID != members[0]:                  # if membership hash ID different

            membershipHashID = members[0]                       # update new membership hash ID

            membershipList = []                                 # clear old membership list
            for n in range(0, len(members[1:]), 3):             # for every 3 :
                member = members[1:][n:n+3]                         # member = [ username, IP, Port]
                membershipList.append(member)                       # save member to membership list

            hashList = []                                       # clear old hash list
            for member in membershipList:                       # for each member
                combine = ""                                    
                for info in member:                             
                    combine = combine + info                        # combine username, IP, Port
                hashList.append((member,sdbm_hash(combine)))        # calculate hash ID, save [([username, IP, Port],hash ID)] to hash list                 
            hashList = sorted(hashList, key=lambda member: member[1]) # sort hash list according to hash ID                                       
        
    elif rmsg[0] == 'F':                                # if response is not membership list (failed)
        CmdWin.insert(1.0, "\nFail to join")

def findPeerToForwardLink():
    global status
    global forwardLink
    global hashList
    global myHashID

    hashList = []                                                                   # clear old hash list
    for member in membershipList:                                                   # for each member
        combine = ""                                    
        for info in member:                             
            combine = combine + info                                                    # combine username, IP, Port
        hashList.append((member,sdbm_hash(combine)))                                    # calculate hash ID, save [([username, IP, Port],hash ID)] to hash list                 
    hashList = sorted(hashList, key=lambda member: member[1])                       # sort hash list according to hash ID 
    myHashID = sdbm_hash(username+myIP+myPort)                                      # calculate my hash ID
    start = (hashList.index(([username,myIP,myPort], myHashID)) + 1) % len(hashList)# use my hash ID to find its index in hash list

    while hashList[start][1] != myHashID:                                           # while current hash ID not equal to my hash ID
        exist = False
        for backwardLink in backwardLinks:
            if backwardLink[0][0] == hashList[start][0]:
                exist = True
        if exist:                                                                       # if there is a backward link between current member and backward link list
            start = (start + 1) % len(hashList)                                             # next member
            continue
        else:                                                                           # else
            peerSocket = socket.socket()                                                    # create a socket
            try:
                peerSocket.connect((hashList[start][0][1],int(hashList[start][0][2])))      # establish TCP connection to the member 
                # CmdWin.insert(1.0, "\nTry to TCP connection to Peer "+hashList[start][0][1]+" "+hashList[start][0][2])
            except:
                # CmdWin.insert(1.0, "\nPeer refuse to connect")
                start = (start + 1) % len(hashList) 
                continue    
            if peerSocket:                                                                  # if successfully established
                P2PHandShake = False
                try:                                                                    
                    msg = "P:"+roomname+":"+username+":"+myIP+":"+myPort+":"+str(msgID)+"::\r\n"
                    peerSocket.send(msg.encode('ascii'))                                        # send P2P handshaking request
                    rmsg = peerSocket.recv(1024).decode('ascii')                                # receive response
                    if rmsg[0] =='S':                                                           
                        P2PHandShake = True 
                        # CmdWin.insert(1.0, "\nHandshake success")
                    else:
                        CmdWin.insert(1.0, "\nHandshake fail")                                  
                except:
                    CmdWin.insert(1.0, "\nHandshake fail")
                if P2PHandShake:                                                                # if response P2P handshake successful
                    CmdWin.insert(1.0,"\n"+"[Forward] "+username+" -> " + hashList[start][0][0])
                    forwardLink = (hashList[start],peerSocket)                                      # save forward linked member info                                           
                    status = "connected"                                                            # update status to connected
                    _thread.start_new_thread (checkPeerStatus, ("forward", peerSocket, ))  
                    break
                else:                                                                           # else
                    peerSocket.close()                                                              # close connection
                    start = (start + 1) % len(hashList)                                             # next member
                    continue
            else:                                                                           # else
                peerSocket.close()                                                              # close connection
                start = (start + 1) % len(hashList)                                             # next member
                continue

def start_UDP_server():
    while(True):
        try:
            rmsg, addr = sockUDP.recvfrom(1024)         # receive UDP msg
            rmsg = rmsg.decode('ascii')
            if rmsg[0] == 'K':
                rmsg = rmsg[2:-4]                           # if msg is Poke Msg
                split = rmsg.split(":")
                display = "["+split[1]+"]"+"-----------Poke-----------"
                MsgWin.insert(1.0, "\n"+display)
                CmdWin.insert(1.0, "\nReceived poke from "+split[1])

                msg = "A::\r\n"
                sockUDP.sendto(msg.encode('ascii'),addr)    # send Poke ACK
                CmdWin.insert(1.0,"\nSend poke ACK to "+split[1])
        except socket.error as emsg:
            print("Socket error3: ", emsg)
            sys.exit(1)


def do_Send():
    #CmdWin.insert(1.0, "\nPress Send")

        userEntry = userentry.get()
        # for incrementing the global variable msgID
        global msgID

        # Make sure the user has typed something
        if userEntry != "":
            # check if the user has been connected or joined
            if status == "joined" or status == "connected":
                msgID = msgID + 1
                MsgWin.insert(1.0, "\n["+username+"] "+userEntry)

                # Below is for forwarding the typed msg to other peers for display
                # Message to be forwarded
                forward_msg = "T:"+roomname+":"+str(myHashID)+":"+username+":"+str(msgID)+":"+str(len(userEntry))+":"+userEntry+"::\r\n"
                # check if the localhost is connected with a forward linked peer
                if forwardLink:
                    # The msg will not be forwarded to its original user
                    if str(forwardLink[0][1]) != str(myHashID):
                        forwardLink[1].send(forward_msg.encode("ascii"))
                        CmdWin.insert(1.0,"\n1st Send msg to forward link "+str(forwardLink[0][0][0]))
        
                # Forward to backward linked peers if exist
                for i in backwardLinks:
                    # The msg will not be forwarded to its original user
                    if str(i[0][1]) != str(myHashID):
                        i[1].send(forward_msg.encode("ascii"))
                        CmdWin.insert(1.0,"\n1st Send msg to backward link "+str(i[0][0][0]))

            # user still remains at "not joined" status
            else:
                CmdWin.insert(1.0, "\nYou have not joined a chat yet! Failed to send message.")
        # no else condition --> program ignores as nothing has been typed in the textfield
        userentry.delete(0, END)


def do_Poke():

    userEntry = userentry.get()         
    if status == "not joined":                                                  # if not connected to a chatroom, error
        CmdWin.insert(1.0, "\nPlease connect to a chatroom before poking")
    elif userEntry == "":                                                   # if no entry, error
        for member in membershipList:
            CmdWin.insert(1.0, "\n"+member[0])                                  # display member list
        CmdWin.insert(1.0, "\nWho do you want to poke?")
    elif userEntry == username:                                             # if entry equal username, error
        CmdWin.insert(1.0, "\nCannot poke yourself")
    else:                                                                   # if connected to a chatroom
        exist = False
        for member in membershipList:
            if userEntry == member[0]:                                          # if entry is a member of chatroom
                msg = "K:"+roomname+":"+username+"::\r\n"
                sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
                sock.sendto(msg.encode('ascii'),(member[1],int(member[2])))     # send UDP Poke message
                CmdWin.insert(1.0, "\nSend poke to "+member[0])
                sock.settimeout(2)                                              # wait for 2 seconds
                try:
                    rmsg, addr = sock.recvfrom(1024)
                    rmsg = rmsg.decode('ascii')
                    if rmsg[0] == 'A':                                          # if returned message is ACK
                        CmdWin.insert(1.0,"\nReceived poke ACK")                    # display
                except socket.timeout:
                    CmdWin.insert(1.0, "\nDid not receive Poke ACK after 2 seconds")
                except socket.error as emsg:
                    CmdWin.insert(1.0, "\nSocket close")
                    print("Socket error4: ", emsg)
                sock.close()
                exist = True
        if exist == False:                                                  # else, error
            CmdWin.insert(1.0, "\nThere is not such member in the chatroom")    
    userentry.delete(0, END)

def checkPeerStatus(forward_or_back, incoming_socket):
    global forwardLink
    global backwardLinks
    global hashList
    global status
    global messages
    # Keep the following process alive if the connection is not broken
    while incoming_socket:
        try:
            # Start receiving messages from others
            recv_msg = incoming_socket.recv(1024)
            # Convert the received msg to string
            recv_msg = str(recv_msg.decode("ascii"))
            # Check if the received msg is an empty string
            # Received successfully as indicated by the protocol
            if recv_msg[0] == 'T':
                # Chunk the msg and store the partitions into an array
                recv_msg = recv_msg[2:-4]
                recv_msg_decode = recv_msg.split(":")
                roomInfo = recv_msg_decode[0]

                # If the received msg comes from the same room as the localhost
                if roomInfo == roomname:
                    
                    # Retrieve all the information from array storing the msg partitions
                    getHashID = recv_msg_decode[1]
                    getUsername = recv_msg_decode[2]
                    getMsgID = recv_msg_decode[3]
                    getMsgLength = recv_msg_decode[4]
                    getMsgContent = recv_msg[-(int(getMsgLength)):]
                    # To prevent duplication of the same msg from different peers in the same chatroom

                    sync_msg.acquire()
                    
                    CmdWin.insert(1.0, "\nReceived msg from "+getUsername)

                    exist_message = False
                    for msg in messages:
                        if (getHashID,getMsgID) == msg:
                            exist_message = True

                    if exist_message == False:             #If message has not been seen before, add it to msg window and store to messages array
                        MsgWin.insert(1.0, "\n["+getUsername+"] "+getMsgContent)
                        messages.append((getHashID, getMsgID))
                        sync_msg.release()                                  #Release lock since message has been appended

                        # Below is for forwarding the typed msg to other peers for display
                        # Message to be forwarded
                        forward_msg = "T:"+roomname+":"+str(getHashID)+":"+getUsername+":"+str(getMsgID)+":"+str(len(getMsgContent))+":"+getMsgContent+"::\r\n"
                        # check if the localhost is connected with a forward linked peer
                        if forwardLink:
                            # The msg will not be forwarded to its original user
                            if str(forwardLink[0][1]) != str(getHashID):
                                forwardLink[1].send(forward_msg.encode("ascii"))
                                CmdWin.insert(1.0,"\nSend msg to forward link "+str(forwardLink[0][0][0]))
                
                        # Forward to backward linked peers if exist
                        for i in backwardLinks:
                            # The msg will not be forwarded to its original user
                            if str(i[0][1]) != str(getHashID):
                                i[1].send(forward_msg.encode("ascii"))
                                CmdWin.insert(1.0,"\nSend msg to backward link "+str(i[0][0][0]))

                        exist_peer = False
                        for member in hashList:
                            if str(member[1]) == str(getHashID):
                                exist_peer = True 
                        if exist_peer == False:                              # if it is an unknown peer   
                            updateMembershipListHashList()                      # update membership and hash list
                    else:                                                    # this is a repeated message
                        sync_msg.release()                         
        except:
            incoming_socket.close()
            break

    CmdWin.insert(1.0, "\nConnection broken") 
    if forward_or_back == "forward":        # if the connection is forward              
        updateMembershipListHashList()          # update membership list and hash list        
        forwardLink = ()                        # reset the forward link
        status = "joined"                       # set back status to joined
        findPeerToForwardLink()                 # find new forward link
    else:                                   # else if the connection is backward
        for back in backwardLinks:              # remove the backwardlink from backwardlink array
            if back[1] == incoming_socket:
                backwardLinks.remove(back)
                break                

def do_Quit():
    #CmdWin.insert(1.0, "\nPress Quit")

    # Close the current client socket
    if sockfd:
        sockfd.close()
        CmdWin.insert(1.0,"\nThe client socket will be closed.")

    # Cut all connections with the backward linked peers
    for i in backwardLinks:
        i[1].close()
        CmdWin.insert(1.0,"\nDisconnecting with all backward linked peers.")
        
        # Cut the connection with the forward linked peer
    if forwardLink:
        forwardLink[1].close()
        CmdWin.insert(1.0,"\nDisconnecting with the forward linked peer.")

        # Program exit (Close the UI)
    sys.exit(0)


#
# Set up of Basic UI
#
win = Tk()
win.title("MyP2PChat")

#Top Frame for Message display
topframe = Frame(win, relief=RAISED, borderwidth=1)
topframe.pack(fill=BOTH, expand=True)
topscroll = Scrollbar(topframe)
MsgWin = Text(topframe, height='15', padx=5, pady=5, fg="red", exportselection=0, insertofftime=0)
MsgWin.pack(side=LEFT, fill=BOTH, expand=True)
topscroll.pack(side=RIGHT, fill=Y, expand=True)
MsgWin.config(yscrollcommand=topscroll.set)
topscroll.config(command=MsgWin.yview)

#Top Middle Frame for buttons
topmidframe = Frame(win, relief=RAISED, borderwidth=1)
topmidframe.pack(fill=X, expand=True)
Butt01 = Button(topmidframe, width='6', relief=RAISED, text="User", command=do_User)
Butt01.pack(side=LEFT, padx=8, pady=8);
Butt02 = Button(topmidframe, width='6', relief=RAISED, text="List", command=do_List)
Butt02.pack(side=LEFT, padx=8, pady=8);
Butt03 = Button(topmidframe, width='6', relief=RAISED, text="Join", command=do_Join)
Butt03.pack(side=LEFT, padx=8, pady=8);
Butt04 = Button(topmidframe, width='6', relief=RAISED, text="Send", command=do_Send)
Butt04.pack(side=LEFT, padx=8, pady=8);
Butt06 = Button(topmidframe, width='6', relief=RAISED, text="Poke", command=do_Poke)
Butt06.pack(side=LEFT, padx=8, pady=8);
Butt05 = Button(topmidframe, width='6', relief=RAISED, text="Quit", command=do_Quit)
Butt05.pack(side=LEFT, padx=8, pady=8);

#Lower Middle Frame for User input
lowmidframe = Frame(win, relief=RAISED, borderwidth=1)
lowmidframe.pack(fill=X, expand=True)
userentry = Entry(lowmidframe, fg="blue")
userentry.pack(fill=X, padx=4, pady=4, expand=True)

#Bottom Frame for displaying action info
bottframe = Frame(win, relief=RAISED, borderwidth=1)
bottframe.pack(fill=BOTH, expand=True)
bottscroll = Scrollbar(bottframe)
CmdWin = Text(bottframe, height='15', padx=5, pady=5, exportselection=0, insertofftime=0)
CmdWin.pack(side=LEFT, fill=BOTH, expand=True)
bottscroll.pack(side=RIGHT, fill=Y, expand=True)
CmdWin.config(yscrollcommand=bottscroll.set)
bottscroll.config(command=CmdWin.yview)

def main():
        if len(sys.argv) != 4:
                print("P2PChat.py <server address> <server port no.> <my port no.>")
                sys.exit(2)
        win.mainloop()

if __name__ == "__main__":
    main()

