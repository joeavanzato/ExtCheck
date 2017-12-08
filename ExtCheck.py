#Extension-Checker (ExtCheck)
#Joseph Avanzato, joeavanzato@gmail.com
#Simple script to check files against known file signatures stored in external file ('filesignatures.txt')
#Returns events if missing expected signature and checks files for other possible signatures
#Potential usage in determining mislabeled files (.exe labeled as .jpg, etc)
#Allows custom extensions, maximum size specifications and outputs detect/skip list to CWD in .txt
#Uses 'filesignatures.txt' to detect file signatures - text file contains rows consisting of 3 columns - Hex Signature, Expected Offset and associated Description/Extension
#Portions of this script are taken from an earlier version I wrote which had more features.  I edited out the non-pertinent sections and designed new logic for most of them to function correctly in this extension-checking scenario but certain deprecated elements remain.
#I'm trying to remove them all still without breaking things.

import os, ntpath, time, datetime, binascii
from re import split

#os for walking through filesystem and other validation aspects
#ntpath for normalizing Windows path
#time for initalizating time formats
#datetime same as above
#binascii for converting between hex/raw binary/other formats

global path #Tracks starting directory
global scansize #Tracks max file threshold 
global time2 #me being dumb
global skiplist #list of skipped files during scan
global detectlist #initializing now because later is a problem
global startdir  #Gets starting directory for file-writing
global exttype #Users input for manual extension specification

exttype = 0 #This gets changed if manual extension is used, otherwise current file extension is implemented
detectlist = [] #List of possible mis-matches
skiplist = [] #List of skipped files during scan
scansize = 0 
time2 = time.strftime("%H-%M(%m-%d-%Y)")
startdir = os.getcwd()

def maxSize(): #Determines max size for file scanning in megabytes
    global scansize
    scansize = input("Enter the threshold file size for scanning in MegaBytes (will skip files greater than): ")
    try:
        test = int(scansize)
    except ValueError:
        print("Error : Please enter a number...")
        maxSize()
    test = int(scansize) #Prepares test variable in integer format
    test = test*1000000 #converts megabytes to bytes for whole-integer less than comparison

    if (test < 1000000): #ensures input must be at least 1 megabyte
        print("Lowest Scanning Size is 1 MegaByte...")
        maxSize()

    else:
        print("Selected Threshold is "+scansize+" MegaBytes")
        scanforPE()
    
def start(): #Initializes program 
    binaryStart()

def binaryStart(): #Init
    loadSigs() #Loads file signatures, offsets and descriptions from filesignatures.txt in script home directory
    print("This mode allows the user to specify a signature file directly or select a malware binary for a file-system comparison")
    getPath2()
    printSigs()
    scanforPE()

def getPath2(): #Gets path for binary sample as user input, checks if valid file exist before succeeding
    global path
    path = input("Please enter full path for scan initialization : ")
    if (os.path.isdir(os.path.normpath(path)) == False) and (os.path.isfile(ntpath.basename(path)) == True):
        print("ERROR : PLEASE SPECIFY A DIRECTORY")
        getPath2()
    elif (os.path.isdir(os.path.normpath(path)) == True) and (os.path.isfile(ntpath.basename(path)) == False):
        print("Directory successfully located at "+path)
        print("Initiating signature scan...")
        #ScanDB()
    else:
        print("ERROR : PATH NOT FOUND")
        getPath2()


def extensionType(): #todo: add proper validation for this
    global exttype
    exttype = input("Please enter the desired extension ('wav', 'jpeg', 'mp3', etc : ")
    #exttype = str(exttype)

def scanforPE(): #Recursive file system scan for various extensions - logical tests for file/directory/path existence verifying user input
    global path
    global scanpath
    global skiplist
    global name2
    global curext
    skiplist = []
    if (scansize == 0):
        maxSize()
    scanpath = path
    ends = input("Search specific extension type (1) or all files (2)? :")
    if (int(ends) == 1):
        extensionType()
        print("Scanning from "+path+" for files posessing "+exttype+" extension..")
        for roots, subdirs, files in os.walk(scanpath):
            for file in files:
                try: #In case permission or other related error
                    if ntpath.basename(file).endswith(exttype): #Gets only executables
                        os.chdir(roots)
                        isPE(file, roots)
                    else:
                        pass
                except OSError:
                    pass
        finished()
    elif (int(ends) == 2): 
        print("Scanning from "+path+" for all files..")
        for roots, subdirs, files in os.walk(scanpath):
            for file in files:
                try: #As above
                    #temppath = os.path.join(roots+ntpath.basename(file))
                    os.chdir(roots)
                    name2, curext = os.path.splitext(file)
                    isPE(file, roots)
                except OSError:
                    pass
        finished()
    else:
        print("ERROR : ENTER VALID OPTION")
        scanforPE()

def isPE(file, rp): #hmmm..waste of space and bad design on my part
    print("Testing... "+file)
    try:
        scanTmp(file, rp)
    except:
        return
        print("ERROR READING "+file)

   
def scanTmp(file, rp): #Scans input files from scanforPE/isPE, Gets value error if file for some reason is read wrong (permissions error, etc)
    global dumptmp
    global tmpread
    global skiplist
    if (scansize == 0):
        maxSize()
    if (os.path.getsize(file) > (int(scansize)*1000000)):
        print(file+" excluded from scanning")
        skiplist.append(file)
        skiplist.append(os.path.getsize(file))
        return
    print("Dumping... "+file)
    name = file
    with open(file, 'rb') as tmp: #Could modify this to have it only read required bytes for signature...TODO
        tmpread = tmp.read() #Reads first 40000(CHANGED TO ALL) bytes of file, need to mess with exact value for performance vs accuracy for average signature offset (most are 0 and require much less of file to be read)
    dumptmp = binascii.hexlify(tmpread).upper()
    tst = dumptmp
    try:
        tst = type(bytes)
    except ValueError:
        print("ERROR READING "+file)
        return
    print(file+" Successfully dumped.")
    checkSig(dumptmp, name) #Check file signature

def printSigs(): #Prints File Header Signatures when called
    print("")
    print("")
    print("<--------------------STORED SIGNATURES, OFFSETS and DESCRIPTIONS/EXTENSIONS-------------------->")
    print("")
    print("")
    i = len(siglist) #Gets length of siglist as filled by loadSigs
    x = 0
    while x < i:
        a = siglist[x]
        x = x + 1
        b = siglist[x]
        x = x + 1
        c = siglist[x]
        print(a+"   0x"+b+"   "+c)
        x = x + 1
    print("")
    print("<------------------------------------END OF SIGNATURE LIST------------------------------------>")     
    print("")

def loadSigs(): #fills sigfile with tuple values from filesignatures.txt (SIGNATURE OFFSET DESCRIPTION) NEED TO CHANGE THIS TO SIT WHEREVER
    tempdir = os.getcwd() #Saves CWD
    os.chdir(startdir) #Reverts to home folder
    global siglist
    siglist = []
    print("")
    print("Reading filesignatures.txt and storing learned file signatures...")
    print("")

    with open("filesignatures.txt") as sigfile:
        for newline in sigfile:
            a, b, c = newline.split() #sigfile contains 3 values delimited via spaces, appended to siglist in triples
            siglist.append(a) 
            siglist.append(b)
            siglist.append(c)
    os.chdir(tempdir) #Sets to last CWD before home


def checkSig(bin, name):
    global lena
    global lenb
    global detectlist
    print("Checking Signature... "+name)
    i = len(siglist)
    x = 0
    bin = binascii.unhexlify(bin) #Putting Hex rep into binary data
    #print(bin)
    while x < i:
        a = siglist[x]
        test = siglist[x]
        a = hex(int(a, 16)) #Putting ASCII str from sigfile into base-16 int then Hex
        a = bytes(a, 'utf8').upper() #Then UTF8 byte object
        x = x + 1
        b = siglist[x]
        b = str(int(b,16)) #Getting offset as Hex
        x = x + 1
        c = siglist[x]
        lenb = len(b)
        tmpbinsig2 = hex(int(test, 16)).upper() #Putting signature into uppercase
        lensig = len(tmpbinsig2) - 2 #for removing 0x counting towards length for getting substring
        lenstr = str(lensig) #Getting length for slicing bin
        #print(tmpbinsig2)
        getSubstring(bin, lenb, lenstr) #Passes slice parameters for retrieving tmpbinsig for sig comparison from appropriate location
        tmpa = a[3:lensig] #Cuts off b'0x
        x = x + 1
        #print(a)
        if (tmpbinsig.find(tmpa) == 1):
        #if (bin.find(a) == 1) and (int(loc) == int(b)): #At specific offset (OLD bad method I was using that was super slow, searched entire binary for signature...)
            #loc = bin.find(a)
            #if (int(loc) == int(b)):
            #loc = hex(loc)
            #a = str(a)
            a = a.decode("utf-8", errors="ignore")
            print("Signature "+a+ " DETECTED for "+c+" file At OFFSET "+b)
            if (exttype != 0) and (exttype.casefold() not in c.casefold()):
                print("POTENTIAL MISMATCH DETECTED")
                print("")
                detectlist.append(name)
                detectlist.append(c)
            elif (curext.casefold() not in c.casefold()):
                print(curext)
                print(c)
                print("POTENTIAL MISMATCH DETECTED")
                print("")
                detectlist.append(name)
                detectlist.append(c)
            print("")
            return
            #else:
                #print("No Signature Detected for : "+c)
                #pass
        else:
            pass
    print("ERROR: NO SIGNATURE DETECTED!")
    print("")

def getSubstring(string, start, length): #Takes file and cuts out string from Hex according to signature in use for testing against known-sigs
    global tmpbinsig 
    s = start 
    l = length
    #print(s)
    #print(l)
    s = int(s) - 1 #Because strings indexed from 0 and len of offset will return 1 at 0
    #print(s)
    l = int(l) + 1
    tmpbinsig  = string[s:l]
    tmpbinsig = binascii.hexlify(tmpbinsig).upper()


def finished(): #Reads and prints mismatch/skip lists
    global time2
    os.chdir(scanpath) #Switch to base scan path for file writing
    time2 = time.strftime("%H-%M(%m-%d-%Y)")
    matchtime = time2+".txt"
    skiptime = time2+".txt"
    try:
        i = len(detectlist)
        x = 0
        if (i > 0):
            file = open("ExtCheck-Detection-List for "+skiptime, "w")
            while x < i:
                a = detectlist[x] #FileName
                x = x + 1
                b = detectlist[x] #Detected Signature
                file.write(str(a)+" contained signature for "+b+"\n")
                x = x + 1
            file.close()
            print("Detection List Successfully Written to 'ExtCheck-Detection-List for "+skiptime+"'""\n")
    except OSError:
        print("ERROR WRITING DETECT-LIST")
        pass
    try:
        file = open("Skip-List for "+skiptime, "w") 
        i = len(skiplist) #Getting length of list
        x = 0
        if (i > 0):
            while x < i:
                a = skiplist[x] #iterating through name lists simultaneously
                x = x + 1
                b = (skiplist[x]/1000000)
                x = x + 1
                file.write(str(a)+" "+str(b)+" MB""\n") #Comma-delimited output, can change
            file.close()
    except OSError:
        print("ERROR WRITING SKIP-LIST")
        pass
    print("Skip List Successfully written to Skip-List for "+skiptime)
    print("Program operations complete...")
    tmp = input("Would you like to restart?")
    


start()
