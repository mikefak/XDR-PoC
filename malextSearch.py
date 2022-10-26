# --------------------------------Disclaimer--------------------------------
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
# --------------------------------Disclaimer--------------------------------

import requests as req
import re
import socket
import os

#Retrieve CSV of malicious ID's
resp = req.get("https://raw.githubusercontent.com/mallorybowes/chrome-mal-ids/master/current-list.csv")

#Format Extension ID into list
resptext = str(resp.text)
malidlist = list(resptext.split())

#Examine entered list of chrome extensions
def examinelist (idinput):

    #Builds input from user into three seperate lists for examination
    formatinput = [x for x in re.compile('\s*[,|\s+]\s*').split(idinput)]
    formbuild = ""

    hostlist = []
    userlist = []
    idlist = []
    foundct = 0
    malct = 0
    missct = 0
    testdict = {}

    count = 1
    for info in formatinput:
        if (count % 3 == 1):
            hostlist.append(info)
        elif (count % 3 == 2):
            userlist.append(info)
        else:
            idlist.append(info)
        count += 1

    #First check if host exists in list

    if (socket.gethostname() in hostlist):

        #Search through id's in list
        for i in range(len(hostlist)):
            if (hostlist[i] == socket.gethostname()):
                foundct += 1
                strbuild = ""

                #Retrieve all information from webpage
                extractid = req.get("https://chrome.google.com/webstore/detail/thisdoesntmatter/" + idlist[i])
                title = re.compile('<title>(.*)</title>')

                #Search Extension Title
                titlesearch = title.search(extractid.text)
                search = extractid.text.split("content=")

                #Format directory
                userform = userlist[i].split("\\")
                dir = "/Users/" + userform[1] + "/AppData/Local/Google/Chrome/User Data/Default/Extensions/" + idlist[i]
                pathexist = os.path.exists(dir)

                #Try formatting to grab page info, fail if page is obstructed (typically when removed from Web Store)
                try:
                    searchformatted = search[3].split('"')
                    searchurl = search[8].split('"')

                except:
                    formbuild += ("-" * 100) + "\n" + "Extension ID " + idlist[i] + " has been obstructed or removed from the Web Store" + "\n"
                    if idlist[i] in malidlist:
                        formbuild += "[X] - FOUND IN MALICIOUS LISTING \n"
                        malct += 1
                    else:
                        formbuild += "[O] \n"
                    if (pathexist):
                        formbuild += "Path for extension EXISTS at: " + dir + "\n"
                    else:
                        formbuild += "Path for extension DOES NOT exist at: " + dir + "\n"
                        missct += 1
                    continue

                strbuild += "Installed by user: " + userlist[i] + "\n"

                #Build output string and reuturn. Format - ID: metadata
                if idlist[i] in malidlist:
                    malresult = "[X] - FOUND IN MALICIOUS LISTING \n"
                    malct += 1
                else:
                    malresult = "[O] \n"

                if (pathexist):
                    strbuild += "Path for extension EXISTS at default location: " + dir + "\n\n"
                else:
                    strbuild += "Path for extension DOES NOT exist at default location: " + dir + "\n\n"
                    missct += 1

                #Build formatted output after retreiving info
                strbuild += titlesearch.group(1) + "\n"
                strbuild += str(searchformatted[1]) + "\n"
                strbuild += str(searchurl[1])
                formbuild += ("-" * 100) + "\n" + idlist[i] + ": " + malresult + "\n" + strbuild + "\n "
                testdict[1] = idlist

    else:
        return (print("Host not found in entered list"))

    #Test print
    #print(str(foundct) + " extension(s) associated w/ " + socket.gethostname() + ", " + str(malct) + " in malicious listing, " + str(missct) + " obstructed or missing" + "\n" + formbuild + ("-" * 100))

    return(str(foundct) + " extension(s) associated w/ " + socket.gethostname() + ", " + str(malct) + " in malicious listing, " + str(missct) + " obstructed or missing" + "\n" + formbuild + ("-" * 100))

#Test Sample
#examinelist("DESKTOP-DHRFHCD	MF-WINDOWS10\MF-Stage3Test	mdpljndcmbeikfnlflcggaipgnhiedbl  DESKTOP-DHRFHCD	MF-WINDOWS10\MF-Stage3Test	bhlhnicpbhignbdhedgjhgdocnmhomnp")
