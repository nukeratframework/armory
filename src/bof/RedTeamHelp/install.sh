sudo apt-get install libsasl2-dev python3-dev libldap2-dev libssl-dev
pip install python-ldap
sudo apt install openjdk-11-jdk
sudo apt-get install mingw-w64
sudo apt install golang
go get github.com/fatih/color
go get github.com/yeka/zip
go get github.com/josephspurrier/goversioninfo

cd ActiveDirectory
git clone https://github.com/samratashok/ADModule.git
git clone https://github.com/ropnop/windapsearch.git
cd ..
sudo mkdir adcs
cd adcs
pip3 install certipy-ad
git clone https://github.com/AlmondOffSec/PassTheCert.git
git clone https://github.com/ExAndroidDev/impacket.git
cd impacket
git checkout ntlmrelayx-adcs-attack
pip install .
cd ..
cd ..

cd ShellcodeRunners
git clone https://github.com/D1rkMtr/FilelessRemotePE.git

cd ..
cd BOFs
git clone https://github.com/kyle41111/Inline-Execute-PE
git clone https://github.com/anthemtotheego/CredBandit.git
git clone https://github.com/GeorgePatsias/ScareCrow-CobaltStrike.git
cd CredBandit/src
x86_64-w64-mingw32-gcc -o credBanditx64.o -c credBandit.c  -masm=intel
cd ..
cd .. 
cd ScareCrow-CobaltStrike
sudo chmod +x install.sh
sudo bash install.sh



