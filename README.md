# airodump

## SET
ipconfig [Interface name](ex: wlx588694f3a1ce) down<br/>
ip link set [Old Interface name] (ex : wlx588694f3a1ce) name [New Interface name]mon0<br/>
iwconfig mon0 mode monitor<br/>
ifconfig mon0 up<br/>

## Usage

syntax : ./airodump-ng Interface<br/>
sample : ./airodump-ng mon0
