# airodump

## SET
ipconfig [Interface name](ex: wlx588694f3a1ce) down
ip link set [Old Interface name] (ex : wlx588694f3a1ce) name [New Interface name]mon0
iwconfig mon0 mode monitor
ifconfig mon0 up

## Usage

syntax : ./airodump-ng Interface
sample : ./airodump-ng mon0
