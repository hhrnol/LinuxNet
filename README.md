### Linux Network

Network <br/>
![1 results](../main/Task_Linux_Net.bmp)
<pre>
net1 - 192.168.1.0/24
net2 - 10.76.16.0/24
net3 - 10.11.76.0/24
net4 - 172.16.16.0/24
Server1.Int1 - 192.168.1.200/24
Server1.Int2 - 10.76.16.200/24
Server1.Int3 - 10.11.76.200/24
Client1.Int1 - 10.76.16.1/24
Client2.Int1 - 10.11.76.1/24
Client1.Int2 - 172.16.16.1/24
Client2.Int2 - 172.16.16.2/24
Client1.lo   - 172.17.26.1/24,172.17.36.1/24
</pre>
### SERVER1
<pre>
Linux server1 5.15.0-56-generic #62-Ubuntu SMP
alex@server1:~$ cat /etc/netplan/00-installer-config.yaml
network:
  version: 2
  renderer: networkd
  ethernets:
    enp0s3:
      dhcp4: no
      addresses: [192.168.1.200/24]
      routes:
      - to: default
        via: 192.168.1.1
      nameservers:
        addresses: [192.168.1.1, 1.1.1.1]
    enp0s8:
      dhcp4: no
      addresses: [10.76.16.200/24]
      routes:
        - to: 172.17.26.0/24
          via: 10.76.16.1
          metric: 45
    enp0s9:
      dhcp4: no
      addresses: [10.11.76.200/24]
 </pre>
 <pre>
 sudo netplan generate && sudo netplan try
 
 hostname -i
::1 192.168.1.200 10.76.16.200 10.11.76.200

sudo apt install isc-dhcp-server

sudo vim /etc/dhcp/dhcpd.conf
option domain-name "co.local";
option domain-name-servers 192.168.1.1, 1.1.1.1;
default-lease-time 600;
max-lease-time 7200;
authoritative;
option classless-routes code 121 = array of unsigned integer 8;
subnet 10.76.16.0 netmask 255.255.255.0 {
  range 10.76.16.1 10.76.16.100;
  option routers 10.76.16.200;
  option classless-routes 0,             10,76,16,200, 
                          24, 10,11,76,  10,76,16,200,
                          24, 192,168,1, 10,76,16,200;
}
subnet 10.11.76.0 netmask 255.255.255.0 {
  range 10.11.76.1 10.11.76.100;
  option routers 10.11.76.200;
  option classless-routes 0,             10,11,76,200, 
                          24, 10,76,16,  10,11,76,200,
                          24, 192,168,1, 10,11,76,200;
}
host client1 {
  hardware ethernet 08:00:27:e3:fb:82;
  fixed-address 10.76.16.1;
}
host client2 {
  hardware ethernet 08:00:27:2e:d9:69;
  fixed-address 10.11.76.1;
}
</pre>
###Packet Forwarding
<pre>
sudo su
fgrep -v net.ipv4.ip_forward /etc/sysctl.conf > /etc/sysctl.conf.tmp
echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf.tmp
mv /etc/sysctl.conf.tmp /etc/sysctl.conf
fgrep -v net.ipv6.conf.all.forwarding /etc/sysctl.conf > /etc/sysctl.conf.tmp
echo "net.ipv6.conf.all.forwarding = 1" >> /etc/sysctl.conf.tmp
mv /etc/sysctl.conf.tmp /etc/sysctl.conf
exit
sudo sysctl -p
 </pre>
 ### CLIENT1
 <pre>
 alex@client1:~$ hostnamectl status
 Static hostname: client1
       Icon name: computer-vm
         Chassis: vm
        Location: get
      Machine ID: 0cbeee11a95748ca8be8ae4ee24b6895
         Boot ID: 5abdee6e0b3e4fe7ac930a3a4a47d878
  Virtualization: oracle
Operating System: Ubuntu 22.04.1 LTS
          Kernel: Linux 5.15.0-56-generic
    Architecture: x86-64
 Hardware Vendor: innotek GmbH
  Hardware Model: VirtualBox
  
  cat /etc/netplan/00-installer-config.yaml
network:
  ethernets:
    enp0s3:
      dhcp4: true
    enp0s8:
      dhcp4: no
      addresses: [172.16.16.1/24]
    lo:
      addresses: 
        - 127.0.0.1/8
        - 172.17.26.1/24
        - 172.17.36.1/24
      
  version: 2
  renderer: networkd
  </pre>
  ### CLIENT2
  <pre>
  hostnamectl
   Static hostname: centos.epam
         Icon name: computer-vm
           Chassis: vm
        Machine ID: 6a5c119bf20a7d4eba15f887eb1128be
           Boot ID: 5255ce68ad82451793972494f45796af
    Virtualization: kvm
  Operating System: CentOS Linux 7 (Core)
       CPE OS Name: cpe:/o:centos:centos:7
            Kernel: Linux 3.10.0-1160.el7.x86_64
      Architecture: x86-64
      
   ip a sh
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
2: enp0s3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 08:00:27:2e:d9:69 brd ff:ff:ff:ff:ff:ff
    inet 10.11.76.1/24 brd 10.11.76.255 scope global noprefixroute dynamic enp0s3
       valid_lft 553sec preferred_lft 553sec
    inet6 fe80::c505:496c:bd1e:e4b2/64 scope link noprefixroute
       valid_lft forever pref11erred_lft forever
3: enp0s8: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 08:00:27:1d:26:c5 brd ff:ff:ff:ff:ff:ff
    inet6 fe80::6d30:b414:a72d:bc21/64 scope link noprefixroute
       valid_lft forever preferred_lft forever
       
  
nmcli con  del "Wired connection 1"
nmcli con add con-name "net4" \
type ethernet \
ifname enp0s8 \
ipv4.address 172.16.16.2/24 \
ipv4.method manual \
connection.autoconnect yes
  
 # nmcli con sh
NAME     UUID                                  TYPE      DEVICE
server1  41f0b3e6-d360-4b01-904b-a4abf9f3d139  ethernet  enp0s3
net4     1cc0a9a0-9a72-46aa-a2c6-90521106cd61  ethernet  enp0s8 
  
 [root@centos ~]# traceroute 172.17.26.1
traceroute to 172.17.26.1 (172.17.26.1), 30 hops max, 60 byte packets
 1  server1 (10.11.76.200)  0.322 ms  0.367 ms  0.268 ms
 2  172.17.26.1 (172.17.26.1)  0.726 ms  0.785 ms  0.630 ms
 
 ip route add 172.17.36.0/24 dev enp0s8
traceroute to 172.17.36.1 (172.17.36.1), 30 hops max, 60 byte packets
 1  172.17.36.1 (172.17.36.1)  0.451 ms  0.531 ms  0.740 ms
 </pre>
 ### Network aggregation
 <pre>
 aggregate net 172.17.26.0/24 and 172.17.36.0/24
10101100 00010001 00 011010 00000000
10101100 00010001 00 100100 00000000
10101100 00010001 00 000000 00000000

172.17.0.0/18

ip route delete 172.17.36.0/24 dev enp0s8
ip route delete 172.17.26.0/24 dev enp0s3
ip route add 172.17.0.0/18 dev enp0s3
</pre>
### ping
<pre>
on server1

-A ufw-before-input -s 172.17.26.0/24 -p icmp --icmp-type echo-request -j ACCEPT
-A ufw-before-input -s 172.17.36.0/24 -p icmp --icmp-type echo-request -j DROP
</pre>

### Nat
<pre>
# NAT
sudo ufw default allow FORWARD

sudo vim /etc/ufw/before.rules
#add to the end
*nat
-F
:POSTROUTING ACCEPT [0:0]
-A POSTROUTING -s 10.0.0.0/8 -o enp0s3 -j MASQUERADE

COMMIT
:
</pre>
 
  
