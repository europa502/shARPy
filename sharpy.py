import netifaces
import getmac
import time
import threading
import os
from scapy.all import *
from pyfiglet import Figlet
import random
import argparse

class startup():
    def __init__(self,os='linux',reset_iface=0,iface=None,):
        self.iface=None
        self.gateway_IP=None
        self.iface_MAC=None
        self.reset_iface=reset_iface
        self.os=os.upper()
        if iface in netifaces.interfaces():
            self.iface=iface
            self.iface_MAC=getmac.get_mac_address(interface=self.iface)
        else:
            raise Exception
        for network in netifaces.gateways()[2]:
            if self.iface in network:
                self.gateway_IP=network[0]
                self.gateway_MAC = getmac.get_mac_address(ip=self.gateway_IP)

    def do_active_scan(self,interval=1):
        while True:
            if getmac.get_mac_address(ip=self.gateway_IP) == self.gateway_MAC:
                print (True)
            time.sleep(interval)

    def do_passive_scan(self):
        sniff(iface=self.iface, prn=self.pkt_callback, filter='host  %s'%self.gateway_IP)

    def pkt_callback(self,pkt):
        if pkt['Ethernet'].src!=self.gateway_MAC and pkt['Ethernet'].src!=self.iface_MAC:
            print('MAC address changed',pkt['Ethernet'].src, pkt['Ethernet'].dst)
            self.attacker_MAC=str(pkt['Ethernet'].src)
            attacker_mac_vendor_id=str(pkt['Ethernet'].src).replace(':','')[0:6].upper()
            print('Attackers MAC ID is :',attacker_mac_vendor_id)
            mac_vendor_file=open('mac_vendors.txt','r')
            for line in mac_vendor_file:
                if attacker_mac_vendor_id in line[0:7]:
                    print('Spoofer\'s MAC ID and vendor is ',line)
        else:
            print('No Problem',pkt['Ethernet'].src, pkt['Ethernet'].dst)

    def defensive_mode(self,disconnect_all_ifaces=1,command=None):
        if not command:
            if self.os == 'LINUX':
                if disconnect_all_ifaces:
                    for network in netifaces.gateways()[2]:
                        os.system('ifconfig %s down'% network[1])
                else:
                    os.system('ifconfig %s down'% self.iface)
            elif self.os == 'WINDOWS':
                pass
        else:
            os.system(command)

    def offensive_mode(self,iface=None):
        if not iface:
            iface=self.iface
        self.create_deauth_packets()
        if self.os=='linux':
            print('Setting %s to monitor mode!'%iface)
            if not os.system('ifconfig %s down'%iface):
                if not os.system('iwconfig %s mode monitor'%iface):
                    if not os.system('ifconfig %s up' % iface):
                        print('Sending deauthentication packets to %s'%self.attacker_MAC)
                        while True:
                            self.send_deauth_packets()

    def create_deauth_packets(self):
        self.deauth_pkt = RadioTap() / Dot11(addr1=self.gateway_MAC, addr2=self.attacker_MAC, addr3=self.attacker_MAC) / Dot11Deauth(reason=7)

    def send_deauth_packets(self,iface):
        try:
            sendp(self.deauth_pkt, iface=iface,verbose=1,inter=0.1,count=100)
        except KeyboardInterrupt:
            if self.reset_iface:
                self.reset_interface()
            else:
                print('Stopped sending Deauthentication packets to %s',self.attacker_MAC)

    def reset_interface(self,iface=None):
        if not iface:
            iface=self.iface
        if self.os=='LINUX':
            print('Setting %s to managed mode!' % iface)
            if not os.system('ifconfig %s down' % iface):
                if not os.system('sudo iwconfig %s mode monitor' % iface):
                    if not os.system('ifconfig %s up' % iface):
                        print('Interface set to managed mode')

if __name__== "__main__":
    #font=['colossal','doom','doh','isometric3','poison']
    f = Figlet(font='slant')
    print(f.renderText('shARPy'))

    parser = argparse.ArgumentParser()
    parser.add_argument('-m', '--mode', type=str, help='set response mode')
    parser.add_argument('response_mode', metavar='R', type=str, default='Defensive', help='Defensive/ Offensive')
    parser.add_argument('-s', '--scan', type=str, help='set scanning method')
    parser.add_argument('method', metavar='R', type=str, default='Passive', help='Active/ Passive')
    parser.add_argument('-o', '--os', type=str, default='', help='Operating System')
    parser.add_argument('OS', metavar='O', type=str, default='linux', help='Operating System')
    parser.add_argument('-i', '--net_iface', type=str, default='', help='Network interface')
    parser.add_argument('-d', '--da_iface', type=str, default='', help='Deauth interface')
    parser.add_argument('-r', '--reset_da_iface', type=str, default='false', help='Reset deauth interface')
    parser.add_argument('reset_mode', metavar='M', type=str, default='managed', help='reset deauth device to specific mode')
    parser.add_argument('-c', '--command', type=str, default='', help='Explicitly give commands to respond in case spoofing is detected.')

    mode = parser.parse_args().mode
    response_mode = parser.parse_args().response_mode
    scan=parser.parse_args().scan
    os=parser.parse_args().os
    OS= parser.parse_args().OS
    inet_iface = parser.parse_args().net_iface
    da_iface= parser.parse_args().da_iface
    reset_da_iface= parser.parse_args().reset_da_iface
    reset_mode=parser.parse_args().reset_mode
    commnad=parser.parse_args().command


    start = startup(iface)

    active_scanner_thread=threading.Thread(target=start.do_active_scan,args=(2,))
    #active_scanner_thread.start()

    passive_scanner_thread=threading.Thread(target=start.do_passive_scan)
    #passive_scanner_thread.start()

