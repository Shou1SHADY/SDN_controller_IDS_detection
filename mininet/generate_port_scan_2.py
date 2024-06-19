from mininet.topo import Topo
from mininet.net import Mininet
from mininet.link import TCLink
from mininet.log import setLogLevel
from mininet.node import OVSKernelSwitch, RemoteController
from time import sleep
from datetime import datetime
from random import randrange, choice

class MyTopo(Topo):

    def build(self):
        s1 = self.addSwitch('s1', cls=OVSKernelSwitch, protocols='OpenFlow13')
        h1 = self.addHost('h1', cpu=1.0/20, mac="00:00:00:00:00:01", ip="10.0.0.1/24")
        h2 = self.addHost('h2', cpu=1.0/20, mac="00:00:00:00:00:02", ip="10.0.0.2/24")
        h3 = self.addHost('h3', cpu=1.0/20, mac="00:00:00:00:00:03", ip="10.0.0.3/24")
        s2 = self.addSwitch('s2', cls=OVSKernelSwitch, protocols='OpenFlow13')
        h4 = self.addHost('h4', cpu=1.0/20, mac="00:00:00:00:00:04", ip="10.0.0.4/24")
        h5 = self.addHost('h5', cpu=1.0/20, mac="00:00:00:00:00:05", ip="10.0.0.5/24")
        h6 = self.addHost('h6', cpu=1.0/20, mac="00:00:00:00:00:06", ip="10.0.0.6/24")
        s3 = self.addSwitch('s3', cls=OVSKernelSwitch, protocols='OpenFlow13')
        h7 = self.addHost('h7', cpu=1.0/20, mac="00:00:00:00:00:07", ip="10.0.0.7/24")
        h8 = self.addHost('h8', cpu=1.0/20, mac="00:00:00:00:00:08", ip="10.0.0.8/24")
        h9 = self.addHost('h9', cpu=1.0/20, mac="00:00:00:00:00:09", ip="10.0.0.9/24")
        s4 = self.addSwitch('s4', cls=OVSKernelSwitch, protocols='OpenFlow13')
        h10 = self.addHost('h10', cpu=1.0/20, mac="00:00:00:00:00:10", ip="10.0.0.10/24")
        h11 = self.addHost('h11', cpu=1.0/20, mac="00:00:00:00:00:11", ip="10.0.0.11/24")
        h12 = self.addHost('h12', cpu=1.0/20, mac="00:00:00:00:00:12", ip="10.0.0.12/24")
        s5 = self.addSwitch('s5', cls=OVSKernelSwitch, protocols='OpenFlow13')
        h13 = self.addHost('h13', cpu=1.0/20, mac="00:00:00:00:00:13", ip="10.0.0.13/24")
        h14 = self.addHost('h14', cpu=1.0/20, mac="00:00:00:00:00:14", ip="10.0.0.14/24")
        h15 = self.addHost('h15', cpu=1.0/20, mac="00:00:00:00:00:15", ip="10.0.0.15/24")
        s6 = self.addSwitch('s6', cls=OVSKernelSwitch, protocols='OpenFlow13')
        h16 = self.addHost('h16', cpu=1.0/20, mac="00:00:00:00:00:16", ip="10.0.0.16/24")
        h17 = self.addHost('h17', cpu=1.0/20, mac="00:00:00:00:00:17", ip="10.0.0.17/24")
        h18 = self.addHost('h18', cpu=1.0/20, mac="00:00:00:00:00:18", ip="10.0.0.18/24")

        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(h3, s1)
        self.addLink(h4, s2)
        self.addLink(h5, s2)
        self.addLink(h6, s2)
        self.addLink(h7, s3)
        self.addLink(h8, s3)
        self.addLink(h9, s3)
        self.addLink(h10, s4)
        self.addLink(h11, s4)
        self.addLink(h12, s4)
        self.addLink(h13, s5)
        self.addLink(h14, s5)
        self.addLink(h15, s5)
        self.addLink(h16, s6)
        self.addLink(h17, s6)
        self.addLink(h18, s6)
        self.addLink(s1, s2)
        self.addLink(s2, s3)
        self.addLink(s3, s4)
        self.addLink(s4, s5)
        self.addLink(s5, s6)

def ip_generator():
    ip = ".".join(["10", "0", "0", str(randrange(1, 7))])
    return ip

def start_network():
    topo = MyTopo()
    c0 = RemoteController('c0', ip='192.168.10.100', port=6653)
    net = Mininet(topo=topo, link=TCLink, controller=c0)
    net.start()

    hosts = []
    for i in range(1, 19):
        hosts.append(net.get("h{}".format(i)))

    # Start netcat services on random ports on some hosts
    for i in range(1, 7):
        host = net.get("h{}".format(i))
        port = randrange(1000, 2000)
        host.cmd("nc -lk {} &".format(port))
        print("Started netcat on {} port {}".format(host.IP(),port))

    # Perform 5 port scans targeting ports 1000-10000
    for _ in range(2):
        src = choice(hosts)
        dst = ip_generator()
        print("--------------------------------------------------------------------------------")
        print("Performing Port Scan from {} to {}".format(src.IP(),dst))
        print("--------------------------------------------------------------------------------")
        src.cmd("nmap -T4 -p1000-10000 {}".format(dst))

    net.stop()

if __name__ == '__main__':
    start = datetime.now()
    setLogLevel('info')
    start_network()
    end = datetime.now()
    print(end - start)
