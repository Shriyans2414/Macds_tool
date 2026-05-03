"""
Mininet topology for MACDS attack simulation.

Hosts:
    h1, h2  — normal clients       (10.0.0.1, 10.0.0.2)
    h3      — attacker             (10.0.0.3)
    h4      — server / IDS node   (10.0.0.4)
    s1      — single OVS switch

Switch port mapping (used for sniffing):
    s1-eth1 → h1
    s1-eth2 → h2
    s1-eth3 → h3  ← sniff this to see h3's traffic
    s1-eth4 → h4
"""
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.log import setLogLevel

class AttackTopo(Topo):
    def build(self):
        s1 = self.addSwitch("s1")
        h1 = self.addHost("h1")
        h2 = self.addHost("h2")
        h3 = self.addHost("h3")   # attacker
        h4 = self.addHost("h4")   # server / IDS

        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(h3, s1)
        self.addLink(h4, s1)

topos = {"attacktopo": lambda: AttackTopo()}

if __name__ == '__main__':
    setLogLevel('info')
    topo = AttackTopo()
    net = Mininet(topo=topo)
    net.start()
    
    h1 = net.get('h1')
    h3 = net.get('h3')
    
    h1.cmd("ip -6 addr add 2001:db8::1/64 dev h1-eth0")
    h3.cmd("ip -6 addr add 2001:db8::3/64 dev h3-eth0")
    
    CLI(net)
    net.stop()
