netsh ipsec static delete policy name="ip blacklist"
netsh ipsec static add policy name="ip blacklist" description="ban IP requesting rdp login with incorrect passwords"
netsh ipsec static add filteraction name="block" action=block
netsh ipsec static add filterlist name="banned IP"
netsh ipsec static add filter filterlist="banned IP" srcaddr=1.2.3.4 dstaddr=me protocol=any mirror=no
netsh ipsec static add filter filterlist="banned IP" srcaddr=1.3.2.4 dstaddr=me protocol=any mirror=no
netsh ipsec static add filter filterlist="banned IP" srcaddr=2.3.4.5 dstaddr=me protocol=any mirror=no
netsh ipsec static add filter filterlist="banned IP" srcaddr=4.3.2.1 dstaddr=me protocol=any mirror=no
netsh ipsec static add rule name="rdp restrictions" policy="ip blacklist" filterlist="banned IP" filteraction="block"
netsh ipsec static set policy name="ip blacklist" assign=yes
pause