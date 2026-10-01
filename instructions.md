Help me create a project in this folder.

I recently acuired your help in creating a very nifty tools for my linux based wireguad client. it was a TUI tool based on the existing omarchy-vpn tool thats opensource. I like that design quite well. I now want to build a server side tool that is similar to this. Can you help me. I require the following features:

* A multi-tenant server utilizing linux based namespaces to prevent overlapping subnets
* Neat Simple, Easy, Intuitive and most of all very effective TUI design.
* The ability to store and retrieve config files on demand.
* The ability to Create QR codes on demand or as a optional tick
* Due to the use of name spaces wont have any problem working with multiple of the same subnets on the same devices.
* Simple but effective firewall to quickly and easily limit access of nescessary.
* Based on the same design as my HazyVPN or even omarchy VPN TUI https://github.com/NetSlave67/hazyvpn.git
* Easily able to add config peers (road-warrior) and remove them.
* Automatically scan used IP addresses in that namespace or configs so the user wont manually have to type in a IP address for the peer IP.
* User has control over the subnet used for the network, the allowed IPs, DNS, Preshared key, Keepalive etc, but should retain default suggestions that can be overwritten.
* Good error handling especially with the possibility of customers accidentally using the same IP address in the wireguard subnet for their peers.
* Import export functionality.
* Ability to download configs or copy to clipboard.
* Email functionality so configs can be sent over email.

I thinks this covers the basics of it for now.
I made a repository on github thats empty and I want you to push the nescessary files automatically. https://github.com/NetSlave67/hazyvpn-server.git

* I want this to be fully deployable and as simple as possible.
Dont make my machine the server and install unnessesarcy packages. I have docker installed or can make a vm if nesscesarry.

Help me add to this rules set and create a proper instructions folder. As soon as you have drafter a good instruction for yourself please execute that.