## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more information
## Copyright (C) Airbus DS CyberSecurity
## Authors: Jean-Michel Picod, Arnaud Lebrun, Jonathan Christofer Demay
## This program is published under a GPLv2 license

"""
Gnuradio layers, sockets and send/receive functions.
"""

from scapy.layers.ZWave import *

class GnuradioPacket(Packet):
    name = "Gnuradio header"
    fields_desc = [
        ByteField("proto", 0),
        HiddenField(X3BytesField("reserved1", 0)),
        HiddenField(IntField("reserved2", 0))
    ]


## Z-Wave
#bind_layers(GnuradioPacket, ZWave, proto=1)
bind_bottom_up(GnuradioPacket, ZWave, proto=1)
bind_top_down(GnuradioPacket, ZWaveReq, proto=1)

conf.l2types.register(148, GnuradioPacket)
