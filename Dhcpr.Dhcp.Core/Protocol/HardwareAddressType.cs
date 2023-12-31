﻿namespace Dhcpr.Dhcp.Core.Protocol;
// 0	Reserved	[RFC5494]
// 1	Ethernet (10Mb)	[Jon_Postel]
// 2	Experimental Ethernet (3Mb)	[Jon_Postel]
// 3	Amateur Radio AX.25	[Philip_Koch]
// 4	Proteon ProNET Token Ring	[Avri_Doria]
// 5	Chaos	[Gill_Pratt]
// 6	IEEE 802 Networks	[Jon_Postel]
// 7	ARCNET	[RFC1201]
// 8	Hyperchannel	[Jon_Postel]
// 9	Lanstar	[Tom_Unger]
// 10	Autonet Short Address	[Mike_Burrows]
// 11	LocalTalk	[Joyce_K_Reynolds]
// 12	LocalNet (IBM PCNet or SYTEK LocalNET)	[Joseph Murdock]
// 13	Ultra link	[Rajiv_Dhingra]
// 14	SMDS	[George_Clapp]
// 15	Frame Relay	[Andy_Malis]
// 16	Asynchronous Transmission Mode (ATM)	[[JXB2]]
// 17	HDLC	[Jon_Postel]
// 18	Fibre Channel	[RFC4338]
// 19	Asynchronous Transmission Mode (ATM)	[RFC2225]
// 20	Serial Line	[Jon_Postel]
// 21	Asynchronous Transmission Mode (ATM)	[Mike_Burrows]
// 22	MIL-STD-188-220	[Herb_Jensen]
// 23	Metricom	[Jonathan_Stone]
// 24	IEEE 1394.1995	[Myron_Hattig]
// 25	MAPOS	[Mitsuru_Maruyama][RFC2176]
// 26	Twinaxial	[Marion_Pitts]
// 27	EUI-64	[Kenji_Fujisawa]
// 28	HIPARP	[Jean_Michel_Pittet]
// 29	IP and ARP over ISO 7816-3	[Scott_Guthery]
// 30	ARPSec	[Jerome_Etienne]
// 31	IPsec tunnel	[RFC3456]
// 32	InfiniBand (TM)	[RFC4391]
// 33	TIA-102 Project 25 Common Air Interface (CAI)	[Jeff Anderson, Telecommunications Industry of America (TIA) TR-8.5 Formulating Group, <cja015&motorola.com>, June 2004]
// 34	Wiegand Interface	[Scott_Guthery_2]
// 35	Pure IP	[Inaky_Perez-Gonzalez]
// 36	HW_EXP1	[RFC5494]
// 37	HFI	[Tseng-Hui_Lin]
// 38	Unified Bus (UB)	[Wei_Pan]

public enum HardwareAddressType : byte
{
    Reserved,
    Ethernet,
    ExperimentalEthernet,
    AmateurRadio,
    TokenRing,
    Chaos,
    IEEE802,
    ARCNET,
    HyperChannel,
    LanStar,
    AutoNetShort,
    LocalTalk,
    LocalNet,
    UltraLink,
    SMDS,
    FrameRelay,
    AsynchronousTransmissionMode1,
    HLDC,
    FibreChannel,
    AsynchronousTransmissionMode2,
    SerialLine,
    AsynchronousTransmissionMode3,
    MilStd188220,
    Metricom,
    FireWire1995,
    MapOS,
    TwinAxial,
    Eui64,
    HIPARP,
    IpAndArpOverISO78163,
    ArpSec,
    IPSecTunnel,
    InfiniBand,
    Tia102Project25CAI,
    WiegandInterface,
    PureIP,
    HW_EXP1,
    HFI,
    UnifiedBus
}