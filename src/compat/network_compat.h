#pragma once

// POSIX networking compatibility for Windows
// This file provides cross-platform networking includes and defines constants
// and structures that are available on POSIX systems but missing or different on Windows.
// It provides compatibility definitions for network-related headers like <netinet/ip.h>,
// <netinet/tcp.h>, etc., as well as network byte order conversion functions.

#include "system.h"

#ifdef OS_WINDOWS

#include "endianess.h"
#include <stdio.h>
#include <stdint.h>
#include <winsock2.h>
#include <ws2tcpip.h>
// Windows provides ntohs, ntohl, htons, htonl in <winsock2.h>

typedef SOCKET socket_fd_t;
#define INVALID_FD INVALID_SOCKET
#define close closesocket

#else

// POSIX systems - include standard networking headers
#include <arpa/inet.h>
#include <netinet/in.h>
// POSIX systems provide ntohs, ntohl, htons, htonl in <arpa/inet.h>

typedef int socket_fd_t;
#define INVALID_FD -1

#endif // OS_WINDOWS

#ifdef OS_WINDOWS

#pragma region <linux/if_ether.h>
/*
 *	IEEE 802.3 Ethernet magic constants.  The frame sizes omit the preamble
 *	and FCS/CRC (frame check sequence).
 */
#define ETH_ALEN	6		/* Octets in one ethernet addr	 */
#define ETH_TLEN	2		/* Octets in ethernet type field */
#define ETH_HLEN	14		/* Total octets in header.	 */
#define ETH_ZLEN	60		/* Min. octets in frame sans FCS */
#define ETH_DATA_LEN	1500		/* Max. octets in payload	 */
#define ETH_FRAME_LEN	1514		/* Max. octets in frame sans FCS */
#define ETH_FCS_LEN	4		/* Octets in the FCS		 */

#define ETH_MIN_MTU	68		/* Min IPv4 MTU per RFC791	*/
#define ETH_MAX_MTU	0xFFFFU		/* 65535, same as IP_MAX_MTU	*/
#pragma endregion <linux/if_ether.h>

#pragma region <net/ethernet.h>
/* This is a name for the 48 bit ethernet address available on many
   systems.  */
#pragma pack(push, 1)
struct ether_addr
{
  uint8_t ether_addr_octet[ETH_ALEN];
};
#pragma pack(pop)

/* 10Mb/s ethernet header */
#pragma pack(push, 1)
struct ether_header
{
  uint8_t  ether_dhost[ETH_ALEN];	/* destination eth addr	*/
  uint8_t  ether_shost[ETH_ALEN];	/* source ether addr	*/
  uint16_t ether_type;		        /* packet type ID field	*/
};
#pragma pack(pop)

/* Ethernet protocol ID's */
#define	ETHERTYPE_PUP		0x0200          /* Xerox PUP */
#define ETHERTYPE_SPRITE	0x0500		/* Sprite */
#define	ETHERTYPE_IP		0x0800		/* IP */
#define	ETHERTYPE_ARP		0x0806		/* Address resolution */
#define	ETHERTYPE_REVARP	0x8035		/* Reverse ARP */
#define ETHERTYPE_AT		0x809B		/* AppleTalk protocol */
#define ETHERTYPE_AARP		0x80F3		/* AppleTalk ARP */
#define	ETHERTYPE_VLAN		0x8100		/* IEEE 802.1Q VLAN tagging */
#define ETHERTYPE_IPX		0x8137		/* IPX */
#define	ETHERTYPE_IPV6		0x86dd		/* IP protocol version 6 */
#define ETHERTYPE_LOOPBACK	0x9000		/* used to test interfaces */

#define	ETHER_ADDR_LEN	ETH_ALEN                 /* size of ethernet addr */
#define	ETHER_TYPE_LEN	2                        /* bytes in type field */
#define	ETHER_CRC_LEN	4                        /* bytes in CRC field */
#define	ETHER_HDR_LEN	ETH_HLEN                 /* total octets in header */
#define	ETHER_MIN_LEN	(ETH_ZLEN + ETHER_CRC_LEN) /* min packet length */
#define	ETHER_MAX_LEN	(ETH_FRAME_LEN + ETHER_CRC_LEN) /* max packet length */

/* make sure ethernet length is valid */
#define	ETHER_IS_VALID_LEN(foo)	\
	((foo) >= ETHER_MIN_LEN && (foo) <= ETHER_MAX_LEN)

/*
 * The ETHERTYPE_NTRAILER packet types starting at ETHERTYPE_TRAIL have
 * (type-ETHERTYPE_TRAIL)*512 bytes of data followed
 * by an ETHER type (as given above) and then the (variable-length) header.
 */
#define	ETHERTYPE_TRAIL		0x1000		/* Trailer packet */
#define	ETHERTYPE_NTRAILER	16

#define	ETHERMTU	ETH_DATA_LEN
#define	ETHERMIN	(ETHER_MIN_LEN - ETHER_HDR_LEN - ETHER_CRC_LEN)
#pragma endregion <net/ethernet.h>

#pragma region <netinet/ether.h>
// Windows doesn't have ether_ntoa
static inline char *ether_ntoa(const struct ether_addr *addr) {
    static char buf[18];
    sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x",
        addr->ether_addr_octet[0], addr->ether_addr_octet[1],
        addr->ether_addr_octet[2], addr->ether_addr_octet[3],
        addr->ether_addr_octet[4], addr->ether_addr_octet[5]);
    return buf;
}
#pragma endregion <netinet/ether.h>

#pragma region <netinet/ip.h>
#pragma pack(push, 1)
struct iphdr
  {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    uint8_t ihl:4;
    uint8_t version:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
    uint8_t version:4;
    uint8_t ihl:4;
#else
# error	"Please fix <bits/endian.h>"
#endif
    uint8_t tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
    /*The options start here. */
  };
#pragma pack(pop)

/*
 * Structure of an internet header, naked of options.
 */
#pragma pack(push, 1)
struct ip
  {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    uint8_t ip_hl:4;		/* header length */
    uint8_t ip_v:4;		/* version */
#endif
#if __BYTE_ORDER == __BIG_ENDIAN
    uint8_t ip_v:4;		/* version */
    uint8_t ip_hl:4;		/* header length */
#endif
    uint8_t ip_tos;			/* type of service */
    uint16_t ip_len;		/* total length */
    uint16_t ip_id;		/* identification */
    uint16_t ip_off;		/* fragment offset field */
#define	IP_RF 0x8000			/* reserved fragment flag */
#define	IP_DF 0x4000			/* dont fragment flag */
#define	IP_MF 0x2000			/* more fragments flag */
#define	IP_OFFMASK 0x1fff		/* mask for fragmenting bits */
    uint8_t ip_ttl;			/* time to live */
    uint8_t ip_p;			/* protocol */
    uint16_t ip_sum;		/* checksum */
    struct in_addr ip_src, ip_dst;	/* source and dest address */
  };
#pragma pack(pop)

/*
 * Time stamp option structure.
 */
#pragma pack(push, 1)
struct ip_timestamp
  {
    uint8_t ipt_code;			/* IPOPT_TS */
    uint8_t ipt_len;			/* size of structure (variable) */
    uint8_t ipt_ptr;			/* index of current entry */
#if __BYTE_ORDER == __LITTLE_ENDIAN
    uint8_t ipt_flg:4;		/* flags, see below */
    uint8_t ipt_oflw:4;		/* overflow counter */
#endif
#if __BYTE_ORDER == __BIG_ENDIAN
    uint8_t ipt_oflw:4;		/* overflow counter */
    uint8_t ipt_flg:4;		/* flags, see below */
#endif
    uint32_t data[9];
  };
#pragma pack(pop)

#define	IPVERSION	4               /* IP version number */
#define	IP_MAXPACKET	65535		/* maximum packet size */
#pragma endregion <netinet/ip.h>

#pragma region <netinet/ip_icmp.h>
#pragma pack(push, 1)
struct icmphdr
{
  uint8_t type;		/* message type */
  uint8_t code;		/* type sub-code */
  uint16_t checksum;
  union
  {
    struct
    {
      uint16_t	id;
      uint16_t	sequence;
    } echo;			/* echo datagram */
    uint32_t	gateway;	/* gateway address */
    struct
    {
      uint16_t	__glibc_reserved;
      uint16_t	mtu;
    } frag;			/* path mtu discovery */
  } un;
};
#pragma pack(pop)

#define ICMP_ECHOREPLY		0	/* Echo Reply			*/
#define ICMP_DEST_UNREACH	3	/* Destination Unreachable	*/
#define ICMP_SOURCE_QUENCH	4	/* Source Quench		*/
#define ICMP_REDIRECT		5	/* Redirect (change route)	*/
#define ICMP_ECHO		8	/* Echo Request			*/
#define ICMP_TIME_EXCEEDED	11	/* Time Exceeded		*/
#define ICMP_PARAMETERPROB	12	/* Parameter Problem		*/
#define ICMP_TIMESTAMP		13	/* Timestamp Request		*/
#define ICMP_TIMESTAMPREPLY	14	/* Timestamp Reply		*/
#define ICMP_INFO_REQUEST	15	/* Information Request		*/
#define ICMP_INFO_REPLY		16	/* Information Reply		*/
#define ICMP_ADDRESS		17	/* Address Mask Request		*/
#define ICMP_ADDRESSREPLY	18	/* Address Mask Reply		*/
#define NR_ICMP_TYPES		18


/* Codes for UNREACH. */
#define ICMP_NET_UNREACH	0	/* Network Unreachable		*/
#define ICMP_HOST_UNREACH	1	/* Host Unreachable		*/
#define ICMP_PROT_UNREACH	2	/* Protocol Unreachable		*/
#define ICMP_PORT_UNREACH	3	/* Port Unreachable		*/
#define ICMP_FRAG_NEEDED	4	/* Fragmentation Needed/DF set	*/
#define ICMP_SR_FAILED		5	/* Source Route failed		*/
#define ICMP_NET_UNKNOWN	6
#define ICMP_HOST_UNKNOWN	7
#define ICMP_HOST_ISOLATED	8
#define ICMP_NET_ANO		9
#define ICMP_HOST_ANO		10
#define ICMP_NET_UNR_TOS	11
#define ICMP_HOST_UNR_TOS	12
#define ICMP_PKT_FILTERED	13	/* Packet filtered */
#define ICMP_PREC_VIOLATION	14	/* Precedence violation */
#define ICMP_PREC_CUTOFF	15	/* Precedence cut off */
#define NR_ICMP_UNREACH		15	/* instead of hardcoding immediate value */

/* Codes for REDIRECT. */
#define ICMP_REDIR_NET		0	/* Redirect Net			*/
#define ICMP_REDIR_HOST		1	/* Redirect Host		*/
#define ICMP_REDIR_NETTOS	2	/* Redirect Net for TOS		*/
#define ICMP_REDIR_HOSTTOS	3	/* Redirect Host for TOS	*/

/* Codes for TIME_EXCEEDED. */
#define ICMP_EXC_TTL		0	/* TTL count exceeded		*/
#define ICMP_EXC_FRAGTIME	1	/* Fragment Reass time exceeded	*/

/* Codes for ICMP_EXT_ECHO (PROBE) */
#define ICMP_EXT_ECHO		42
#define ICMP_EXT_ECHOREPLY	43
#define ICMP_EXT_CODE_MAL_QUERY	1	/* Malformed Query */
#define ICMP_EXT_CODE_NO_IF	2	/* No such Interface */
#define ICMP_EXT_CODE_NO_TABLE_ENT	3	/* No table entry */
#define ICMP_EXT_CODE_MULT_IFS	4	/* Multiple Interfaces Satisfy Query */

/* Constants for EXT_ECHO (PROBE) */
#define ICMP_EXT_ECHOREPLY_ACTIVE	(1 << 2)/* active bit in reply */
#define ICMP_EXT_ECHOREPLY_IPV4		(1 << 1)/* ipv4 bit in reply */
#define ICMP_EXT_ECHOREPLY_IPV6		1	/* ipv6 bit in reply */
#define ICMP_EXT_ECHO_CTYPE_NAME	1
#define ICMP_EXT_ECHO_CTYPE_INDEX	2
#define ICMP_EXT_ECHO_CTYPE_ADDR	3
#define ICMP_AFI_IP			1	/* Address Family Identifier for IPV4 */
#define ICMP_AFI_IP6			2	/* Address Family Identifier for IPV6 */

/*
 * Internal of an ICMP Router Advertisement
 */
struct icmp_ra_addr
{
  uint32_t ira_addr;
  uint32_t ira_preference;
};

#pragma pack(push, 1)
struct icmp
{
  uint8_t  icmp_type;	/* type of message, see below */
  uint8_t  icmp_code;	/* type sub code */
  uint16_t icmp_cksum;	/* ones complement checksum of struct */
  union
  {
    unsigned char ih_pptr;	/* ICMP_PARAMPROB */
    struct in_addr ih_gwaddr;	/* gateway address */
    struct ih_idseq		/* echo datagram */
    {
      uint16_t icd_id;
      uint16_t icd_seq;
    } ih_idseq;
    uint32_t ih_void;

    /* ICMP_UNREACH_NEEDFRAG -- Path MTU Discovery (RFC1191) */
    struct ih_pmtu
    {
      uint16_t ipm_void;
      uint16_t ipm_nextmtu;
    } ih_pmtu;

    struct ih_rtradv
    {
      uint8_t irt_num_addrs;
      uint8_t irt_wpa;
      uint16_t irt_lifetime;
    } ih_rtradv;
  } icmp_hun;
#define	icmp_pptr	icmp_hun.ih_pptr
#define	icmp_gwaddr	icmp_hun.ih_gwaddr
#define	icmp_id		icmp_hun.ih_idseq.icd_id
#define	icmp_seq	icmp_hun.ih_idseq.icd_seq
#define	icmp_void	icmp_hun.ih_void
#define	icmp_pmvoid	icmp_hun.ih_pmtu.ipm_void
#define	icmp_nextmtu	icmp_hun.ih_pmtu.ipm_nextmtu
#define	icmp_num_addrs	icmp_hun.ih_rtradv.irt_num_addrs
#define	icmp_wpa	icmp_hun.ih_rtradv.irt_wpa
#define	icmp_lifetime	icmp_hun.ih_rtradv.irt_lifetime
  union
  {
    struct
    {
      uint32_t its_otime;
      uint32_t its_rtime;
      uint32_t its_ttime;
    } id_ts;
    struct
    {
      struct ip idi_ip;
      /* options and then 64 bits of data */
    } id_ip;
    struct icmp_ra_addr id_radv;
    uint32_t   id_mask;
    uint8_t    id_data[1];
  } icmp_dun;
#define	icmp_otime	icmp_dun.id_ts.its_otime
#define	icmp_rtime	icmp_dun.id_ts.its_rtime
#define	icmp_ttime	icmp_dun.id_ts.its_ttime
#define	icmp_ip		icmp_dun.id_ip.idi_ip
#define	icmp_radv	icmp_dun.id_radv
#define	icmp_mask	icmp_dun.id_mask
#define	icmp_data	icmp_dun.id_data
};
#pragma pack(pop)

/*
 * Lower bounds on packet lengths for various types.
 * For the error advice packets must first insure that the
 * packet is large enough to contain the returned ip header.
 * Only then can we do the check to see if 64 bits of packet
 * data have been returned, since we need to check the returned
 * ip header length.
 */
#define	ICMP_MINLEN	8				/* abs minimum */
#define	ICMP_TSLEN	(8 + 3 * sizeof (n_time))	/* timestamp */
#define	ICMP_MASKLEN	12				/* address mask */
#define	ICMP_ADVLENMIN	(8 + sizeof (struct ip) + 8)	/* min */
#ifndef _IP_VHL
#define	ICMP_ADVLEN(p)	(8 + ((p)->icmp_ip.ip_hl << 2) + 8)
	/* N.B.: must separately check that ip_hl >= 5 */
#else
#define	ICMP_ADVLEN(p)	(8 + (IP_VHL_HL((p)->icmp_ip.ip_vhl) << 2) + 8)
	/* N.B.: must separately check that header length >= 5 */
#endif

/* Definition of type and code fields. */
/* defined above: ICMP_ECHOREPLY, ICMP_REDIRECT, ICMP_ECHO */
#define	ICMP_UNREACH		3		/* dest unreachable, codes: */
#define	ICMP_SOURCEQUENCH	4		/* packet lost, slow down */
#define	ICMP_ROUTERADVERT	9		/* router advertisement */
#define	ICMP_ROUTERSOLICIT	10		/* router solicitation */
#define	ICMP_TIMXCEED		11		/* time exceeded, code: */
#define	ICMP_PARAMPROB		12		/* ip header bad */
#define	ICMP_TSTAMP		13		/* timestamp request */
#define	ICMP_TSTAMPREPLY	14		/* timestamp reply */
#define	ICMP_IREQ		15		/* information request */
#define	ICMP_IREQREPLY		16		/* information reply */
#define	ICMP_MASKREQ		17		/* address mask request */
#define	ICMP_MASKREPLY		18		/* address mask reply */

#define	ICMP_MAXTYPE		18

/* UNREACH codes */
#define	ICMP_UNREACH_NET	        0	/* bad net */
#define	ICMP_UNREACH_HOST	        1	/* bad host */
#define	ICMP_UNREACH_PROTOCOL	        2	/* bad protocol */
#define	ICMP_UNREACH_PORT	        3	/* bad port */
#define	ICMP_UNREACH_NEEDFRAG	        4	/* IP_DF caused drop */
#define	ICMP_UNREACH_SRCFAIL	        5	/* src route failed */
#define	ICMP_UNREACH_NET_UNKNOWN        6	/* unknown net */
#define	ICMP_UNREACH_HOST_UNKNOWN       7	/* unknown host */
#define	ICMP_UNREACH_ISOLATED	        8	/* src host isolated */
#define	ICMP_UNREACH_NET_PROHIB	        9	/* net denied */
#define	ICMP_UNREACH_HOST_PROHIB        10	/* host denied */
#define	ICMP_UNREACH_TOSNET	        11	/* bad tos for net */
#define	ICMP_UNREACH_TOSHOST	        12	/* bad tos for host */
#define	ICMP_UNREACH_FILTER_PROHIB      13	/* admin prohib */
#define	ICMP_UNREACH_HOST_PRECEDENCE    14	/* host prec vio. */
#define	ICMP_UNREACH_PRECEDENCE_CUTOFF  15	/* prec cutoff */

/* REDIRECT codes */
#define	ICMP_REDIRECT_NET	0		/* for network */
#define	ICMP_REDIRECT_HOST	1		/* for host */
#define	ICMP_REDIRECT_TOSNET	2		/* for tos and net */
#define	ICMP_REDIRECT_TOSHOST	3		/* for tos and host */

/* TIMEXCEED codes */
#define	ICMP_TIMXCEED_INTRANS	0		/* ttl==0 in transit */
#define	ICMP_TIMXCEED_REASS	1		/* ttl==0 in reass */

/* PARAMPROB code */
#define	ICMP_PARAMPROB_OPTABSENT 1		/* req. opt. absent */

#define	ICMP_INFOTYPE(type) \
	((type) == ICMP_ECHOREPLY || (type) == ICMP_ECHO \
	 || (type) == ICMP_ROUTERADVERT || (type) == ICMP_ROUTERSOLICIT \
	 || (type) == ICMP_TSTAMP || (type) == ICMP_TSTAMPREPLY \
	 || (type) == ICMP_IREQ || (type) == ICMP_IREQREPLY \
	 || (type) == ICMP_MASKREQ || (type) == ICMP_MASKREPLY)
#pragma endregion <netinet/ip_icmp.h>

#pragma region <net/if_arp.h>
/* Some internals from deep down in the kernel.  */
#define MAX_ADDR_LEN	7

/* This structure defines an ethernet arp header.  */

/* ARP protocol opcodes. */
#define	ARPOP_REQUEST	1		/* ARP request.  */
#define	ARPOP_REPLY	2		/* ARP reply.  */
#define	ARPOP_RREQUEST	3		/* RARP request.  */
#define	ARPOP_RREPLY	4		/* RARP reply.  */
#define	ARPOP_InREQUEST	8		/* InARP request.  */
#define	ARPOP_InREPLY	9		/* InARP reply.  */
#define	ARPOP_NAK	10		/* (ATM)ARP NAK.  */

/* See RFC 826 for protocol description.  ARP packets are variable
   in size; the arphdr structure defines the fixed-length portion.
   Protocol type values are the same as those for 10 Mb/s Ethernet.
   It is followed by the variable-sized fields ar_sha, arp_spa,
   arp_tha and arp_tpa in that order, according to the lengths
   specified.  Field names used correspond to RFC 826.  */

#pragma pack(push, 1)
struct arphdr
  {
    unsigned short int ar_hrd;		/* Format of hardware address.  */
    unsigned short int ar_pro;		/* Format of protocol address.  */
    unsigned char ar_hln;		/* Length of hardware address.  */
    unsigned char ar_pln;		/* Length of protocol address.  */
    unsigned short int ar_op;		/* ARP opcode (command).  */
#if 0
    /* Ethernet looks like this : This bit is variable sized
       however...  */
    unsigned char __ar_sha[ETH_ALEN];	/* Sender hardware address.  */
    unsigned char __ar_sip[4];		/* Sender IP address.  */
    unsigned char __ar_tha[ETH_ALEN];	/* Target hardware address.  */
    unsigned char __ar_tip[4];		/* Target IP address.  */
#endif
  };
#pragma pack(pop)

/* ARP protocol HARDWARE identifiers. */
#define ARPHRD_NETROM	0		/* From KA9Q: NET/ROM pseudo. */
#define ARPHRD_ETHER 	1		/* Ethernet 10/100Mbps.  */
#define	ARPHRD_EETHER	2		/* Experimental Ethernet.  */
#define	ARPHRD_AX25	3		/* AX.25 Level 2.  */
#define	ARPHRD_PRONET	4		/* PROnet token ring.  */
#define	ARPHRD_CHAOS	5		/* Chaosnet.  */
#define	ARPHRD_IEEE802	6		/* IEEE 802.2 Ethernet/TR/TB.  */
#define	ARPHRD_ARCNET	7		/* ARCnet.  */
#define	ARPHRD_APPLETLK	8		/* APPLEtalk.  */
#define	ARPHRD_DLCI	15		/* Frame Relay DLCI.  */
#define	ARPHRD_ATM	19		/* ATM.  */
#define	ARPHRD_METRICOM	23		/* Metricom STRIP (new IANA id).  */
#define ARPHRD_IEEE1394	24		/* IEEE 1394 IPv4 - RFC 2734.  */
#define ARPHRD_IEEE1394_EUI64 25	/* IEEE 1394 EUI-64 hardware type */
#define ARPHRD_EUI64		27		/* EUI-64.  */
#define ARPHRD_INFINIBAND	32		/* InfiniBand.  */

/* Dummy types for non ARP hardware */
#define ARPHRD_SLIP	256
#define ARPHRD_CSLIP	257
#define ARPHRD_SLIP6	258
#define ARPHRD_CSLIP6	259
#define ARPHRD_RSRVD	260		/* Notional KISS type.  */
#define ARPHRD_ADAPT	264
#define ARPHRD_ROSE	270
#define ARPHRD_X25	271		/* CCITT X.25.  */
#define ARPHRD_HWX25	272		/* Boards with X.25 in firmware.  */
#define ARPHRD_CAN	280		/* Controller Area Network.  */
#define ARPHRD_MCTP	290
#define ARPHRD_PPP	512
#define ARPHRD_CISCO	513		/* Cisco HDLC.  */
#define ARPHRD_HDLC	ARPHRD_CISCO
#define ARPHRD_LAPB	516		/* LAPB.  */
#define ARPHRD_DDCMP	517		/* Digital's DDCMP.  */
#define	ARPHRD_RAWHDLC	518		/* Raw HDLC.  */
#define ARPHRD_RAWIP	519		/* Raw IP.  */

#define ARPHRD_TUNNEL	768		/* IPIP tunnel.  */
#define ARPHRD_TUNNEL6	769		/* IPIP6 tunnel.  */
#define ARPHRD_FRAD	770             /* Frame Relay Access Device.  */
#define ARPHRD_SKIP	771		/* SKIP vif.  */
#define ARPHRD_LOOPBACK	772		/* Loopback device.  */
#define ARPHRD_LOCALTLK 773		/* Localtalk device.  */
#define ARPHRD_FDDI	774		/* Fiber Distributed Data Interface. */
#define ARPHRD_BIF	775             /* AP1000 BIF.  */
#define ARPHRD_SIT	776		/* sit0 device - IPv6-in-IPv4.  */
#define ARPHRD_IPDDP	777		/* IP-in-DDP tunnel.  */
#define ARPHRD_IPGRE	778		/* GRE over IP.  */
#define ARPHRD_PIMREG	779		/* PIMSM register interface.  */
#define ARPHRD_HIPPI	780		/* High Performance Parallel I'face. */
#define ARPHRD_ASH	781		/* (Nexus Electronics) Ash.  */
#define ARPHRD_ECONET	782		/* Acorn Econet.  */
#define ARPHRD_IRDA	783		/* Linux-IrDA.  */
#define ARPHRD_FCPP	784		/* Point to point fibrechanel.  */
#define ARPHRD_FCAL	785		/* Fibrechanel arbitrated loop.  */
#define ARPHRD_FCPL	786		/* Fibrechanel public loop.  */
#define ARPHRD_FCFABRIC 787		/* Fibrechanel fabric.  */
#define ARPHRD_IEEE802_TR 800		/* Magic type ident for TR.  */
#define ARPHRD_IEEE80211 801		/* IEEE 802.11.  */
#define ARPHRD_IEEE80211_PRISM 802	/* IEEE 802.11 + Prism2 header.  */
#define ARPHRD_IEEE80211_RADIOTAP 803	/* IEEE 802.11 + radiotap header.  */
#define ARPHRD_IEEE802154 804		/* IEEE 802.15.4 header.  */
#define ARPHRD_IEEE802154_PHY 805	/* IEEE 802.15.4 PHY header.  */

#define ARPHRD_VOID	  0xFFFF	/* Void type, nothing is known.  */
#define ARPHRD_NONE	  0xFFFE	/* Zero header length.  */
#pragma endregion <net/if_arp.h>

#pragma region <netinet/if_ether.h>
/*
 * Ethernet Address Resolution Protocol.
 *
 * See RFC 826 for protocol description.  Structure below is adapted
 * to resolving internet addresses.  Field names used correspond to
 * RFC 826.
 */
#pragma pack(push, 1)
struct	ether_arp {
	struct	arphdr ea_hdr;		/* fixed-size header */
	uint8_t arp_sha[ETH_ALEN];	/* sender hardware address */
	uint8_t arp_spa[4];		/* sender protocol address */
	uint8_t arp_tha[ETH_ALEN];	/* target hardware address */
	uint8_t arp_tpa[4];		/* target protocol address */
};
#pragma pack(pop)
#define	arp_hrd	ea_hdr.ar_hrd
#define	arp_pro	ea_hdr.ar_pro
#define	arp_hln	ea_hdr.ar_hln
#define	arp_pln	ea_hdr.ar_pln
#define	arp_op	ea_hdr.ar_op

/*
 * Macro to map an IP multicast address to an Ethernet multicast address.
 * The high-order 25 bits of the Ethernet address are statically assigned,
 * and the low-order 23 bits are taken from the low end of the IP address.
 */
#define ETHER_MAP_IP_MULTICAST(ipaddr, enaddr) \
	/* struct in_addr *ipaddr; */ \
	/* uint8_t enaddr[ETH_ALEN]; */ \
{ \
	(enaddr)[0] = 0x01; \
	(enaddr)[1] = 0x00; \
	(enaddr)[2] = 0x5e; \
	(enaddr)[3] = ((uint8_t *)ipaddr)[1] & 0x7f; \
	(enaddr)[4] = ((uint8_t *)ipaddr)[2]; \
	(enaddr)[5] = ((uint8_t *)ipaddr)[3]; \
}
#pragma endregion <netinet/if_ether.h>

#pragma region <netinet/tcp.h>
typedef	uint32_t tcp_seq;
/*
 * TCP header.
 * Per RFC 793, September, 1981.
 */
#pragma pack(push, 1)
struct tcphdr
  {
    __extension__ union
    {
      struct
      {
	uint16_t th_sport;	/* source port */
	uint16_t th_dport;	/* destination port */
	tcp_seq th_seq;		/* sequence number */
	tcp_seq th_ack;		/* acknowledgement number */
# if __BYTE_ORDER == __LITTLE_ENDIAN
	uint8_t th_x2:4;	/* (unused) */
	uint8_t th_off:4;	/* data offset */
# endif
# if __BYTE_ORDER == __BIG_ENDIAN
	uint8_t th_off:4;	/* data offset */
	uint8_t th_x2:4;	/* (unused) */
# endif
	uint8_t th_flags;
# define TH_FIN	0x01
# define TH_SYN	0x02
# define TH_RST	0x04
# define TH_PUSH	0x08
# define TH_ACK	0x10
# define TH_URG	0x20
# define TH_ECE 0x40
# define TH_CWR 0x80
	uint16_t th_win;	/* window */
	uint16_t th_sum;	/* checksum */
	uint16_t th_urp;	/* urgent pointer */
      };
      struct
      {
	uint16_t source;
	uint16_t dest;
	uint32_t seq;
	uint32_t ack_seq;
# if __BYTE_ORDER == __LITTLE_ENDIAN
	uint16_t res1:4;
	uint16_t doff:4;
	uint16_t fin:1;
	uint16_t syn:1;
	uint16_t rst:1;
	uint16_t psh:1;
	uint16_t ack:1;
	uint16_t urg:1;
	uint16_t res2:2;
# elif __BYTE_ORDER == __BIG_ENDIAN
	uint16_t doff:4;
	uint16_t res1:4;
	uint16_t res2:2;
	uint16_t urg:1;
	uint16_t ack:1;
	uint16_t psh:1;
	uint16_t rst:1;
	uint16_t syn:1;
	uint16_t fin:1;
# else
#  error "Adjust your <bits/endian.h> defines"
# endif
	uint16_t window;
	uint16_t check;
	uint16_t urg_ptr;
      };
    };
};
#pragma pack(pop)

enum
{
  TCP_ESTABLISHED = 1,
  TCP_SYN_SENT,
  TCP_SYN_RECV,
  TCP_FIN_WAIT1,
  TCP_FIN_WAIT2,
  TCP_TIME_WAIT,
  TCP_CLOSE,
  TCP_CLOSE_WAIT,
  TCP_LAST_ACK,
  TCP_LISTEN,
  TCP_CLOSING   /* now a valid state */
};

# define TCPOPT_EOL		0
# define TCPOPT_NOP		1
# define TCPOPT_MAXSEG		2
# define TCPOLEN_MAXSEG		4
# define TCPOPT_WINDOW		3
# define TCPOLEN_WINDOW		3
# define TCPOPT_SACK_PERMITTED	4		/* Experimental */
# define TCPOLEN_SACK_PERMITTED	2
# define TCPOPT_SACK		5		/* Experimental */
# define TCPOPT_TIMESTAMP	8
# define TCPOLEN_TIMESTAMP	10
# define TCPOLEN_TSTAMP_APPA	(TCPOLEN_TIMESTAMP+2) /* appendix A */

# define TCPOPT_TSTAMP_HDR	\
    (TCPOPT_NOP<<24|TCPOPT_NOP<<16|TCPOPT_TIMESTAMP<<8|TCPOLEN_TIMESTAMP)

/*
 * Default maximum segment size for TCP.
 * With an IP MSS of 576, this is 536,
 * but 512 is probably more convenient.
 * This should be defined as MIN(512, IP_MSS - sizeof (struct tcpiphdr)).
 */
# define TCP_MSS	512

# define TCP_MAXWIN	65535	/* largest value for (unscaled) window */

# define TCP_MAX_WINSHIFT	14	/* maximum window shift */

# define SOL_TCP		6	/* TCP level */


# define TCPI_OPT_TIMESTAMPS	1
# define TCPI_OPT_SACK		2
# define TCPI_OPT_WSCALE	4
# define TCPI_OPT_ECN		8  /* ECN was negociated at TCP session init */
# define TCPI_OPT_ECN_SEEN	16 /* we received at least one packet with ECT */
# define TCPI_OPT_SYN_DATA	32 /* SYN-ACK acked data in SYN sent or rcvd */
#pragma endregion <netinet/tcp.h>

#pragma region <netinet/udp.h>
/* UDP header as specified by RFC 768, August 1980. */

#pragma pack(push, 1)
struct udphdr
{
  __extension__ union
  {
    struct
    {
      uint16_t uh_sport;	/* source port */
      uint16_t uh_dport;	/* destination port */
      uint16_t uh_ulen;		/* udp length */
      uint16_t uh_sum;		/* udp checksum */
    };
    struct
    {
      uint16_t source;
      uint16_t dest;
      uint16_t len;
      uint16_t check;
    };
  };
};
#pragma pack(pop)

/* UDP socket options */
#define UDP_CORK	1	/* Never send partially complete segments.  */
#define UDP_ENCAP	100	/* Set the socket to accept
				   encapsulated packets.  */
#define UDP_NO_CHECK6_TX 101	/* Disable sending checksum for UDP
				   over IPv6.  */
#define UDP_NO_CHECK6_RX 102	/* Disable accepting checksum for UDP
				   over IPv6.  */
#define UDP_SEGMENT	103	/* Set GSO segmentation size.  */
#define UDP_GRO		104	/* This socket can receive UDP GRO packets.  */

/* UDP encapsulation types */
#define UDP_ENCAP_ESPINUDP_NON_IKE 1	/* draft-ietf-ipsec-nat-t-ike-00/01 */
#define UDP_ENCAP_ESPINUDP	2	/* draft-ietf-ipsec-udp-encaps-06 */
#define UDP_ENCAP_L2TPINUDP	3	/* rfc2661 */
#define UDP_ENCAP_GTP0		4	/* GSM TS 09.60 */
#define UDP_ENCAP_GTP1U		5	/* 3GPP TS 29.060 */

#define SOL_UDP            17      /* sockopt level for UDP */
#pragma endregion <netinet/udp.h>

#endif // OS_WINDOWS
