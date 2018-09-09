//
// IPA 産業サイバーセキュリティセンター サイバー技術研究室 特別講義 (2018/9/18 1 限目)
// 講義利用サンプルコード (C 言語)
// 「IPA-DN-TestIDS」 by Inchiki Tenuki
// Copyright (c) 2018 IPA ICSCoE Cyber-Lab
// 
// 取扱い: TLP なし (秘密情報なし)
// 作者: Inchiki Tenuki 氏 (≓ Daiyuu Nobori)
// 
// 動作環境: なんと 以下の 3 OS で動作いたします。
// - Windows, Linux, macOS
// 
// Windows: Visual Studio 2017 と winpcap が必要
// Linux および macOS: gcc および OpenSSL が必要


// C 言語のおなじみの include 集
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <wchar.h>
#include <stdarg.h>
#include <locale.h>
#include <time.h>
#include <errno.h>

// この nativelib というのは、手抜きライブラリであり、Inchiki Tenuki 氏が過去に作成したものを
// 大変いい加減にコンパイルしやすいように 1 つの C 言語ソースに無理やりまとめたものである。
// モダンなプログラミング言語におけるライブラリのようなものであるが、
// なんと nativelib.c 1 ファイルだけで 28 万行 (約 6MB) もあり、
// 可読性は全く考慮されていないのである。
// しかしながら、このライブラリのおかげで、Windows、Linux、macOS で色々な処理を共通して
// 書くことができるようになっている。
#include <nativelib.h>

#include "lowether.h"

// インチキ関数 (大文字・小文字を区別せずに文字列比較)
// http://www.c-tipsref.com/reference/ctype/toupper.html からもらってきた。もらいっこ。
// (C) Copyright 2010, C言語関数辞典 - Created by Kojo Sugita
int strcmp_ignorecase(const char *s1, const char *s2) {
	int i = 0;

	/* 文字が等しい間繰り返す */
	while (toupper((unsigned char)s1[i]) == toupper((unsigned char)s2[i])) {
		if (s1[i] == '\0') {
			return 0;
		}
		i++;
	}

	return toupper((unsigned char)s1[i]) - toupper((unsigned char)s2[i]);
}

// 構造体のパディングを無効にする
#ifdef	OS_WIN32
#pragma pack(push, 1)
#endif	// OS_WIN32

// --------------------------------------
// パケット解析のために利用する構造体の定義
// --------------------------------------

// Ethernet ヘッダ
// 参考: https://en.wikipedia.org/wiki/Ethernet_frame
typedef struct ETHERNET_HEADER
{
	UCHAR	DestAddress[6];			// Source MAC address
	UCHAR	SrcAddress[6];			// Destination MAC address
	USHORT	Protocol;				// Protocol (=TPID)
} GCC_PACKED ETHERNET_HEADER;

// TPID の値
// 参考: https://en.wikipedia.org/wiki/EtherType
#define	TPID_PROTO_ARPV4		0x0806	// ARPv4
#define	TPID_PROTO_IPV4			0x0800	// IPv4
#define	TPID_PROTO_IPV6			0x86dd	// IPv6
#define	TPID_PROTO_TAGVLAN		0x8100	// IEEE802.1Q タグ付き VLAN

// IEEE802.1Q タグ VLAN ヘッダ
// 参考: https://en.wikipedia.org/wiki/IEEE_802.1Q
typedef struct TAG_VLAN_HEADER
{
	USHORT Tag;
	USHORT Protocol;
} GCC_PACKED TAG_VLAN_HEADER;

// IPv4 ヘッダ
// 参考: https://en.wikipedia.org/wiki/IPv4#Header
typedef struct IPV4_HDR
{
	UCHAR	VersionAndHeaderLength;		// Version and header size
	UCHAR	TypeOfService;				// Service Type
	USHORT	TotalLength;				// Total size
	USHORT	Identification;				// Identifier
	UCHAR	FlagsAndFlagmentOffset[2];	// Flag and Fragment offset
	UCHAR	TimeToLive;					// TTL
	UCHAR	Protocol;					// Protocol
	USHORT	Checksum;					// Checksum
	UINT	SrcIP;						// Source IP address
	UINT	DstIP;						// Destination IP address
} GCC_PACKED IPV4_HDR;

// IPv4 ヘッダの分析のための便利な手抜きマクロ
#define	IP_V4_GET_VERSION(h)			(((h)->VersionAndHeaderLength >> 4 & 0x0f))
#define	IP_V4_SET_VERSION(h, v)		((h)->VersionAndHeaderLength |= (((v) & 0x0f) << 4))
#define	IP_V4_GET_HEADER_LEN(h)		((h)->VersionAndHeaderLength & 0x0f)
#define	IP_V4_SET_HEADER_LEN(h, v)	((h)->VersionAndHeaderLength |= ((v) & 0x0f))
#define	IP_V4_GET_FLAGS(h)			(((h)->FlagsAndFlagmentOffset[0] >> 5) & 0x07)
#define	IP_V4_SET_FLAGS(h, v)		((h)->FlagsAndFlagmentOffset[0] |= (((v) & 0x07) << 5))
#define	IP_V4_GET_OFFSET(h)			(((h)->FlagsAndFlagmentOffset[0] & 0x1f) * 256 + ((h)->FlagsAndFlagmentOffset[1]))
#define	IP_V4_SET_OFFSET(h, v)		{(h)->FlagsAndFlagmentOffset[0] |= (UCHAR)((v) / 256); (h)->FlagsAndFlagmentOffset[1] = (UCHAR)((v) % 256);}

// IPv4 上で動作する L4 以上のプロトコルのプロトコル番号
// 参考: https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
#define	IPV4_PROTO_TCP		0x06	// TCP protocol
#define	IPV4_PROTO_UDP		0x11	// UDP protocol

// TCP ヘッダ
// 参考: https://en.wikipedia.org/wiki/Transmission_Control_Protocol
typedef struct TCP_HDR
{
	USHORT	SrcPort;					// Source port number
	USHORT	DstPort;					// Destination port number
	UINT	SeqNumber;				// Sequence number
	UINT	AckNumber;				// Acknowledgment number
	UCHAR	HeaderSizeAndReserved;	// Header size and Reserved area
	UCHAR	Flag;					// Flag
	USHORT	WindowSize;				// Window size
	USHORT	Checksum;				// Checksum
	USHORT	UrgentPointer;			// Urgent Pointer
} GCC_PACKED TCP_HDR;

// TCP ヘッダの分析のための便利なマクロ
#define	TCP_HDR_GET_HEADER_SIZE(h)	(((h)->HeaderSizeAndReserved >> 4) & 0x0f)
#define	TCP_HDR_SET_HEADER_SIZE(h, v)	((h)->HeaderSizeAndReserved = (((v) & 0x0f) << 4))

// いやないやな TCP フラグ
#define	TCP_FLAG_FIN						1
#define	TCP_FLAG_SYN						2
#define	TCP_FLAG_RST						4
#define	TCP_FLAG_PSH						8
#define	TCP_FLAG_ACK						16
#define	TCP_FLAG_URG						32

// パディングを有効に戻す
#ifdef	OS_WIN32
#pragma pack(pop)
#endif	// OS_WIN32

// 6. HTTP リクエストをレポートする手抜き関数
void report_http_request(ETHERNET_HEADER *eth_header, IPV4_HDR *v4_header, TCP_HDR *tcp_header, char *method, char *url, UINT vlan_id)
{
	UCHAR *a;
	char str_eth_src[20];
	char str_eth_dst[20];
	char str_ip_src[20];
	char str_ip_dst[20];

	// Ethernet の送信元 / 宛先 MAC アドレスを文字列に変換する
	// ※ sprintf 関数は非推奨であるが、手抜きで使っている。生成される文字列長が確定している場合は危険はない。
	a = eth_header->SrcAddress;
	sprintf(str_eth_src, "%02X:%02X:%02X:%02X:%02X:%02X", a[0], a[1], a[2], a[3], a[4], a[5]);
	a = eth_header->DestAddress;
	sprintf(str_eth_dst, "%02X:%02X:%02X:%02X:%02X:%02X", a[0], a[1], a[2], a[3], a[4], a[5]);

	// 送信元 / 宛先 IPv4 アドレスを文字列に変換する
	// ※ sprintf 関数は非推奨であるが、手抜きで使っている。生成される文字列長が確定している場合は危険はない。
	a = (UCHAR *)(&v4_header->SrcIP);
	sprintf(str_ip_src, "%u.%u.%u.%u", a[0], a[1], a[2], a[3]);
	a = (UCHAR *)(&v4_header->DstIP);
	sprintf(str_ip_dst, "%u.%u.%u.%u", a[0], a[1], a[2], a[3]);

	// 画面に表示する
	printf("[HTTP %s] %s:%u -> %s:%u ", method, str_ip_src, Endian16(tcp_header->SrcPort), str_ip_dst, Endian16(tcp_header->DstPort));
	printf("VLAN ID: %u, eth_src: %s, eth_dst: %s ", vlan_id, str_eth_src, str_eth_dst);
	printf("%s\n", url);
}

// 5. TCP の接続 / 切断をレポートする手抜き関数
void report_tcp_connect_or_disconnect(ETHERNET_HEADER *eth_header, IPV4_HDR *v4_header, TCP_HDR *tcp_header, char *op_type, UINT vlan_id)
{
	UCHAR *a;
	char str_eth_src[20];
	char str_eth_dst[20];
	char str_ip_src[20];
	char str_ip_dst[20];

	// Ethernet の送信元 / 宛先 MAC アドレスを文字列に変換する
	// ※ sprintf 関数は非推奨であるが、手抜きで使っている。生成される文字列長が確定している場合は危険はない。
	a = eth_header->SrcAddress;
	sprintf(str_eth_src, "%02X:%02X:%02X:%02X:%02X:%02X", a[0], a[1], a[2], a[3], a[4], a[5]);
	a = eth_header->DestAddress;
	sprintf(str_eth_dst, "%02X:%02X:%02X:%02X:%02X:%02X", a[0], a[1], a[2], a[3], a[4], a[5]);

	// 送信元 / 宛先 IPv4 アドレスを文字列に変換する
	// ※ sprintf 関数は非推奨であるが、手抜きで使っている。生成される文字列長が確定している場合は危険はない。
	a = (UCHAR *)(&v4_header->SrcIP);
	sprintf(str_ip_src, "%u.%u.%u.%u", a[0], a[1], a[2], a[3]);
	a = (UCHAR *)(&v4_header->DstIP);
	sprintf(str_ip_dst, "%u.%u.%u.%u", a[0], a[1], a[2], a[3]);

	// 画面に表示する
	printf("[%s] %s:%u -> %s:%u ", op_type, str_ip_src, Endian16(tcp_header->SrcPort), str_ip_dst, Endian16(tcp_header->DstPort));
	printf("VLAN ID: %u, eth_src: %s, eth_dst: %s\n", vlan_id, str_eth_src, str_eth_dst);
}

// 4. TCP パケットを 1 つ受信した際に呼び出される偉大なる関数様
void one_tcp_packet_is_received(ETHERNET_HEADER *eth_header, IPV4_HDR *v4_header, UCHAR *buffer, UINT size, UINT vlan_id)
{
	// TCP ヘッダを分析いたします
	if (size >= sizeof(TCP_HDR))
	{
		TCP_HDR *tcp_header = (TCP_HDR *)buffer;

		// TCP ヘッダはヘンテコな構造なのでヘッダ内に書かれている「ヘッダサイズ」を読み取る必要があるんだぞ
		UINT tcp_hdr_len = TCP_GET_HEADER_SIZE(tcp_header) * 4;

		if (tcp_hdr_len >= sizeof(TCP_HDR))
		{
			if (size >= tcp_hdr_len)
			{
				buffer += tcp_hdr_len;
				size -= tcp_hdr_len;

				if ((tcp_header->Flag & TCP_FLAG_SYN) && !(tcp_header->Flag & TCP_FLAG_ACK))
				{
					// TCP の接続要求パケット (SYN) を受信したぞ。報告だ！
					report_tcp_connect_or_disconnect(eth_header, v4_header, tcp_header, "TCP SYN", vlan_id);
				}
				else if ((tcp_header->Flag & TCP_FLAG_SYN) && (tcp_header->Flag & TCP_FLAG_ACK))
				{
					// TCP の接続応答パケット (SYN ＋ACK) を受信したぞ。報告だ！
					report_tcp_connect_or_disconnect(eth_header, v4_header, tcp_header, "TCP SYN+ACK", vlan_id);
				}
				else if (tcp_header->Flag & TCP_FLAG_RST)
				{
					// TCP の切断通知パケット (RST) を受信したぞ。報告だ！
					report_tcp_connect_or_disconnect(eth_header, v4_header, tcp_header, "TCP RST", vlan_id);
				}
				else if (tcp_header->Flag & TCP_FLAG_FIN)
				{
					// TCP の切断通知パケット (FIN) を受信したぞ。報告だ！
					report_tcp_connect_or_disconnect(eth_header, v4_header, tcp_header, "TCP FIN", vlan_id);
				}
				else if (!(tcp_header->Flag & TCP_FLAG_SYN) && (tcp_header->Flag & TCP_FLAG_ACK))
				{
					// TCP のデータパケットを受信したぞ。宛先が Port 80 (HTTP) の場合は、中身を分析してみよう
					if (Endian16(tcp_header->DstPort) == 80)
					{
						if (size >= 5 && size <= 1500)
						{
							// 超絶 手抜き
							if ((buffer[0] == 'G' && buffer[1] == 'E' && buffer[2] == 'T' && buffer[3] == ' ') ||
								(buffer[0] == 'P' && buffer[1] == 'O' && buffer[2] == 'S' && buffer[3] == 'T' && buffer[4] == ' '))
							{
								// GET または POST で始まる TCP データなので HTTP である可能性があるぞ
								char safe_str[2000] = { 0 };
								memcpy(safe_str, buffer, size); // size は 1500 以下であるので安全
								int len = (int)strlen(safe_str);
								int newline_start_pos = 0;
								int n = 0;
								char *method = NULL;
								char host_header_value[2000] = { 0 };
								char request_path[2000] = { 0 };
								int i;

								// 手抜きコード 改行コードごとに分割して 1 行抜き出す
								for (i = 0; i < len; i++)
								{
									char c = safe_str[i];
									char tmp[2000] = { 0 };
									if (c == '\r' || c == '\n')
									{
										// 本当は strcpy なんか使ってはいけませンよ!
										// しかしこのケースでは入力文字列の最大長が限定されるので一応は安全なのでよい
										strcpy(tmp, &safe_str[newline_start_pos]);
										tmp[i - newline_start_pos] = 0;
										newline_start_pos = i + 1;
										if (strlen(tmp) >= 1)
										{
											// 抜き出した 1 行を分析する
											if (n == 0)
											{
												int skip_len = 0;
												int i;
												// 1 行目は GET とかになっているはず
												if (memcmp(tmp, "GET ", 4) == 0)
												{
													method = "GET";
													skip_len = 4;
												}
												else if (memcmp(tmp, "POST ", 5) == 0)
												{
													method = "POST";
													skip_len = 5;
												}
												// 本当は strcpy なんか使ってはいけませンよ!
												// しかしこのケースでは入力文字列の最大長が限定されるので一応は安全なのでよい
												strcpy(request_path, &tmp[skip_len]);
												// HTTP バージョン番号文字列は目障りなので消してやる
												for (i = 0; i < strlen(request_path); i++)
													if (request_path[i] == ' ') request_path[i] = 0;
											}
											else
											{
												// 2 行目以降は HTTP ヘッダ情報が付いている。HOST: ヘッダを探してみる
												char neko[6] = { 0 };
												memcpy(neko, tmp, 5);
												if (strcmp_ignorecase(neko, "host:") == 0)
												{
													// HOST: ヘッダらしき先頭文字を発見した。値を取得する
													char *s = &tmp[5];
													while (*s == ' ') s++;
													// 本当は strcpy なんか使ってはいけませンよ!
													// しかしこのケースでは入力文字列の最大長が限定されるので一応は安全なのでよい
													strcpy(host_header_value, s);
												}
											}
											n++;
										}
									}
								}

								// HTTP リクエストのパースに成功した場合
								if (method != NULL && strlen(host_header_value) >= 1 && strlen(request_path) >= 1)
								{
									// URL を組立てる
									char url[2000];
									// あっ危険な sprintf 関数だ！まったくけしからんな
									sprintf(url, "http://%s%s", host_header_value, request_path);
									
									// 報告だ !
									report_http_request(eth_header, v4_header, tcp_header, method, url, vlan_id);
								}
							}
						}
					}
				}
			}
		}
	}
}

// 3. Ethernet フレームを 1 つ受信した際に呼び出される偉大なる関数
void one_ethernet_frame_is_received(UCHAR *buffer, UINT size)
{
	UINT vlan_id = 0;

	// フレームサイズが 1518 バイトより大きいもの (Jumbo Frame) は無視する
	// 1518 = MTU 1500 + DST_MAC 6 + SRC_MAC 6 + TPID 2 + TAG_VLAN 4
	if (size > 1518) return;

	// Ethernet ヘッダを分析いたします
	if (size >= sizeof(ETHERNET_HEADER))
	{
		ETHERNET_HEADER *eth_header = (ETHERNET_HEADER *)buffer;
		USHORT tpid = Endian16(eth_header->Protocol);

		buffer += sizeof(ETHERNET_HEADER);
		size -= sizeof(ETHERNET_HEADER);

		if (tpid == TPID_PROTO_TAGVLAN && (size >= sizeof(TAG_VLAN_HEADER)))
		{
			// IEEE802.1Q タグ VLAN パケットの場合、VLAN ID を読み取ってからタグを除去する
			TAG_VLAN_HEADER *tag_header = (TAG_VLAN_HEADER *)buffer;
			USHORT tag = Endian16(tag_header->Tag);
			vlan_id = tag & 0xFFF;
			tpid = Endian16(tag_header->Protocol);

			buffer += sizeof(TAG_VLAN_HEADER);
			size -= sizeof(TAG_VLAN_HEADER);
		}

		if (tpid == TPID_PROTO_IPV4)
		{
			// あっ！ IPv4 パケットを受信したようだぞ。ちょいと IPv4 ヘッダを分析してやろう
			if (size >= sizeof(IPV4_HDR))
			{
				IPV4_HDR *ipv4_hdr = (IPV4_HDR *)buffer;

				// 一応ヘッダに書かれている IP バージョンが 4 かどうか確認したろ！
				if (IP_V4_GET_VERSION(ipv4_hdr) == 4)
				{
					// IPv4 ヘッダはヘンテコな構造なのでヘッダ内に書かれている「ヘッダサイズ」を読み取る必要があるんだぞ
					UINT ipv4_hdr_len = IP_V4_GET_HEADER_LEN(ipv4_hdr) * 4;
					if (ipv4_hdr_len >= sizeof(IPV4_HDR))
					{
						if (size >= ipv4_hdr_len)
						{
							buffer += ipv4_hdr_len;
							size -= ipv4_hdr_len;

							// 簡単のために、フラグメント化 (複数パケットに分割) されていない IPv4 パケットのみを対象にいたします
							if (IP_V4_GET_OFFSET(ipv4_hdr) == 0 && (IP_V4_GET_FLAGS(ipv4_hdr) & 0x01) == 0)
							{
								// IPv4 パケットの TotalLength の長さを確認します
								USHORT ipv4_total_len = Endian16(ipv4_hdr->TotalLength);
								if (ipv4_total_len >= ipv4_hdr_len)
								{
									UINT ipv4_data_len = ipv4_total_len - ipv4_hdr_len;
									if (size >= ipv4_data_len)
									{
										size = ipv4_data_len;

										if (ipv4_hdr->Protocol == IPV4_PROTO_TCP)
										{
											// あっ！ これは TCP パケットだな。よっし TCP パケットを処理する関数を呼び出してやろう。丸投げや！
											one_tcp_packet_is_received(eth_header, ipv4_hdr, buffer, size, vlan_id);
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}
}

// 2. メインループスレッド。新たな Ethernet フレームを次々に受信する
void main_loop_thread(THREAD *thread, void *param)
{
	MAIN_LOOP_THREAD_PARAM *p = (MAIN_LOOP_THREAD_PARAM *)param;
	ETH *eth = p->Eth;

	while (p->Halt == false)
	{
		// 新しい Ethernet フレームが 1 つ以上受信されるまで CPU を Sleep させる
		Select(NULL, INFINITE, p->Cancel, NULL);

		// 受信された Ethernet フレームを 1 つずつ処理する
		while (true)
		{
			void *recv_packet;
			UINT size = EthGetPacket(eth, &recv_packet);

			if (size == 0)
			{
				// これ以上受信 Ethernet フレームはない
				break;
			}
			else if (size == INFINITE)
			{
				// 致命的なエラーが発生した (例: NIC が無効化された、USB-NIC が抜かれた)
				Print("EthGetPacket: interface error.\n");
				break;
			}
			else
			{
				// Ethernet フレームを受信した
				one_ethernet_frame_is_received(recv_packet, size);

				Free(recv_packet);
			}
		}
	}
}

// 1. C 言語でおなじみの main() 関数様
int main(int argc, char *argv[])
{
	char if_name[256] = { 0 };

	SetHamMode();
	InitMayaqua(false, false, argc, argv);
	InitCedar();
	InitEth();

	Print("IPA-DN-TestIDS Sample C Program (Inchiki Tenuki)\n");
	Print("Copyright (c) 2018 IPA ICSCoE Cyber-Lab\n");
	Print("\n");

	if (argc >= 2) StrCpy(if_name, sizeof(if_name), argv[1]);
	
	if (IsEmptyStr(if_name))
	{
		// Print the list of Ethernet adapters on the system currently running
		TOKEN_LIST *t = GetEthList();
		UINT i;

		if (t->NumTokens == 0)
		{
			Print("Failed to open the low-level Ethernet API.\n");
			Print("You must run this program with the root privilege.\n");
			Print("Use sudo to run this program.\n");
		}
		else
		{
			Print("--- List of available Ethernet adapters ---\n");

			for (i = 0;i < t->NumTokens;i++)
			{
				char *eth_name = t->Token[i];
				wchar_t tmp2[MAX_SIZE];
				char tmp[MAX_SIZE];

				Zero(tmp, sizeof(tmp));
				Zero(tmp2, sizeof(tmp2));

#ifdef OS_UNIX
				EthGetInterfaceDescriptionUnix(eth_name, tmp, sizeof(tmp));
				StrToUni(tmp2, sizeof(tmp2), tmp);
#else  // OS_UNIX
				GetEthNetworkConnectionName(tmp2, sizeof(tmp2), eth_name);
#endif // OS_UNIX

				if (UniIsEmptyStr(tmp2) == false)
				{
					UniPrint(L"NIC #%u: %S\n  description: %s\n", i, eth_name, tmp2);
				}
				else
				{
					UniPrint(L"name: %S\n", eth_name);
				}
			}
		}

		FreeToken(t);
	}
	else
	{
		// Open the specified Ethernet adapter
		ETH *eth;
		
		Print("Opening the device '%s' ...\n", if_name);
		eth = OpenEth(if_name, false, false, NULL);

		if (eth == NULL)
		{
			Print("Failed to open the device '%s'.\n", if_name);
			Print("Please ensure that this process is running with the root privilege.\n");
		}
		else
		{
			MAIN_LOOP_THREAD_PARAM p;
			THREAD *thread;

			Zero(&p, sizeof(p));
			p.Eth = eth;
			p.Cancel = p.Eth->Cancel;

			AddRef(p.Cancel->ref);

			thread = NewThread(main_loop_thread, &p);

			Print("Press Enter key to exit the process.\n");

			GetLine(NULL, 0);

			Print("Stoping the main loop thread...\n");

			p.Halt = true;

			Cancel(p.Cancel);

			WaitThread(thread, INFINITE);
			ReleaseThread(thread);

			ReleaseCancel(p.Cancel);

			Print("Stop ok.\n");

			CloseEth(eth);
		}
	}

	FreeEth();
	FreeCedar();
	FreeMayaqua();

	return 0;
}

