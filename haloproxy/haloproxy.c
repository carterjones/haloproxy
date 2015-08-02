/*
    Copyright 2005,2006,2007 Luigi Auriemma

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA

    http://www.gnu.org/licenses/gpl.txt
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "halo_pck_algo.h"
#include "show_dump.h"
#include "rwbits.h"

#pragma comment(lib, "ws2_32.lib")

#ifdef WIN32
    #include <winsock.h>
    #include "winerr.h"

    #define close   closesocket
    #define sleep   Sleep
#else
    #include <unistd.h>
    #include <sys/socket.h>
    #include <sys/types.h>
    #include <arpa/inet.h>
    #include <netinet/in.h>
    #include <netdb.h>
#endif

typedef uint8_t     u8;
typedef uint16_t    u16;
typedef uint32_t    u32;



#define VER         "0.1.2"
#define BUFFSZ      0xffff
#define SEND(x,y)   sendto(x, buff, len, 0, (struct sockaddr *)&y, sizeof(struct sockaddr_in));
#define RECV(x,y)   len = recvfrom(x, buff, BUFFSZ, 0, (struct sockaddr *)&y, &psz); \
                    if(len < 0) std_err();



void genkeys(u8 *text, u8 *hash1, u8 *hash2, u8 *skey1, u8 *skey2, u8 *dkey1, u8 *dkey2);
void decshow(u8 *buff, int len, u8 *deckey, u8 *enckey);
int read_bstr(u8 *data, u32 len, u8 *buff, u32 bitslen);
void halobits(u8 *buff, int buffsz);
u32 resolv(char *host);
void std_err(void);



#pragma pack(1)
typedef struct {
    u16     sign;
    u8      type;
    u16     gs1;
    u16     gs2;
} gh_t;
#pragma pack()



int main(int argc, char *argv[]) {
    struct  sockaddr_in peer1,
                        peer2;
    fd_set  rset;
    gh_t    *gh;
    int     sd1,
            sd2,
            selsock,
            len,
            plain,
            on = 1,
            psz;
    u16     port,
            lport;
    u8      *buff,
            basekey1[16],
            basekey2[16],
            enckey1[16],    // client
            deckey1[16],
            enckey2[16],    // server
            deckey2[16],
            hash1[17],
            hash2[17],
            *psdk;

#ifdef WIN32
    WSADATA    wsadata;
    WSAStartup(MAKEWORD(1,0), &wsadata);
#endif

    setbuf(stdout, NULL);

    fputs("\n"
        "Halo proxy data decrypter "VER"\n"
        "by Luigi Auriemma\n"
        "e-mail: aluigi@autistici.org\n"
        "web:    aluigi.org\n"
        "\n", stdout);

    if(argc < 4) {
        printf("\n"
            "Usage: %s <server> <server_port> <local_port>\n"
            "\n"
            "How to use:\n"
            "1) launch this tool specifying the server in which you wanna join and the\n"
            "   ports to use, the game usually uses the port 2302\n"
            "2) open your game client\n"
            "3) connect your client to localhost on the port specified in local_port\n"
            "   only one client at time is supported\n"
            "\n", argv[0]);
        exit(1);
    }

    port  = atoi(argv[2]);
    lport = atoi(argv[3]);

    peer1.sin_addr.s_addr = INADDR_ANY;
    peer1.sin_port        = htons(lport);
    peer1.sin_family      = AF_INET;

    peer2.sin_addr.s_addr = resolv(argv[1]);
    peer2.sin_port        = htons(port);
    peer2.sin_family      = AF_INET;

    printf(
        "- target   %s : %hu\n"
        "- set local proxy on port %hu\n"
        "- only one client at time is allowed\n",
        inet_ntoa(peer2.sin_addr), port,
        lport);

    sd1 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if(sd1 < 0) std_err();
    sd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if(sd2 < 0) std_err();

    if(setsockopt(sd1, SOL_SOCKET, SO_REUSEADDR, (char *)&on, sizeof(on))
      < 0) std_err();
    if(bind(sd1, (struct sockaddr *)&peer1, sizeof(peer1))
      < 0) std_err();

    printf("- wait packets...\n");
    FD_ZERO(&rset);
    FD_SET(sd1, &rset);
    if(select(sd1 + 1, &rset, NULL, NULL, NULL)
      < 0) std_err();

    buff    = malloc(BUFFSZ);
    if(!buff) std_err();
    psdk    = buff + 7;
    gh      = (gh_t *)buff;
    selsock = 1 + ((sd1 > sd2) ? sd1 : sd2);
    psz     = sizeof(struct sockaddr_in);

    printf("- ready:\n");
    plain = 1;

    for(;;) {
        FD_ZERO(&rset);
        FD_SET(sd1, &rset);
        FD_SET(sd2, &rset);
        if(select(selsock, &rset, NULL, NULL, NULL)
          < 0) std_err();

        if(FD_ISSET(sd1, &rset)) {
            printf("\n    ### CLIENT ###\n");
            RECV(sd1, peer1);

            if(ntohs(gh->sign) == 0xfefd) {
                plain = 1;
            }
            if((ntohs(gh->sign) == 0xfefe) && (gh->type == 1) && (ntohs(gh->gs1) == 0) && (ntohs(gh->gs2) == 0)) {
                genkeys("my client", hash1, hash2, NULL, NULL, basekey1, basekey2);
                plain = 1;
            }

            if(plain) {
                if((ntohs(gh->sign) == 0xfefe) && (gh->type == 3) && (ntohs(gh->gs1) == 1) && (ntohs(gh->gs2) == 1)) {
                    genkeys("client", hash1, hash1, psdk + 32, psdk + 32, deckey1, enckey1);
                    memcpy(psdk + 32, basekey2, 16);
                }
                show_dump(buff, len, stdout);
            } else {
                decshow(buff, len, deckey1, enckey2);
            }

            SEND(sd2, peer2);

        } else if(FD_ISSET(sd2, &rset)) {
            printf("\n    ### SERVER ###\n");
            RECV(sd2, peer2);

            if((ntohs(gh->sign) == 0xfefe) && (gh->type == 2) && (ntohs(gh->gs1) == 0) && (ntohs(gh->gs2) == 1)) {
                genkeys("my server", hash1, hash2, NULL, NULL, basekey1, basekey2);
                plain = 1;
            }

            if(plain) {
                if((ntohs(gh->sign) == 0xfefe) && (gh->type == 4) && (ntohs(gh->gs1) == 1) && (ntohs(gh->gs2) == 2)) {
                    genkeys("server", hash2, hash2, psdk, psdk, deckey2, enckey2);
                    memcpy(psdk, basekey1, 16);
                    plain = 0;
                }
                show_dump(buff, len, stdout);
            } else {
                decshow(buff, len, deckey2, enckey1);
            }

            SEND(sd1, peer1);
        }
    }

    close(sd1);
    close(sd2);
    free(buff);
    return(0);
}



void genkeys(u8 *text, u8 *hash1, u8 *hash2, u8 *skey1, u8 *skey2, u8 *dkey1, u8 *dkey2) {
    printf("- generate %s keys\n", text);
    halo_generate_keys(hash1, skey1, dkey1);
    halo_generate_keys(hash2, skey2, dkey2);
}



void decshow(u8 *buff, int len, u8 *deckey, u8 *enckey) {
    gh_t    *gh;
    int     head;

    head = 0;
    gh   = (gh_t *)buff;

    if(ntohs(gh->sign) == 0xfefd) { /* info */
        show_dump(buff, len, stdout);
        return;
    }
    if(ntohs(gh->sign) == 0xfefe) {
        if(len <= 7) {
            show_dump(buff, len, stdout);
            return;
        }
        head = 7;
    }

    halo_tea_decrypt(buff + head, len - head, deckey);

    if(head) show_dump(buff, head, stdout);
    halobits(buff + head, len - head);

    halo_tea_encrypt(buff + head, len - head, enckey);
}



int read_bstr(u8 *data, u32 len, u8 *buff, u32 bitslen) {
    int     i;

    for(i = 0; i < len; i++) {
        data[i] = read_bits(8, buff, bitslen);
        bitslen += 8;
    }
    return(bitslen);
}



void halobits(u8 *buff, int buffsz) {
    int     b,
            n,
            o;
    u8      str[1 << 11];

    buffsz -= 4;    // crc;
    if(buffsz <= 0) return;
    buffsz <<= 3;

    for(b = 0;;) {
        if((b + 11) > buffsz) break;
        n = read_bits(11, buff, b);     b += 11;

        if((b + 1) > buffsz) break;
        o = read_bits(1,  buff, b);     b += 1;

        if((b + n) > buffsz) break;
        b = read_bstr(str, n, buff, b);
        show_dump(str, n, stdout);
    }
}



u32 resolv(char *host) {
    struct  hostent *hp;
    u32     host_ip;

    host_ip = inet_addr(host);
    if(host_ip == INADDR_NONE) {
        hp = gethostbyname(host);
        if(!hp) {
            printf("\nError: Unable to resolv hostname (%s)\n", host);
            exit(1);
        } else host_ip = *(u32 *)(hp->h_addr);
    }
    return(host_ip);
}



#ifndef WIN32
    void std_err(void) {
        perror("\nError");
        exit(1);
    }
#endif


