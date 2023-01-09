// bob11-$IN$A

#include <pcap.h> // pcap_open_live, pcap_next_ex
#include <stdbool.h> // bool func
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <pthread.h> // create thread
#include <time.h> // date
#include <unistd.h> // usleep

#include "main.h" // 구조체 정의 헤더

// -------------------------------------global variable--------------------------------------------------------- //

b_info * pk_beacon; // beacon frame
p_info * pk_probe; // probe frame

radiotap_header * radiotap; // radiotap
dot11_header * dot11; // ieee802.11

f_param * fixed; // fixed parameter
t_param * tagged; // tagged parameter

int ch_arr[] = {1, 7, 13, 2, 8, 3, 14, 9, 4, 10, 5, 11, 6, 12}; // 기존 airodump-ng.c 의 bg_chans 구성 참고
int ch_cnt, b_cnt, p_req_cnt, p_res_cnt = 0;
long long time_tmp = 0;
int elapsed =  0; // 경과 시간 측정

b_info b_data[100]; // beacon 저장
p_info p_req_data[100]; // request probe 저장
p_info p_res_data[100]; // response probe 저장

// uint16_t freq = 0;

// -------------------------------------function--------------------------------------------------------- //

void usage() {
    printf("syntax: ./airodump-ng <interface>\n"); // skeleton
    printf("sample: ./airodump-ng mon0\n"); // skeleton
}

typedef struct { // skeleton
    char * dev_;
} Param;

Param param = { // skeleton
    .dev_ = NULL
};

bool parse(Param * param, int argc, char * argv[]) { // skeleton
    
    if (argc != 2) {
        usage();
        return false;
    }
    param->dev_ = argv[1]; // NIC 담기
    return true;
}

// BSSID, ESSID MAC 주소 출력 포맷팅 함수, dumpwrite.c 참고
void print_SSID(uint8_t * MAC_addr) { 

    if (!memcmp(MAC_addr, "\x00\x00\x00\x00\x00\x00", 6) 
    || !memcmp(MAC_addr, "\xFF\xFF\xFF\xFF\xFF\xFF", 6)) { // mac addr is NULL
        printf(" (not associated)  "); // not connect
    }
    else {
        printf(" %02X:%02X:%02X:%02X:%02X:%02X ", 
                    MAC_addr[0], 
                    MAC_addr[1], 
                    MAC_addr[2], 
                    MAC_addr[3], 
                    MAC_addr[4], 
                    MAC_addr[5]);
    }

    /* 
    for (i = 0; i < 5; i++) {
        printf("%02x:", MAC_addr[i]);
    }
    printf("%02x\n", MAC_addr[5]);
    */
}

// rate buffer write 함수
void write_rate() {
    // airodump-ng.c source code 내 AP-STATION 간 expression 참고, qos : "e" 로 표현(enabled)
    snprintf(pk_probe->RATE, sizeof(pk_probe->RATE), "%2d%1s-%2d%1s", pk_probe->AP_RATE, pk_probe->AP_QOS ? "e" : "", pk_probe->STATION_RATE, pk_probe->STATION_QOS ? "e" : "");
}

// 결과 출력 포맷팅 함수
void print_result(int b_cnt, int p_req_cnt, int p_res_cnt, b_info * beacon, p_info * probe_req, p_info * probe_res) {
    
    struct tm * date;
    const time_t t = time(NULL);
    date = localtime(&t);

    // 최상단 출력
    printf("\e[2J\e[H\e[?25l"); // ANSI escape code
    printf("\n CH %2d", ch_arr[ch_cnt]);  // 채널 출력
    printf(" ][ Elapsed: %d s", elapsed); // 경과 시간 출력
    printf(" ][ %4d-%02d-%02d %02d:%02d", 
                    date->tm_year + 1900, 
                    date->tm_mon + 1, 
                    date->tm_mday, 
                    date->tm_hour, 
                    date->tm_min); // 시간 출력

    // beacon frame 출력
    printf("\n\n BSSID              PWR  Beacons    #Data, #/s  CH  MB   ENC  CIPHER AUTH ESSID\n\n");

    for (int i = 0; i < b_cnt; i++) {
        pk_beacon = beacon + i;
        print_SSID(pk_beacon->BSSID);
        printf(" %3d     %4d     %4d  %3d %3d  %-4s %-4s %-4s   %-3s  %-33s\n", 
                    pk_beacon->PWR, 
                    pk_beacon->BEACONS, 
                    pk_beacon->DATA, 
                    pk_beacon->DPPS, 
                    pk_beacon->CH, 
                    pk_beacon->MB,
                    pk_beacon->ENC, 
                    pk_beacon->CIPHER, 
                    pk_beacon->AUTH, 
                    pk_beacon->ESSID);
    }

    // probe request, response frame 출력
    printf("\n BSSID              STATION            PWR   Rate    Lost    Frames  Probes\n\n");

    // 
    for (int j = 0; j < p_req_cnt; j++) {
        pk_probe = probe_req + j;
        print_SSID(pk_probe->BSSID);
        print_SSID(pk_probe->STATION);
        printf(" %3d  %8s  %4d    %5d  %-33s\n", 
                    pk_probe->PWR, 
                    pk_probe->RATE, 
                    pk_probe->LOST, 
                    pk_probe->FRAMES, 
                    pk_probe->PROBE);
    }

    //usleep(5000); // interval

    for (int j = 0; j < p_res_cnt; j++) {
        pk_probe = probe_res + j;
        print_SSID(pk_probe->BSSID);
        print_SSID(pk_probe->STATION);
        printf(" %3d  %8s  %4d    %5d  %-33s\n", 
                    pk_probe->PWR, 
                    pk_probe->RATE, 
                    pk_probe->LOST, 
                    pk_probe->FRAMES, 
                    pk_probe->PROBE);
    }

    printf("\n");
}

// ms(Milliseconds) 시간 측정 함수
long long get_time() {

    struct timeval tv; 

    gettimeofday(&tv, NULL); // ms 까지 받아오는 gettimeofday 사용

    long long ms = tv.tv_sec*1000LL + tv.tv_usec/1000; // sec : seconds, usec : milliseconds

    return ms;
}

// channel hopping
void * interval(void * dev) {

    while(true) {
        char cmd[255];

        /* begin = get_time();
           end = get_time();

        if(end - begin > 1000) {
            elapsed++;
        }
        */

        if (get_time() - time_tmp > 1000) {
            time_tmp = get_time();
            elapsed++;

            // hopping
            snprintf(cmd, sizeof(cmd), "iwconfig %s channel %d", (char *)dev, ch_arr[ch_cnt]);
            system(cmd);


            print_result(b_cnt, p_req_cnt, p_res_cnt, b_data, p_req_data, p_res_data);

            // channel control
            if (ch_cnt <= (sizeof(ch_arr) / sizeof(int)) - 1) {
                ch_cnt++;
            } else {
                ch_cnt = 0;
            } 
        }
    }
}

// rate data according to to_ds, from_ds
// void rate_qos(int r_flag, uint8_t data_rate)

/* frequency to channel in 802.11 radio information 
int getCH(uint16_t freq){

	if(freq < 3000){
		return (freq-2407)/5; // 1~
	}
	else if(freq > 5000 && freq <= 5865){
		return (freq-5000)/5;
	}
	else if(freq > 4000 && freq < 5000){
		return (freq-4000)/5;
	}
	else return -1;
}*/

// -------------------------------------Main--------------------------------------------------------- //

int main(int argc, char * argv[]) {

    int flag, i = 0;
    u_char * tag_data;

    // skeleton
    if (!parse(&param, argc, argv))
        return -1;

    // skeleton - dev open for packet capture
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t * pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf); // exception
        return -1;
    };

    // periodical한 출력을 위해 thread를 이용
    pthread_t p_thread;
    int thr_id;
    thr_id = pthread_create(&p_thread, NULL, interval, (void *)argv[1]);

    // airodump start
    while (true) {
        struct pcap_pkthdr * header;
        const u_char * packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        else if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap)); // exception
            break;
        } // skeleton

        
	    radiotap = (radiotap_header *)packet; // radiotap boundary 
        dot11 = (dot11_header *)(packet + radiotap->length); // ieee80211 boundary

// -------------------------------------radiotap--------------------------------------------------------- //

        /*
        bool isTSFT = ((radiotap->present_flag & 1) != 0);
        bool isFlags = ((radiotap->present_flag & 2) != 0);
        bool isRate = ((radiotap->present_flag & 4) != 0);
        bool isChannel = ((radiotap->present_flag & 8) != 0);
        bool isFHSS = ((radiotap->present_flag & 16) != 0);
        bool isSignal = ((radiotap->present_flag & 32) != 0);
        */


        int p_cnt = 1;
        

        // radiotap present flag의 ext(extension)이 설정되어 있다면 p_cnt 증가
        if ((radiotap->present_flag & (1 << 31)) >> 31) {
            p_cnt = 2;
        }
        

        uint8_t * flag_ptr = (uint8_t *)&(radiotap->present_flag) + (4 * p_cnt); // present_flag offset을 계산해줄 flag_ptr
        uint8_t data_rate = 0;
        int pwr = -1;

        // data_rate와 pwr을 가져오기 위해선 활성화 되어 있는 필드들을 건너 뛰어 주는 것이 필요
        // present flag로 rate, pwr 계산
        for (uint32_t pflag = 0; pflag < 32; pflag++) {
            if (radiotap->present_flag & (1 << pflag)) {    // bit mask
                switch(pflag) {
                    case IEEE80211_RADIOTAP_TSFT:
                        flag_ptr += 8; // uint64 mactimestamp length 8
                        break;
                    case IEEE80211_RADIOTAP_FLAGS:
                        flag_ptr++; // uint8 flag
                        break;
                    case IEEE80211_RADIOTAP_RATE:
                        data_rate = *(uint8_t *)flag_ptr / 2; // Data_rate : 1.0 Mb/s -> 0x02 고정이라 /2 로 1 을 표현
                        flag_ptr++; // uint8
                        break;
                    case IEEE80211_RADIOTAP_CHANNEL:
                        flag_ptr += 4; // uint16 frequency, uint16 flags
                        break;
                    case IEEE80211_RADIOTAP_FHSS:
                        flag_ptr += 2; // uint8 hop set, uint8 hop pattern
                        break;
                    case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
                        pwr = *(char *)flag_ptr; // 신호 세기
                        flag_ptr++; // s8
                        break;
                    default:
                        break;
                }
            }
        }
 

// -------------------------------------IEEE 802.11 -> beacon frame-------------------------------------------------------- //

        // beacon frame flag
        if (dot11->frame_control_type == 0x00 && dot11->frame_control_subtype == 0x08) { 
            // control_type 하위로부터 3,4 번째비트와 subtype 상위 4비트
            for (flag = 0, i = 0; i < b_cnt; i++) {
                pk_beacon = b_data + i;

                // beacon_frame 에서 bssid 존재
                if (!memcmp(pk_beacon->BSSID, dot11->bssid_addr, sizeof(pk_beacon->BSSID))) { // 일치 시 flag, beacon 증가
                    flag = 1;
                    pk_beacon->PWR = pwr; 
                    pk_beacon->BEACONS++; 
                    break;
                }
            }

            // 초기
            if (!flag) {
                // BSSID 존재할 때
                pk_beacon = b_data + b_cnt;
                memcpy(pk_beacon->BSSID, dot11->bssid_addr, sizeof(pk_beacon->BSSID));
 
                pk_beacon->PWR = pwr; // 앞서 radiotap으로 계산했던 PWR 신호 세기 
                pk_beacon->BEACONS = 1;
                pk_beacon->DATA = 0;
                pk_beacon->DPPS = 0;

                fixed = (f_param *)((u_char *)dot11 + sizeof(dot11_header)); // fixed parameter 들어가기 전 위치
                tagged = (t_param *)((u_char *)fixed + sizeof(f_param)); // tagged parameter 들어가기 전 위치

                if (fixed->capabilities_privacy == 0) { // WEP를 support하는 AP/STA를 capabilities_privacy로 판단
                    strncpy(pk_beacon->ENC, "OPN", sizeof(pk_beacon->ENC)); // Open network
                }
                else if (fixed->capabilities_privacy == 1) {
                    strncpy(pk_beacon->ENC, "WEP", sizeof(pk_beacon->ENC)); // Encrypted
                    strncpy(pk_beacon->CIPHER, "WEP", sizeof(pk_beacon->ENC));
                }

                int qos= 0; 
                int is_wpa2 = 0; // wpa2 flag
                int tagged_size = 0;
                int MB = 0;
                int rsn_offset = 0;
                //int rsn_offset2 = 0;
                int vendor_offset = 0;

                // tagged parameter size 계산
                tagged_size = header->caplen - radiotap->length - sizeof(dot11_header) - sizeof(f_param); // 초기 값

                while (tagged_size > 0) { // tagged size가 존재할 때 => tagged parameter 값이 있을 때 반복
                    tag_data = (u_char *)tagged + sizeof(t_param);
                    switch(tagged->tag_number) { // tag_Number로 쉽게 case 구분
                        case 0x00:    // SSID
                            if (*(uint8_t *)tag_data != 0x00 && tagged->tag_length != 0) {
                                strncpy(pk_beacon->ESSID, tag_data, tagged->tag_length);
                                //strncpy(pk_probe->PROBE, pk_beacon->ESSID, tagged->tag_length);
                            }
                            else {
                                snprintf(pk_beacon->ESSID, sizeof(pk_beacon->ESSID), "<length:%3d>", tagged->tag_length);
                            }
                            break;

                        case 0x03:    // Channel 계산
                            pk_beacon->CH = *(uint8_t *)(tag_data);
                            break;

                        case 0x30:    // RSN 존재시 WPA2 성립
                            is_wpa2 = 1;
                            strncpy(pk_beacon->ENC, "WPA2", 5);

                            //rsn_offset2 += 2 + *(uint16_t *)(tag_data + rsn_offset2) * 4;

                            

                            // cipher suite offset
                            rsn_offset = 5;

                            rsn_offset += 2 + *(uint16_t *)(tag_data + rsn_offset + 1) * 4; // pairwise cipher suite type 판별

                            switch (*(uint8_t *)(tag_data + rsn_offset)) {    // unicase는 고려 x
                                case 0x01:    
                                    strncpy(pk_beacon->CIPHER, "WEP", 4); // WEP 40
                                    break;
                                case 0x02:
                                    strncpy(pk_beacon->CIPHER, "TKIP", 5);
                                    break;
                                case 0x03:
                                    strncpy(pk_beacon->CIPHER, "WARP", 5);
                                    break;
                                case 0x04:
                                    strncpy(pk_beacon->CIPHER, "CCMP", 5); // AES - CCM
                                    break;
                                case 0x05:    
                                    strncpy(pk_beacon->CIPHER, "WEP", 7); // WEP104
                                    break;
                                default:
                                    strncpy(pk_beacon->CIPHER, " ", 2);
                                    break;
                            }

                            // auth key management offset
                            rsn_offset += 2 + *(uint16_t *)(tag_data + rsn_offset + 1) * 4;
                            switch(*(uint8_t *)(tag_data + rsn_offset)) {    // auth key type 판별
                                case 0x01:
                                    strncpy(pk_beacon->AUTH, "MGT", 4); 
                                    break;
                                case 0x02:
                                    strncpy(pk_beacon->AUTH, "PSK", 4); // PSK
                                    break;
                                case 0x04:
                                    strncpy(pk_beacon->AUTH, "PSK", 4); // FT using PSK -> 0x04
                                    break;
                                case 0x08:
                                    strncpy(pk_beacon->AUTH, "SAE", 4); // WPA3 SAE
                                    strncpy(pk_beacon->ENC, "WPA3", 5); // SAE 사용 시 ENC도 WPA3으로 변경
                                    break;
                                case 0x0d:
                                    strncpy(pk_beacon->AUTH, "CMAC", 5);
                                    break;
                                default:
                                    strncpy(pk_beacon->AUTH, " ", 2); 
                                    break;
                            }
                            break;

                        case 0x32:    // Extended Supported Rates, 최대 MB 계산
                            MB = (MB < *(uint8_t *)(tag_data + tagged->tag_length - 1)/2) 
                            ? *(uint8_t *)(tag_data + tagged->tag_length - 1)/2 : MB;
                            break;

                        case 0xDD:    // Vendor Specific
                            vendor_offset = 3;

                            // 00 50 F2 : MS corp
                            // 02 01 01 : OUI type WMM/WME(0x02), Parameter Element(0x01), WME version(0x01)
                            if (*(uint8_t *)(tag_data + vendor_offset) == 2 && 
                            !memcmp(tag_data, "\x00\x50\xF2\x02\x01\x01", 6)) {
                                
                                /* U_APSD : 0x80 -> QoS를 지원하는 APSD
                                if (*(uint8_t *)(tag_data + vendor_offset + 1) == 0x80) {
                                    qos = 1;
                                }
                                */
                                qos = 1;
                            }

                            // 01 01 00 : WPA Information Element(0x01), WPA version 1(0x01, 0x00)
                            if (*(uint8_t *)(tag_data + vendor_offset) == 1 && 
                            !memcmp(tag_data, "\x00\x50\xF2\x01\x01\x00", 6) && !is_wpa2) { 
                                strncpy(pk_beacon->ENC, "WPA", 4);
                            }
                            break;

                        deault:
                            break;
                    }

                    
		            tagged_size -= sizeof(t_param) + tagged->tag_length; // tag_length만 계산
		            tagged = (t_param *)(tag_data + tagged->tag_length); 
                }

                // MB write, qos 값 존재시 "e" 함께 write, preamble 존재시 "." write
                // 54 above는 preamble로 "."로 indicate
                snprintf(pk_beacon->MB, sizeof(pk_beacon->MB), "%2d%1s%1s", MB, qos ? "e" : "", fixed->capabilities_short_preamble ? "." : "");

                b_cnt++; 
                print_result(b_cnt, p_req_cnt, p_res_cnt, b_data, p_req_data, p_res_data);
            }
        }

// -------------------------------------IEEE 802.11 -> Data-------------------------------------------------------- //

        // data#,
        if (dot11->frame_control_type == 0x02) { // 0x02 : data
            uint8_t to_ds = 0; // STA -> DS : to_ds
            uint8_t from_ds = 0; // DS -> STA : from_ds
            
            for (uint8_t pflag = 0; pflag < 8; pflag++) {
                if (dot11->flags & (1 << pflag)) {    // bit mask
                    switch (pflag) {
                        case TO_DS: // Frame from STA to a DS via an AP(To DS: 1, From DS: 0)
                            to_ds = 1; 
                            break;
                        case FROM_DS: // Frame from DS to a STA via AP(To DS: 0, From DS: 1)
                            from_ds = 1;
                            break;
                        default: // Not leaving DS or network is operating in AD-HOC mode(To DS: 0, From DS: 0)
                            break;
                    }
                }
            }

            // BSSID 존재 시 pwr, DATA
            for (i = 0; i < b_cnt; i++) {
                pk_beacon = b_data + i;

                if (!memcmp(pk_beacon->BSSID, dot11->bssid_addr, sizeof(pk_beacon->BSSID))) {
                    pk_beacon->PWR = pwr;
                    pk_beacon->DATA++;
                }
            }

            //dest_addr이 broadcast 상태가 아닐 때
            if (memcmp(dot11->destination_addr, "\xFF\xFF\xFF\xFF\xFF\xFF", sizeof(pk_probe->STATION))) {
                // from_ds == 1 -> STA
                if (from_ds == 1) {
                    //rate_qos(r_flag, data_rate)
                    for (i = 0; i < p_res_cnt; i++) {
                        pk_probe = p_res_data + i;
                        pk_probe->STATION_RATE = data_rate; // 

                        // // 0x20 : data, 0x28 : Qos_data 이므로 subtype이 0x08로 설정되어있으면 Qos_data
                        if (dot11->frame_control_subtype == 0x08) { 

                            // network QOS가 설정되면, enabled 상태가 되서 출력시 e를 display해주기 위해 값 저장
                            pk_probe->STATION_QOS = 1; 
                        }

                        write_rate(); // rate에 qos - preamble write
                    }
                        
                }

                // to_ds == 1 -> AP
                if (to_ds == 1) {
                    //rate_qos(r_flag, data_rate)
                    for (i = 0; i < p_req_cnt; i++) {
                        pk_probe = p_req_data + i;

                        // BSSID 가 동일하다면 AP_rate 설정
                        if (!memcmp(pk_probe->BSSID, dot11->bssid_addr, sizeof(pk_probe->BSSID))) {
                        pk_probe->AP_RATE = data_rate;

                        // beacon frame 일 때
                        if (dot11->frame_control_subtype == 0x08) {
                            // network QOS가 설정되면, enabled 상태가 되서 출력시 e를 display해주기 위해 값 저장
                            pk_probe->AP_QOS = 1; // null function(no data)를 제외하고 Qos Data 이므로 AP_QOS = 값 설정
                        }

                        write_rate(); // rate에 qos - preamble write

                        }
                    }
                }
            } 
        }

// -------------------------------------IEEE 802.11 -> Probe frame-------------------------------------------------------- //
        // probe request flag
        if (dot11->frame_control_type == 0x00 && dot11->frame_control_subtype == 0x04) {
            /*
            if (!memcmp(pk_probe->BSSID, "\xFF\xFF\xFF\xFF\xFF\xFF", sizeof(pk_probe->BSSID))) {
                tag_data = (u_char *)tagged + sizeof(t_param);
                if (*(uint8_t *)tag_data != 0x00 && tagged->tag_length != 0) {
                strncpy(pk_probe->PROBE, tag_data, tagged->tag_length); // Probe ESSID 
                }
            }
            */
            
            
            // 존재
            for (flag = 0, i = 0; i < p_req_cnt; i++) {
                pk_probe = p_req_data + i;
                
                // request 시에 transmitter address = source address 존재
                if (!memcmp(pk_probe->STATION, dot11->source_addr, sizeof(pk_probe->STATION))) { 
                    // 있다면 pwr mapping, frames 증가
                    flag = 1;
                    pk_probe->PWR = pwr;
                    pk_probe->FRAMES++;

                    write_rate(); // rate에 qos - preamble write

                    break;
                }
            }

            // 초기
            if (!flag) {

                pk_probe = p_req_data + p_req_cnt;
                memcpy(pk_probe->STATION, dot11->source_addr, sizeof(pk_probe->STATION));

                // 없다면 pwr mapping, FRAMES 1
                pk_probe->PWR = pwr;
                pk_probe->FRAMES = 1;
                pk_probe->LOST = 0;
                
                write_rate(); // rate에 qos - preamble write

                p_req_cnt++;
                print_result(b_cnt, p_req_cnt, p_res_cnt, b_data, p_req_data, p_res_data);
            }
        }

        // probe response flag
        if (dot11->frame_control_type == 0x00 && dot11->frame_control_subtype == 0x05) {
            for (flag = 0, i = 0; i < p_res_cnt; i++) {

                pk_probe = p_res_data + i;

                // response 시에는 BSSID도 존재, receiver == destination addr도 존재
                if (!memcmp(pk_probe->BSSID, dot11->bssid_addr, sizeof(pk_probe->BSSID))
                && !memcmp(pk_probe->STATION, dot11->destination_addr, sizeof(pk_probe->STATION))) {

                    // 있다면 pwr mapping, frames 증가
                    flag = 1;
                    pk_probe->PWR = pwr;
                    pk_probe->FRAMES++;

                    write_rate(); // rate에 qos - preamble write
                
                    break;
                }
            }

            // 초기
            if (!flag) {

                pk_probe = p_res_data + p_res_cnt;

                memcpy(pk_probe->BSSID, dot11->bssid_addr, sizeof(pk_probe->BSSID));
                memcpy(pk_probe->STATION, dot11->destination_addr, sizeof(pk_probe->STATION));

                // 없다면 pwr mapping, Frames 1
                pk_probe->PWR = pwr;
                pk_probe->FRAMES = 1;
                pk_probe->LOST = 0;

                write_rate(); // rate에 qos - preamble write

                p_res_cnt++;
                print_result(b_cnt, p_req_cnt, p_res_cnt, b_data, p_req_data, p_res_data);
            }
        }  
    }
    pcap_close(pcap);
    return 0;
}
