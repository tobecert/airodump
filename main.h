#ifndef _AIRODUMP_NG_H
#define _AIRODUMP_NG_H

#include <stdint.h>

#pragma pack(push, 1)

// http://www.radiotap.org/

typedef struct _radiotap_header {
    uint8_t version;
    uint8_t pad;
    uint16_t length;
    uint32_t present_flag;
    uint64_t mactimestamp;
    uint8_t flags;
    uint8_t data_rate;
    uint16_t channel_frequency;
    uint16_t channel_flags;
    uint8_t antenna_signal1;
    uint16_t RX_flags;
    uint8_t antenna_signal2;
    uint8_t antenna;
} radiotap_header;

// http://www.radiotap.org/fields/defined
// https://github.com/radiotap/radiotap-library/blob/master/radiotap.h

enum radiotap_presence_flag {
    IEEE80211_RADIOTAP_TSFT = 0,
    IEEE80211_RADIOTAP_FLAGS = 1,
    IEEE80211_RADIOTAP_RATE = 2,
    IEEE80211_RADIOTAP_CHANNEL = 3,
    IEEE80211_RADIOTAP_FHSS = 4,
    IEEE80211_RADIOTAP_DBM_ANTSIGNAL = 5,
    IEEE80211_RADIOTAP_DBM_ANTNOISE = 6,
    IEEE80211_RADIOTAP_LOCK_QUALITY = 7,
    IEEE80211_RADIOTAP_TX_ATTENUATION = 8,
    IEEE80211_RADIOTAP_DB_TX_ATTENUATION = 9,
    IEEE80211_RADIOTAP_DBM_TX_POWER = 10,
    IEEE80211_RADIOTAP_ANTENNA = 11,
    IEEE80211_RADIOTAP_DB_ANTSIGNAL = 12,
    IEEE80211_RADIOTAP_DB_ANTNOISE = 13,
    IEEE80211_RADIOTAP_RX_FLAGS = 14,
    IEEE80211_RADIOTAP_TX_FLAGS = 15,
    IEEE80211_RADIOTAP_RTS_RETRIES = 16,
    IEEE80211_RADIOTAP_DATA_RETRIES = 17,
    IEEE80211_RADIOTAP_MCS = 19,
    IEEE80211_RADIOTAP_AMPDU_STATUS = 20,
    IEEE80211_RADIOTAP_VHT = 21,
    IEEE80211_RADIOTAP_TIMESTAMP = 22,
    IEEE80211_RADIOTAP_RADIOTAP_NAMESPACE = 29,
    IEEE80211_RADIOTAP_VENDOR_NAMESPACE = 30,
    IEEE80211_RADIOTAP_EXT = 31
};

typedef struct _dot11_header {
    uint8_t frame_control_version : 2;
    uint8_t frame_control_type : 2;
    uint8_t frame_control_subtype : 4;
    uint8_t flags; 
    uint16_t duration;
    uint8_t destination_addr[6];
    uint8_t source_addr[6];
    uint8_t bssid_addr[6];
    uint16_t fragment_number : 4;
    uint16_t sequence_number : 12;
} dot11_header;

enum dot11_flags {
    TO_DS = 0,
    FROM_DS = 1,
    MORE_FRAGEMENTS = 2,
    RETRY = 3,
    PWR_MGT = 4,
    MORE_DATA = 5,
    PROTECTED_FLAG = 7,
    ORDER_FLAG = 8
};

typedef struct _fixed_parameter {
    uint64_t timestamp;
    uint16_t beacon_interval;
    uint16_t capabilities_ess : 1;
    uint16_t capabilities_ibss : 1;
    uint16_t capabilities_cfp : 2;
    uint16_t capabilities_privacy : 1;
    uint16_t capabilities_short_preamble : 1;
    uint16_t capabilities_pbcc : 1;
    uint16_t capabilities_channel_agility : 1;
    uint16_t capabilities_spectrum_management : 1;
    uint16_t capabiltiies_short_slot_time : 1;
    uint16_t capabilities_cfp2 : 1;
    uint16_t capabilities_automatic_power_save_delivery : 1;
    uint16_t capabilities_radio_measurement : 1;
    uint16_t capabilities_dsss_ofdm : 1;
    uint16_t capabilities_delayed_block_ack : 1;
    uint16_t capabilities_immediate_block_ack : 1;
} f_param;

typedef struct _tagged_parameter {
    uint8_t tag_number;
    uint8_t tag_length;
} t_param;

typedef struct _beacon_information {
    uint8_t BSSID[6];
    int PWR;
    int BEACONS;
    int DATA;
    uint8_t CH;
    char MB[5];
    int DPPS;
    char ENC[5];
    char CIPHER[5];
    char AUTH[5];
    char ESSID[50];
} b_info;

typedef struct _probe_information {
    uint8_t BSSID[6];
    uint8_t STATION[6];
    int PWR;
    char RATE[16];
    int LOST;
    int FRAMES;
    char PROBE[50];
    int AP_RATE;
    int AP_QOS;
    int STATION_RATE;
    int STATION_QOS;
} p_info;

#pragma pack(pop)

#endif