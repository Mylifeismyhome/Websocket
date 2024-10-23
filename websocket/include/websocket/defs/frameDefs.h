#pragma once

#ifdef __cplusplus
extern "C" {
#endif

enum class e_ws_frame_status : unsigned char
{
    status_ok = 0x0, /**< Status indicates all is OK */
    status_error = 0x1, /**< Status indicates an error occurred */
    status_incomplete = 0x2, /**< Status indicates message is waiting for more information */
    status_fragment = 0x3, /**< Status indicates a message fragment was processed */
    status_final = 0x4 /**< Status indicates the message is final */
};

enum e_ws_frame_opcode : unsigned char
{
    opcode_continuation = 0x0,
    opcode_text = 0x1,
    opcode_binary = 0x2,
    opcode_rsv1_further_non_controll = 0x3,
    opcode_rsv2_further_non_controll = 0x4,
    opcode_rsv3_further_non_controll = 0x5,
    opcode_rsv4_further_non_controll = 0x6,
    opcode_rsv5_further_non_controll = 0x7,
    opcode_close = 0x8,
    opcode_ping = 0x9,
    opcode_pong = 0xA,
    opcode_rsv1_further_controll = 0xB,
    opcode_rsv2_further_controll = 0xC,
    opcode_rsv3_further_controll = 0xD,
    opcode_rsv4_further_controll = 0xE,
    opcode_rsv5_further_controll = 0xF
};

#ifdef __cplusplus
}
#endif
