
/*
 * Copyright (c) 2024, Qualcomm Innovation Center, Inc. All rights reserved.
 * SPDX-License-Identifier: ISC
 */

 

 
 
 
 
 
 
 
 


#ifndef _PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_H_
#define _PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_H_
#if !defined(__ASSEMBLER__)
#endif

#define NUM_OF_DWORDS_PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS 66

#define NUM_OF_QWORDS_PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS 33


struct phyrx_other_receive_info_evm_details {
#ifndef WIFI_BIT_ORDER_BIG_ENDIAN
             uint32_t number_of_data_sym                                      : 16,  
                      number_of_streams                                       :  8,  
                      number_of_pilots                                        :  8;  
             uint32_t acc_linear_evm_0_0                                      : 32;  
             uint32_t acc_linear_evm_1_0                                      : 32;  
             uint32_t acc_linear_evm_0_1                                      : 32;  
             uint32_t acc_linear_evm_1_1                                      : 32;  
             uint32_t acc_linear_evm_0_2                                      : 32;  
             uint32_t acc_linear_evm_1_2                                      : 32;  
             uint32_t acc_linear_evm_0_3                                      : 32;  
             uint32_t acc_linear_evm_1_3                                      : 32;  
             uint32_t acc_linear_evm_0_4                                      : 32;  
             uint32_t acc_linear_evm_1_4                                      : 32;  
             uint32_t acc_linear_evm_0_5                                      : 32;  
             uint32_t acc_linear_evm_1_5                                      : 32;  
             uint32_t acc_linear_evm_0_6                                      : 32;  
             uint32_t acc_linear_evm_1_6                                      : 32;  
             uint32_t acc_linear_evm_0_7                                      : 32;  
             uint32_t acc_linear_evm_1_7                                      : 32;  
             uint32_t acc_linear_evm_0_8                                      : 32;  
             uint32_t acc_linear_evm_1_8                                      : 32;  
             uint32_t acc_linear_evm_0_9                                      : 32;  
             uint32_t acc_linear_evm_1_9                                      : 32;  
             uint32_t acc_linear_evm_0_10                                     : 32;  
             uint32_t acc_linear_evm_1_10                                     : 32;  
             uint32_t acc_linear_evm_0_11                                     : 32;  
             uint32_t acc_linear_evm_1_11                                     : 32;  
             uint32_t acc_linear_evm_0_12                                     : 32;  
             uint32_t acc_linear_evm_1_12                                     : 32;  
             uint32_t acc_linear_evm_0_13                                     : 32;  
             uint32_t acc_linear_evm_1_13                                     : 32;  
             uint32_t acc_linear_evm_0_14                                     : 32;  
             uint32_t acc_linear_evm_1_14                                     : 32;  
             uint32_t acc_linear_evm_0_15                                     : 32;  
             uint32_t acc_linear_evm_1_15                                     : 32;  
             uint32_t acc_linear_evm_0_16                                     : 32;  
             uint32_t acc_linear_evm_1_16                                     : 32;  
             uint32_t acc_linear_evm_0_17                                     : 32;  
             uint32_t acc_linear_evm_1_17                                     : 32;  
             uint32_t acc_linear_evm_0_18                                     : 32;  
             uint32_t acc_linear_evm_1_18                                     : 32;  
             uint32_t acc_linear_evm_0_19                                     : 32;  
             uint32_t acc_linear_evm_1_19                                     : 32;  
             uint32_t acc_linear_evm_0_20                                     : 32;  
             uint32_t acc_linear_evm_1_20                                     : 32;  
             uint32_t acc_linear_evm_0_21                                     : 32;  
             uint32_t acc_linear_evm_1_21                                     : 32;  
             uint32_t acc_linear_evm_0_22                                     : 32;  
             uint32_t acc_linear_evm_1_22                                     : 32;  
             uint32_t acc_linear_evm_0_23                                     : 32;  
             uint32_t acc_linear_evm_1_23                                     : 32;  
             uint32_t acc_linear_evm_0_24                                     : 32;  
             uint32_t acc_linear_evm_1_24                                     : 32;  
             uint32_t acc_linear_evm_0_25                                     : 32;  
             uint32_t acc_linear_evm_1_25                                     : 32;  
             uint32_t acc_linear_evm_0_26                                     : 32;  
             uint32_t acc_linear_evm_1_26                                     : 32;  
             uint32_t acc_linear_evm_0_27                                     : 32;  
             uint32_t acc_linear_evm_1_27                                     : 32;  
             uint32_t acc_linear_evm_0_28                                     : 32;  
             uint32_t acc_linear_evm_1_28                                     : 32;  
             uint32_t acc_linear_evm_0_29                                     : 32;  
             uint32_t acc_linear_evm_1_29                                     : 32;  
             uint32_t acc_linear_evm_0_30                                     : 32;  
             uint32_t acc_linear_evm_1_30                                     : 32;  
             uint32_t acc_linear_evm_0_31                                     : 32;  
             uint32_t acc_linear_evm_1_31                                     : 32;  
             uint32_t tlv64_padding                                           : 32;  
#else
             uint32_t number_of_pilots                                        :  8,  
                      number_of_streams                                       :  8,  
                      number_of_data_sym                                      : 16;  
             uint32_t acc_linear_evm_0_0                                      : 32;  
             uint32_t acc_linear_evm_1_0                                      : 32;  
             uint32_t acc_linear_evm_0_1                                      : 32;  
             uint32_t acc_linear_evm_1_1                                      : 32;  
             uint32_t acc_linear_evm_0_2                                      : 32;  
             uint32_t acc_linear_evm_1_2                                      : 32;  
             uint32_t acc_linear_evm_0_3                                      : 32;  
             uint32_t acc_linear_evm_1_3                                      : 32;  
             uint32_t acc_linear_evm_0_4                                      : 32;  
             uint32_t acc_linear_evm_1_4                                      : 32;  
             uint32_t acc_linear_evm_0_5                                      : 32;  
             uint32_t acc_linear_evm_1_5                                      : 32;  
             uint32_t acc_linear_evm_0_6                                      : 32;  
             uint32_t acc_linear_evm_1_6                                      : 32;  
             uint32_t acc_linear_evm_0_7                                      : 32;  
             uint32_t acc_linear_evm_1_7                                      : 32;  
             uint32_t acc_linear_evm_0_8                                      : 32;  
             uint32_t acc_linear_evm_1_8                                      : 32;  
             uint32_t acc_linear_evm_0_9                                      : 32;  
             uint32_t acc_linear_evm_1_9                                      : 32;  
             uint32_t acc_linear_evm_0_10                                     : 32;  
             uint32_t acc_linear_evm_1_10                                     : 32;  
             uint32_t acc_linear_evm_0_11                                     : 32;  
             uint32_t acc_linear_evm_1_11                                     : 32;  
             uint32_t acc_linear_evm_0_12                                     : 32;  
             uint32_t acc_linear_evm_1_12                                     : 32;  
             uint32_t acc_linear_evm_0_13                                     : 32;  
             uint32_t acc_linear_evm_1_13                                     : 32;  
             uint32_t acc_linear_evm_0_14                                     : 32;  
             uint32_t acc_linear_evm_1_14                                     : 32;  
             uint32_t acc_linear_evm_0_15                                     : 32;  
             uint32_t acc_linear_evm_1_15                                     : 32;  
             uint32_t acc_linear_evm_0_16                                     : 32;  
             uint32_t acc_linear_evm_1_16                                     : 32;  
             uint32_t acc_linear_evm_0_17                                     : 32;  
             uint32_t acc_linear_evm_1_17                                     : 32;  
             uint32_t acc_linear_evm_0_18                                     : 32;  
             uint32_t acc_linear_evm_1_18                                     : 32;  
             uint32_t acc_linear_evm_0_19                                     : 32;  
             uint32_t acc_linear_evm_1_19                                     : 32;  
             uint32_t acc_linear_evm_0_20                                     : 32;  
             uint32_t acc_linear_evm_1_20                                     : 32;  
             uint32_t acc_linear_evm_0_21                                     : 32;  
             uint32_t acc_linear_evm_1_21                                     : 32;  
             uint32_t acc_linear_evm_0_22                                     : 32;  
             uint32_t acc_linear_evm_1_22                                     : 32;  
             uint32_t acc_linear_evm_0_23                                     : 32;  
             uint32_t acc_linear_evm_1_23                                     : 32;  
             uint32_t acc_linear_evm_0_24                                     : 32;  
             uint32_t acc_linear_evm_1_24                                     : 32;  
             uint32_t acc_linear_evm_0_25                                     : 32;  
             uint32_t acc_linear_evm_1_25                                     : 32;  
             uint32_t acc_linear_evm_0_26                                     : 32;  
             uint32_t acc_linear_evm_1_26                                     : 32;  
             uint32_t acc_linear_evm_0_27                                     : 32;  
             uint32_t acc_linear_evm_1_27                                     : 32;  
             uint32_t acc_linear_evm_0_28                                     : 32;  
             uint32_t acc_linear_evm_1_28                                     : 32;  
             uint32_t acc_linear_evm_0_29                                     : 32;  
             uint32_t acc_linear_evm_1_29                                     : 32;  
             uint32_t acc_linear_evm_0_30                                     : 32;  
             uint32_t acc_linear_evm_1_30                                     : 32;  
             uint32_t acc_linear_evm_0_31                                     : 32;  
             uint32_t acc_linear_evm_1_31                                     : 32;  
             uint32_t tlv64_padding                                           : 32;  
#endif
};


 

#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_NUMBER_OF_DATA_SYM_OFFSET              0x0000000000000000
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_NUMBER_OF_DATA_SYM_LSB                 0
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_NUMBER_OF_DATA_SYM_MSB                 15
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_NUMBER_OF_DATA_SYM_MASK                0x000000000000ffff


 

#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_NUMBER_OF_STREAMS_OFFSET               0x0000000000000000
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_NUMBER_OF_STREAMS_LSB                  16
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_NUMBER_OF_STREAMS_MSB                  23
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_NUMBER_OF_STREAMS_MASK                 0x0000000000ff0000


 

#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_NUMBER_OF_PILOTS_OFFSET                0x0000000000000000
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_NUMBER_OF_PILOTS_LSB                   24
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_NUMBER_OF_PILOTS_MSB                   31
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_NUMBER_OF_PILOTS_MASK                  0x00000000ff000000


 

#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_0_OFFSET              0x0000000000000000
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_0_LSB                 32
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_0_MSB                 63
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_0_MASK                0xffffffff00000000


 

#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_0_OFFSET              0x0000000000000008
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_0_LSB                 0
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_0_MSB                 31
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_0_MASK                0x00000000ffffffff


 

#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_1_OFFSET              0x0000000000000008
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_1_LSB                 32
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_1_MSB                 63
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_1_MASK                0xffffffff00000000


 

#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_1_OFFSET              0x0000000000000010
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_1_LSB                 0
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_1_MSB                 31
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_1_MASK                0x00000000ffffffff


 

#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_2_OFFSET              0x0000000000000010
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_2_LSB                 32
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_2_MSB                 63
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_2_MASK                0xffffffff00000000


 

#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_2_OFFSET              0x0000000000000018
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_2_LSB                 0
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_2_MSB                 31
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_2_MASK                0x00000000ffffffff


 

#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_3_OFFSET              0x0000000000000018
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_3_LSB                 32
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_3_MSB                 63
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_3_MASK                0xffffffff00000000


 

#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_3_OFFSET              0x0000000000000020
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_3_LSB                 0
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_3_MSB                 31
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_3_MASK                0x00000000ffffffff


 

#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_4_OFFSET              0x0000000000000020
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_4_LSB                 32
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_4_MSB                 63
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_4_MASK                0xffffffff00000000


 

#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_4_OFFSET              0x0000000000000028
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_4_LSB                 0
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_4_MSB                 31
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_4_MASK                0x00000000ffffffff


 

#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_5_OFFSET              0x0000000000000028
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_5_LSB                 32
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_5_MSB                 63
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_5_MASK                0xffffffff00000000


 

#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_5_OFFSET              0x0000000000000030
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_5_LSB                 0
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_5_MSB                 31
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_5_MASK                0x00000000ffffffff


 

#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_6_OFFSET              0x0000000000000030
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_6_LSB                 32
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_6_MSB                 63
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_6_MASK                0xffffffff00000000


 

#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_6_OFFSET              0x0000000000000038
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_6_LSB                 0
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_6_MSB                 31
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_6_MASK                0x00000000ffffffff


 

#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_7_OFFSET              0x0000000000000038
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_7_LSB                 32
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_7_MSB                 63
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_7_MASK                0xffffffff00000000


 

#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_7_OFFSET              0x0000000000000040
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_7_LSB                 0
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_7_MSB                 31
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_7_MASK                0x00000000ffffffff


 

#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_8_OFFSET              0x0000000000000040
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_8_LSB                 32
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_8_MSB                 63
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_8_MASK                0xffffffff00000000


 

#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_8_OFFSET              0x0000000000000048
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_8_LSB                 0
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_8_MSB                 31
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_8_MASK                0x00000000ffffffff


 

#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_9_OFFSET              0x0000000000000048
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_9_LSB                 32
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_9_MSB                 63
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_9_MASK                0xffffffff00000000


 

#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_9_OFFSET              0x0000000000000050
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_9_LSB                 0
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_9_MSB                 31
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_9_MASK                0x00000000ffffffff


 

#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_10_OFFSET             0x0000000000000050
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_10_LSB                32
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_10_MSB                63
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_10_MASK               0xffffffff00000000


 

#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_10_OFFSET             0x0000000000000058
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_10_LSB                0
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_10_MSB                31
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_10_MASK               0x00000000ffffffff


 

#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_11_OFFSET             0x0000000000000058
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_11_LSB                32
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_11_MSB                63
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_11_MASK               0xffffffff00000000


 

#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_11_OFFSET             0x0000000000000060
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_11_LSB                0
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_11_MSB                31
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_11_MASK               0x00000000ffffffff


 

#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_12_OFFSET             0x0000000000000060
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_12_LSB                32
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_12_MSB                63
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_12_MASK               0xffffffff00000000


 

#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_12_OFFSET             0x0000000000000068
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_12_LSB                0
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_12_MSB                31
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_12_MASK               0x00000000ffffffff


 

#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_13_OFFSET             0x0000000000000068
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_13_LSB                32
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_13_MSB                63
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_13_MASK               0xffffffff00000000


 

#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_13_OFFSET             0x0000000000000070
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_13_LSB                0
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_13_MSB                31
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_13_MASK               0x00000000ffffffff


 

#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_14_OFFSET             0x0000000000000070
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_14_LSB                32
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_14_MSB                63
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_14_MASK               0xffffffff00000000


 

#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_14_OFFSET             0x0000000000000078
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_14_LSB                0
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_14_MSB                31
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_14_MASK               0x00000000ffffffff


 

#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_15_OFFSET             0x0000000000000078
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_15_LSB                32
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_15_MSB                63
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_15_MASK               0xffffffff00000000


 

#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_15_OFFSET             0x0000000000000080
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_15_LSB                0
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_15_MSB                31
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_15_MASK               0x00000000ffffffff


 

#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_16_OFFSET             0x0000000000000080
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_16_LSB                32
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_16_MSB                63
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_16_MASK               0xffffffff00000000


 

#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_16_OFFSET             0x0000000000000088
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_16_LSB                0
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_16_MSB                31
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_16_MASK               0x00000000ffffffff


 

#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_17_OFFSET             0x0000000000000088
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_17_LSB                32
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_17_MSB                63
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_17_MASK               0xffffffff00000000


 

#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_17_OFFSET             0x0000000000000090
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_17_LSB                0
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_17_MSB                31
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_17_MASK               0x00000000ffffffff


 

#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_18_OFFSET             0x0000000000000090
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_18_LSB                32
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_18_MSB                63
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_18_MASK               0xffffffff00000000


 

#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_18_OFFSET             0x0000000000000098
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_18_LSB                0
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_18_MSB                31
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_18_MASK               0x00000000ffffffff


 

#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_19_OFFSET             0x0000000000000098
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_19_LSB                32
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_19_MSB                63
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_19_MASK               0xffffffff00000000


 

#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_19_OFFSET             0x00000000000000a0
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_19_LSB                0
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_19_MSB                31
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_19_MASK               0x00000000ffffffff


 

#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_20_OFFSET             0x00000000000000a0
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_20_LSB                32
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_20_MSB                63
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_20_MASK               0xffffffff00000000


 

#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_20_OFFSET             0x00000000000000a8
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_20_LSB                0
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_20_MSB                31
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_20_MASK               0x00000000ffffffff


 

#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_21_OFFSET             0x00000000000000a8
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_21_LSB                32
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_21_MSB                63
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_21_MASK               0xffffffff00000000


 

#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_21_OFFSET             0x00000000000000b0
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_21_LSB                0
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_21_MSB                31
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_21_MASK               0x00000000ffffffff


 

#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_22_OFFSET             0x00000000000000b0
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_22_LSB                32
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_22_MSB                63
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_22_MASK               0xffffffff00000000


 

#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_22_OFFSET             0x00000000000000b8
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_22_LSB                0
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_22_MSB                31
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_22_MASK               0x00000000ffffffff


 

#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_23_OFFSET             0x00000000000000b8
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_23_LSB                32
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_23_MSB                63
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_23_MASK               0xffffffff00000000


 

#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_23_OFFSET             0x00000000000000c0
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_23_LSB                0
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_23_MSB                31
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_23_MASK               0x00000000ffffffff


 

#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_24_OFFSET             0x00000000000000c0
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_24_LSB                32
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_24_MSB                63
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_24_MASK               0xffffffff00000000


 

#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_24_OFFSET             0x00000000000000c8
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_24_LSB                0
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_24_MSB                31
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_24_MASK               0x00000000ffffffff


 

#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_25_OFFSET             0x00000000000000c8
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_25_LSB                32
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_25_MSB                63
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_25_MASK               0xffffffff00000000


 

#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_25_OFFSET             0x00000000000000d0
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_25_LSB                0
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_25_MSB                31
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_25_MASK               0x00000000ffffffff


 

#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_26_OFFSET             0x00000000000000d0
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_26_LSB                32
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_26_MSB                63
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_26_MASK               0xffffffff00000000


 

#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_26_OFFSET             0x00000000000000d8
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_26_LSB                0
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_26_MSB                31
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_26_MASK               0x00000000ffffffff


 

#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_27_OFFSET             0x00000000000000d8
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_27_LSB                32
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_27_MSB                63
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_27_MASK               0xffffffff00000000


 

#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_27_OFFSET             0x00000000000000e0
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_27_LSB                0
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_27_MSB                31
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_27_MASK               0x00000000ffffffff


 

#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_28_OFFSET             0x00000000000000e0
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_28_LSB                32
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_28_MSB                63
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_28_MASK               0xffffffff00000000


 

#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_28_OFFSET             0x00000000000000e8
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_28_LSB                0
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_28_MSB                31
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_28_MASK               0x00000000ffffffff


 

#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_29_OFFSET             0x00000000000000e8
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_29_LSB                32
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_29_MSB                63
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_29_MASK               0xffffffff00000000


 

#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_29_OFFSET             0x00000000000000f0
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_29_LSB                0
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_29_MSB                31
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_29_MASK               0x00000000ffffffff


 

#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_30_OFFSET             0x00000000000000f0
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_30_LSB                32
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_30_MSB                63
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_30_MASK               0xffffffff00000000


 

#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_30_OFFSET             0x00000000000000f8
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_30_LSB                0
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_30_MSB                31
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_30_MASK               0x00000000ffffffff


 

#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_31_OFFSET             0x00000000000000f8
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_31_LSB                32
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_31_MSB                63
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_0_31_MASK               0xffffffff00000000


 

#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_31_OFFSET             0x0000000000000100
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_31_LSB                0
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_31_MSB                31
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_ACC_LINEAR_EVM_1_31_MASK               0x00000000ffffffff


 

#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_TLV64_PADDING_OFFSET                   0x0000000000000100
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_TLV64_PADDING_LSB                      32
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_TLV64_PADDING_MSB                      63
#define PHYRX_OTHER_RECEIVE_INFO_EVM_DETAILS_TLV64_PADDING_MASK                     0xffffffff00000000



#endif    
