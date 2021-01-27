
#define __DA14531__ 1
#define CFG_UART_ONE_WIRE_SUPPORT 1

typedef int (*dummy_func)(char*);



struct rom_func_addr_table_struct
{
    dummy_func rf_init_func;
    dummy_func rf_reinit_func;
    dummy_func uart_init_func;
    dummy_func uart_flow_on_func;
    dummy_func uart_flow_off_func;
    dummy_func uart_finish_transfers_func;
    dummy_func uart_read_func;
    dummy_func one_wire_uart_write_func;

    dummy_func UART_Handler_func;
    dummy_func gtl_init_func;
    dummy_func gtl_eif_init_func;
    dummy_func gtl_eif_read_start_func;
    dummy_func gtl_eif_read_hdr_func;
    dummy_func gtl_eif_read_payl_func;
    dummy_func one_wire_uart_gtl_eif_tx_done_func;

    dummy_func gtl_eif_rx_done_func;
    dummy_func h4tl_init_func;
    dummy_func h4tl_read_start_func;
    dummy_func h4tl_read_hdr_func;
    dummy_func h4tl_read_payl_func;
    dummy_func h4tl_read_next_out_of_sync_func;
    dummy_func h4tl_out_of_sync_func;
    dummy_func one_wire_uart_h4tl_tx_done_func;
    dummy_func h4tl_rx_done_func;
    dummy_func ke_task_init_func;
    dummy_func ke_timer_init_func;
    dummy_func llm_encryption_done_func;
    dummy_func nvds_get_func;
    dummy_func nvds_put_func;
    dummy_func nvds_del_func;
    dummy_func nvds_init_func;
    dummy_func rwip_eif_get_func;

    dummy_func platform_reset_func;
    dummy_func  lld_sleep_compensate_func;
    dummy_func  lld_sleep_init_func;
    dummy_func  lld_sleep_us_2_lpcycles_sel_func;
    dummy_func  lld_sleep_lpcycles_2_us_sel_func;

    dummy_func lld_test_stop_func;
    dummy_func lld_test_mode_tx_func;
    dummy_func JT_lld_test_mode_rx_func;  // Rx window size set to 10ms in DA14531

    dummy_func smpc_check_param_func;
    dummy_func smpc_pdu_recv_func;

    dummy_func prf_init_func;
    dummy_func prf_add_profile_func;
    dummy_func prf_create_func;
    dummy_func prf_cleanup_func;

    dummy_func prf_get_id_from_task_func;
    dummy_func prf_get_task_from_id_func;


    dummy_func SetSystemVars_func; //SetSystemVars_func;

    dummy_func dbg_init_func_empty;
    dummy_func dbg_platform_reset_complete_func_empty;
    dummy_func hci_rd_local_supp_feats_cmd_handler_func;

    dummy_func l2cc_pdu_pack_func;
    dummy_func JT_l2cc_pdu_unpack_func;
    dummy_func l2c_send_lecb_message_func;
    dummy_func l2c_process_sdu_func;

    dummy_func JT_l2cc_pdu_recv_ind_handler_func;
    dummy_func gapc_lecb_connect_cfm_handler_func;
    dummy_func atts_l2cc_pdu_recv_handler_func;
    dummy_func attc_l2cc_pdu_recv_handler_func;

    dummy_func crypto_init_func;
    dummy_func llm_le_adv_report_ind_func;
    dummy_func PK_PointMult_func;
    dummy_func llm_p256_start_func;
    dummy_func llm_create_p256_key_func;
    dummy_func llm_p256_req_handler_func;
    dummy_func llc_le_length_effective_func;
    dummy_func llc_le_length_conn_init_func;
    dummy_func lld_data_tx_prog_func;
    dummy_func lld_data_tx_check_func;
    dummy_func llc_pdu_send_func;
    dummy_func llc_data_notif_func; //llc_data_notif_func;
    dummy_func dia_rand_func;
    dummy_func dia_srand_func;
    dummy_func ba431_get_rand_func;

    dummy_func smpc_public_key_exchange_start_func;
    dummy_func smpc_dhkey_calc_ind_func;
    dummy_func smpm_ecdh_key_create_func;
    dummy_func ble_init_arp_func;
    dummy_func unk_func_1;
    dummy_func unk_func_2;
    dummy_func unk_func_3;
    dummy_func unk_func_4;
    dummy_func unk_func_5;
    dummy_func unk_func_6;
    dummy_func unk_func_7;
    dummy_func unk_func_8;
    dummy_func unk_func_9;
    dummy_func unk_func_a;
    dummy_func unk_func_b;
    dummy_func unk_func_c;
    dummy_func unk_func_d;
    dummy_func unk_func_e;
    dummy_func unk_func_f;
    dummy_func unk_func_g;
};


 
/// Default Message handler code to handle several message type in same handler.
#define KE_MSG_DEFAULT_HANDLER  (0xFFFF)
/// Invalid task
#define KE_TASK_INVALID         (0xFFFF)
/// Used to know if a message is not present in kernel queue
#define KE_MSG_NOT_IN_QUEUE     ((struct co_list_hdr *) 0xFFFFFFFF)

/// Status of ke_task API functions
enum KE_TASK_STATUS
{
    KE_TASK_OK = 0,
    KE_TASK_FAIL,
    KE_TASK_UNKNOWN,
    KE_TASK_CAPA_EXCEEDED,
    KE_TASK_ALREADY_EXISTS,
};


typedef unsigned short uint16_t;
typedef unsigned char uint8_t;
typedef unsigned int uint32_t;

/// Task Identifier. Composed by the task type and the task index.
typedef uint16_t ke_task_id_t;

/// Builds the task identifier from the type and the index of that task.
#define KE_BUILD_ID(type, index) ( (ke_task_id_t)(((index) << 8)|(type)) )

/// Retrieves task type from task id.
#define KE_TYPE_GET(ke_task_id) ((ke_task_id) & 0xFF)

/// Retrieves task index number from task id.
#define KE_IDX_GET(ke_task_id) (((ke_task_id) >> 8) & 0xFF)

/// Task State
typedef uint8_t ke_state_t;

/// Message Identifier. The number of messages is limited to 0x100.
/// The message ID is divided in two parts:
/// - bits[15..8] : task index (no more than 256 tasks supported).
/// - bits[7..0] : message index (no more that 256 messages per task).
typedef uint16_t ke_msg_id_t;

/// Message structure.
struct ke_msg
{
    struct co_list_hdr hdr;     ///< List header for chaining
    uint32_t        saved;      ///< Message saved.
    ke_msg_id_t     id;         ///< Message id.
    ke_task_id_t    dest_id;    ///< Destination kernel identifier.
    ke_task_id_t    src_id;     ///< Source kernel identifier.
    uint16_t        param_len;  ///< Parameter embedded struct length.
    uint32_t        param[1];   ///< Parameter embedded struct. Must be word-aligned.
};


/// Build the first message ID of a task.
#define KE_FIRST_MSG(task) ((ke_msg_id_t)((task) << 8))
/// Retrieve the task Type from message
#define MSG_T(msg)         ((ke_task_id_t)((msg) >> 8))
/// Retrieve the task ID from message
#define MSG_I(msg)         ((msg) & ((1<<8)-1))

/// Format of a task message handler function
typedef int (*ke_msg_func_t)(ke_msg_id_t const msgid, void const *param,
                             ke_task_id_t const dest_id, ke_task_id_t const src_id);

/// Macro for message handler function declaration or definition
#define KE_MSG_HANDLER(module, fname)   static int module##_##fname##_handler(ke_msg_id_t const msgid,     \
                                                                              void const *param,           \
                                                                              ke_task_id_t const dest_id,  \
                                                                              ke_task_id_t const src_id)

/// Custom message handlers
struct custom_msg_handler 
{
    /// Id of the destination task. This is used because some messages have duplicate handlers like LLD_DATA_IND and LLD_STOP_IND.
    /// Only the type is taken into account and not the index for tasks that have multiple instances
    ke_task_id_t task_id;
    /// Id of the handled message. Can also be KE_MSG_DEFAULT_HANDLER to direct all messages to one handler for the particular task_id
    /// The search is top down so KE_MSG_DEFAULT_HANDLER should be after other handlers for specific messages for the particular task
    ke_msg_id_t id;
    /// Pointer to the handler function for the msgid above.
    ke_msg_func_t func;
};

/// Element of a message handler table.
struct ke_msg_handler
{
    /// Id of the handled message.
    ke_msg_id_t id;
    /// Pointer to the handler function for the msgid above.
    ke_msg_func_t func;
};

/// Element of a state handler table.
struct ke_state_handler
{
    /// Pointer to the message handler table of this state.
    const struct ke_msg_handler *msg_table;
    /// Number of messages handled in this state.
    uint16_t msg_cnt;
};

/// Helps writing the initialization of the state handlers without errors.
#define KE_STATE_HANDLER(hdl) {hdl, sizeof(hdl)/sizeof(struct ke_msg_handler)}

/// Helps writing empty states.
#define KE_STATE_HANDLER_NONE {NULL, 0}

/// Task descriptor grouping all information required by the kernel for the scheduling.
struct ke_task_desc
{
    /// Pointer to the state handler table (one element for each state).
    const struct ke_state_handler* state_handler;
    /// Pointer to the default state handler (element parsed after the current state).
    const struct ke_state_handler* default_handler;
    /// Pointer to the state table (one element for each instance).
    ke_state_t* state;
    /// Maximum number of states in the task.
    uint16_t state_max;
    /// Maximum index of supported instances of the task.
    uint16_t idx_max;
};

#define KE_MEM_RW 1
#define KE_PROFILING 1


/// Kernel memory heaps types.
enum
{
    /// Memory allocated for environment variables
    KE_MEM_ENV,
    /// Memory allocated for Attribute database
    KE_MEM_ATT_DB,
    /// Memory allocated for kernel messages
    KE_MEM_KE_MSG,
    /// Non Retention memory block
    KE_MEM_NON_RETENTION,
    KE_MEM_BLOCK_MAX,
};

/// Kernel environment definition
struct ke_env_tag
{
    /// Queue of sent messages but not yet delivered to receiver
    struct co_list queue_sent;
    /// Queue of messages delivered but not consumed by receiver
    struct co_list queue_saved;
    /// Queue of timers
    struct co_list queue_timer;

    #if (KE_MEM_RW)
    /// Root pointer = pointer to first element of heap linked lists
    struct mblock_free * heap[KE_MEM_BLOCK_MAX];
    /// Size of heaps
    uint16_t heap_size[KE_MEM_BLOCK_MAX];

    #if (KE_PROFILING)
    /// Size of heap used
    uint16_t heap_used[KE_MEM_BLOCK_MAX];
    /// Maximum heap memory used
    uint32_t max_heap_used;
    #endif //KE_PROFILING
    #endif //KE_MEM_RW
};

typedef uint16_t ke_task_id_t;
// #define KE_BUILD_ID(type, index) ( (ke_task_id_t)(((index) << 8)|(type)) )
struct ke_msg_id_struct
{
    ke_task_id_t index:24;
    ke_task_id_t type:8;
};


enum {
    BLE_CNTL_ADDR = 0x114,

};


#define BLE_CENTRAL 1
#define BLE_BROADCASTER 1
#define BLE_CHNL_ASSESS 1
#define __DA14531__ 1
#define ECDH_KEY_LEN        32


/*
 * TYPE DEFINITIONS
 ****************************************************************************************
 */
/// Advertising parameters
struct advertising_pdu_params
{
    /// Pointer on the data adv request
    struct ke_msg * adv_data_req;
    /// Connection interval min
    uint16_t intervalmin;
    /// Connection interval max
    uint16_t intervalmax;
    /// Channel mapping
    uint8_t channelmap;
    /// Filtering policy
    uint8_t filterpolicy;
    /// Advertising type
    uint8_t type;
    /// Data length
    uint8_t datalen;
    /// Scan RSP length
    uint8_t scanrsplen;
    /// Local address type
    uint8_t own_addr_type;
    /// Advertising periodicity: true for low duty cycle, false for high duty cycle
    bool adv_ldc_flag;
    ///Peer address type: public=0x00 /random = 0x01
    uint8_t        peer_addr_type;
    ///Peer Bluetooth device address used for IRK selection
    struct bd_addr peer_addr;
};

///Scanning parameters
struct scanning_pdu_params
{
    /// Scan interval
    uint16_t interval;
    /// Scan window
    uint16_t window;
    /// Filtering policy
    uint8_t filterpolicy;
    /// Scanning type
    uint8_t type;
    /// Duplicate the advertising report
    uint8_t filter_duplicate;
    /// Local address type
    uint8_t own_addr_type;
};

///Access address generation structure
struct access_addr_gen
{
    /// random
    uint8_t intrand;
    /// index 1
    uint8_t ct1_idx;
    /// index 2
    uint8_t ct2_idx;
};

/// Advertising report list
struct adv_device_list
{
    /// Header
    struct co_list_hdr hdr;
    /// Advertising type
    uint8_t adv_type;
    /// Advertising device address
    struct bd_addr adv_addr;
};

//advertising pdu
///structure adv undirected
struct llm_pdu_adv
{
    /// advertising address
    struct bd_addr  adva;
    /// advertising data
    uint8_t         *adva_data;
};
///structure adv directed
struct llm_pdu_adv_directed
{
    /// advertising address
    struct bd_addr  adva;
    /// initiator address
    struct bd_addr  inita;
};

//scanning pdu
///structure scan request
struct llm_pdu_scan_req
{
    /// scanning address
    struct bd_addr  scana;
    /// advertising address
    struct bd_addr  adva;
};
///structure scan response
struct llm_pdu_scan_rsp
{
    /// advertising address
    struct bd_addr  adva;
    /// scan response data
    uint8_t         *scan_data;

};
///initiating pdu
///structure connection request reception
struct llm_pdu_con_req_rx
{
    /// initiator address
    struct bd_addr      inita;
    /// advertiser address
    struct bd_addr      adva;
    /// access address
    struct access_addr  aa;
    /// CRC init
    struct crc_init     crcinit;
    /// window size
    uint8_t             winsize;
    /// window offset
    uint16_t            winoffset;
    /// interval
    uint16_t            interval;
    /// latency
    uint16_t            latency;
    /// timeout
    uint16_t            timeout;
    /// channel mapping
    struct le_chnl_map  chm;
    /// hopping
    uint8_t             hop_sca;
};
///structure connection request transmission
struct llm_pdu_con_req_tx
{
    /// access address
    struct access_addr  aa;
    /// CRC init
    struct crc_init     crcinit;
    /// window size
    uint8_t             winsize;
    /// window offset
    uint16_t            winoffset;
    /// interval
    uint16_t            interval;
    /// latency
    uint16_t            latency;
    /// timeout
    uint16_t            timeout;
    /// channel mapping
    struct le_chnl_map  chm;
    /// hopping
    uint8_t             hop_sca;
};

///structure for the test mode
struct llm_test_mode
{
    /// flag indicating the end of test
    bool end_of_tst;
    /// Direct test type
    uint8_t  directtesttype;
};

/// LLM environment structure to be saved
struct llm_le_env_tag
{
    /// List of encryption requests
    struct co_list enc_req;

    #if (BLE_CENTRAL || BLE_OBSERVER)
    /// Advertising reports filter policy
    struct co_list adv_list;

    /// Scanning parameters
    struct scanning_pdu_params *scanning_params;
    #endif //(BLE_CENTRAL || BLE_OBSERVER)

    #if (BLE_BROADCASTER || BLE_PERIPHERAL)
    /// Advertising parameters
    struct advertising_pdu_params *advertising_params;
    #endif //(BLE_BROADCASTER || BLE_PERIPHERAL)

    #if (BLE_CENTRAL || BLE_PERIPHERAL)
    /// Connected bd address list
    struct co_list cnx_list;
    #endif //(BLE_CENTRAL || BLE_PERIPHERAL)

    /// Event mask
    struct evt_mask eventmask;

    /// Access address
    struct access_addr_gen aa;

    ///protection for the command
    bool llm_le_set_host_ch_class_cmd_sto;

    /// conhdl_allocated
    uint16_t conhdl_alloc;

    #if (BLE_CHNL_ASSESS)
    /// Duration of channel assessment timer
    uint16_t chnl_assess_timer;
    /// Max number of received packets
    uint16_t chnl_assess_nb_pkt;
    /// Max number of received bad packets
    uint16_t chnl_assess_nb_bad_pkt;
    #endif // (BLE_CHNL_ASSESS)

    /// Element
    struct ea_elt_tag *elt;

    ///encryption pending
    bool enc_pend;

    ///test mode
    struct llm_test_mode test_mode;

    /// Active link counter
    uint8_t cpt_active_link;

    /// Current channel map
    struct le_chnl_map ch_map;

    /// random bd_address
    struct bd_addr rand_add;

    /// public bd_address
    struct bd_addr public_add;

    /// current @type in the register
    uint8_t curr_addr_type;

    #if (BLE_CHNL_ASSESS)
    /// Minimum received signal strength
    int8_t chnl_assess_min_rssi;
    /// Counter value used for channel reassessment
    uint8_t chnl_reassess_cnt_val;
    /// Counter used for channel reassessment
    uint8_t chnl_reassess_cnt;
    #endif //(BLE_CHNL_ASSESS)

    // TODO add missing comments
    uint16_t    connInitialMaxTxOctets;
    uint16_t    connInitialMaxTxTime;
#if defined (__DA14531__)
    uint16_t suggestedTxOctets;
    uint16_t suggestedTxTime;
#endif
    uint16_t    supportedMaxTxOctets;
    uint16_t    supportedMaxTxTime;
    uint16_t    supportedMaxRxOctets;
    uint16_t    supportedMaxRxTime;

    uint8_t     address_resolution_enable;
    struct co_list  llm_resolving_list;
    uint16_t    rpa_timeout;

    /// Local address type
    uint8_t own_addr_type;
    /// Resolving list being used for AIR_OP
    struct ll_resolving_list *rl;
    /// Resolving list being used for own address
    struct ll_resolving_list *rlown;
    /// bitfiled for timer usage for local/peer RPA
    uint8_t timer;
    /// Peer address type in Initiating state
    uint8_t peer_addr_type;
    /// Peer bd_address in Initiating state
    struct bd_addr peer_addr;

    uint8_t     llm_resolving_list_index;
    struct co_list  resolve_pending_events;

    /// List of P256 requests
    struct co_list p256_req;
    uint8_t llm_p256_private_key[ECDH_KEY_LEN];
    uint8_t llm_p256_state;
};



/*
 * TYPE DEFINITIONS
 ****************************************************************************************
 */

/// Remote version information structure
struct rem_version
{
    /// LMP version
    uint8_t vers;
    /// Manufacturer ID
    uint16_t compid;
    /// LMP subversion
    uint16_t subvers;
};

/// Encryption structure
struct encrypt
{
    /// Session key diversifier
    struct sess_k_div   skd;
    /// Long term key
    struct ltk          ltk;
};


#define LE_DATA_FREQ_LEN    0x25
#define BLE_CHNL_ASSESS 1
#define __DA14531__ 1

/// Operation type
enum llc_op_type
{
    /// Parameters update operation
    LLC_OP_PARAM_UPD         = 0x00,

    /// Max number of operations
    LLC_OP_MAX
};


/// LLC environment structure
struct llc_env_tag
{
    /// Request operation Kernel message
    void* operation[LLC_OP_MAX];
    /// Pointer to the associated @ref LLD event
    struct ea_elt_tag *elt;
    /// Peer version obtained using the LL_VERSION_IND LLCP message
    struct rem_version  peer_version;

    /// Link supervision time out
    uint16_t            sup_to;
    /// New link supervision time out to be applied
    uint16_t            n_sup_to;
    /// Authenticated payload time out (expressed in units of 10 ms)
    uint16_t            auth_payl_to;
    /// Authenticated payload time out margin (expressed in units of 10 ms)
    uint16_t            auth_payl_to_margin;
    /// Variable to save the previous state
    ke_task_id_t        previous_state;
    /// LLC status
    uint16_t            llc_status;
    ///Current channel map
    struct le_chnl_map  ch_map;
    ///New channel map - Will be applied at instant when a channel map update is pending
    struct le_chnl_map  n_ch_map;
    /// Received signal strength indication
    int8_t              rssi;
    /// Features used by the stack
    struct le_features  feats_used;
    /// Encryption state
    uint8_t             enc_state;
    /// Structure dedicated for the encryption
    struct encrypt      encrypt;
    /// Transmit packet counter
    uint8_t             tx_pkt_cnt;
    /// Disconnection reason
    uint8_t             disc_reason;

    /// rx status
    uint8_t             rx_status;
    /// feature request received first check
    bool                first_check;

    #if (BLE_CHNL_ASSESS)
    /// Channel Assessment - Number of packets received on each channel
    uint8_t            chnl_assess_pkt_cnt[LE_DATA_FREQ_LEN];
    /**
     * Channel Assessment - Number of packets received with a RSSI greater than the min
     * RSSI threshold and without found synchronization on each channel
     */
    uint8_t            chnl_assess_bad_pkt_cnt[LE_DATA_FREQ_LEN];
    #endif //(BLE_CHNL_ASSESS)
    #if (BLE_TESTER)
    struct hci_tester_set_le_params_cmd tester_params;
    #endif
    //GZ 4.2 LEN
    uint16_t            connMaxTxOctets;
    uint16_t            connMaxRxOctets;
    uint16_t            connRemoteMaxTxOctets;
    uint16_t            connRemoteMaxRxOctets;
    uint16_t            connEffectiveMaxTxOctets;
    uint16_t            connEffectiveMaxRxOctets;
    uint16_t            connMaxTxTime;
    uint16_t            connMaxRxTime;
    uint16_t            connRemoteMaxTxTime;
    uint16_t            connRemoteMaxRxTime;
    uint16_t            connEffectiveMaxTxTime;
    uint16_t            connEffectiveMaxRxTime;
    //our value to take time converted to octets into account
    uint16_t            connEffectiveMaxTxOctets_Time;
    /// length request received
    bool                llcp_length_req_first_check;
    /// length response received and queues
    bool                llcp_length_rsp_queued;
    /// packet counter free running
    uint32_t            pkt_cnt_tot;
    /// bad packet counter free running
    uint32_t            pkt_cnt_bad_tot;
    /// packet counter temporary for operations
    uint32_t            pkt_cnt;
    /// bad packet counter temporary for operations
    uint32_t            pkt_cnt_bad;
#if defined (__DA14531__)
    /* Queue with the HCI ACL Tx packets that are waiting for transmission. Each
     * packet might be further fragmented to one or more fragments (tx descriptors),
     * and <acl_flushed_tx_desc_cnt> will be increased by one for each fragment.
     * When the whole packet will be provided to the LLD for transmission, the packet
     * will move to the <acl_unacked_tx_data_queue> queue. */
    struct co_list acl_pending_tx_data_queue;
    /* Queue with the HCI ACL Tx packets that have been provided to the LLD for transmission,
     * but not all fragments have been yet acked by the peer. */
    struct co_list acl_unacked_tx_data_queue;
    /* Counts the tx descriptors that have been been acked by the peer. When all the tx
     * fragments of a packet residing in the <acl_unacked_tx_data_queue> have been acked,
     * the packet will be removed by the <acl_unacked_tx_data_queue> and a HCI_NB_CMP_PKTS_EVT_CODE
     * event will be sent to the host. <acl_flushed_tx_desc_cnt> will also be decreased. */
    uint8_t acl_flushed_tx_desc_cnt;
#endif
};
