
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
