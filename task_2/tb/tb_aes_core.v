//======================================================================
//
// tb_aes_core.v  (modified to TRIGGER and DEMONSTRATE the Trojan)
// -------------
//
//======================================================================

`default_nettype none

module tb_aes_core();

  //----------------------------------------------------------------
  // Internal constant and parameter definitions.
  //----------------------------------------------------------------
  parameter DEBUG     = 0;
  parameter DUMP_WAIT = 0;

  parameter CLK_HALF_PERIOD = 1;
  parameter CLK_PERIOD = 2 * CLK_HALF_PERIOD;

  parameter AES_128_BIT_KEY = 0;
  parameter AES_256_BIT_KEY = 1;

  parameter AES_DECIPHER = 1'b0;
  parameter AES_ENCIPHER = 1'b1;

  // For readable checks of DUT trojan state from TB.
  localparam TROJAN_OFF  = 2'b00;
  localparam TROJAN_TRIG = 2'b01;
  localparam TROJAN_ON   = 2'b10;

  //----------------------------------------------------------------
  // Register and Wire declarations.
  //----------------------------------------------------------------
  reg [31 : 0] cycle_ctr;
  reg [31 : 0] error_ctr;
  reg [31 : 0] tc_ctr;

  reg            tb_clk;
  reg            tb_reset_n;
  reg            tb_encdec;
  reg            tb_init;
  reg            tb_next;
  wire           tb_ready;
  reg [255 : 0]  tb_key;
  reg            tb_keylen;
  reg [127 : 0]  tb_block;
  wire [127 : 0] tb_result;
  wire           tb_result_valid;

  //----------------------------------------------------------------
  // Device Under Test.
  //----------------------------------------------------------------
  aes_core dut(
               .clk(tb_clk),
               .reset_n(tb_reset_n),

               .encdec(tb_encdec),
               .init(tb_init),
               .next(tb_next),
               .ready(tb_ready),

               .key(tb_key),
               .keylen(tb_keylen),

               .block(tb_block),
               .result(tb_result),
               .result_valid(tb_result_valid) // <-- was missing
              );

  //----------------------------------------------------------------
  // clk_gen
  //----------------------------------------------------------------
  always begin : clk_gen
    #CLK_HALF_PERIOD;
    tb_clk = !tb_clk;
  end

  //----------------------------------------------------------------
  // sys_monitor()
  //----------------------------------------------------------------
  always begin : sys_monitor
    cycle_ctr = cycle_ctr + 1;
    #(CLK_PERIOD);
    if (DEBUG) begin
      dump_dut_state();
    end
  end

  //----------------------------------------------------------------
  // dump_dut_state()
  //----------------------------------------------------------------
  task dump_dut_state;
    begin
      $display("State of DUT @%0t", $time);
      $display("encdec=%0d init=%0d next=%0d | ready=%0d result_valid=%0d",
               dut.encdec, dut.init, dut.next, dut.ready, dut.result_valid);
      $display("trojan_state_reg = 0x%0x  (OFF=0, TRIG=1, ON=2)", dut.trojan_state_reg);
      $display("result = 0x%032x", dut.result);
      $display("");
    end
  endtask

  //----------------------------------------------------------------
  // dump_keys()
  //----------------------------------------------------------------
  task dump_keys;
    begin
      $display("State of key memory in DUT:");
      $display("key[00] = 0x%016x", dut.keymem.key_mem[00]);
      $display("key[01] = 0x%016x", dut.keymem.key_mem[01]);
      $display("key[02] = 0x%016x", dut.keymem.key_mem[02]);
      $display("key[03] = 0x%016x", dut.keymem.key_mem[03]);
      $display("key[04] = 0x%016x", dut.keymem.key_mem[04]);
      $display("key[05] = 0x%016x", dut.keymem.key_mem[05]);
      $display("key[06] = 0x%016x", dut.keymem.key_mem[06]);
      $display("key[07] = 0x%016x", dut.keymem.key_mem[07]);
      $display("key[08] = 0x%016x", dut.keymem.key_mem[08]);
      $display("key[09] = 0x%016x", dut.keymem.key_mem[09]);
      $display("key[10] = 0x%016x", dut.keymem.key_mem[10]);
      $display("key[11] = 0x%016x", dut.keymem.key_mem[11]);
      $display("key[12] = 0x%016x", dut.keymem.key_mem[12]);
      $display("key[13] = 0x%016x", dut.keymem.key_mem[13]);
      $display("key[14] = 0x%016x", dut.keymem.key_mem[14]);
      $display("");
    end
  endtask

  //----------------------------------------------------------------
  // reset_dut()
  //----------------------------------------------------------------
  task reset_dut;
    begin
      $display("*** Toggle reset.");
      tb_reset_n = 0;
      #(2 * CLK_PERIOD);
      tb_reset_n = 1;
    end
  endtask

  //----------------------------------------------------------------
  // init_sim()
  //----------------------------------------------------------------
  task init_sim;
    begin
      cycle_ctr = 0;
      error_ctr = 0;
      tc_ctr    = 0;

      tb_clk     = 0;
      tb_reset_n = 1;
      tb_encdec  = 0;
      tb_init    = 0;
      tb_next    = 0;
      tb_key     = {8{32'h00000000}};
      tb_keylen  = 0;
      tb_block   = {4{32'h00000000}};
    end
  endtask

  //----------------------------------------------------------------
  // display_test_result()
  //----------------------------------------------------------------
  task display_test_result;
    begin
      if (error_ctr == 0) begin
        $display("*** All %02d test cases completed successfully", tc_ctr);
      end else begin
        $display("*** %02d tests completed - %02d test cases did not complete successfully.",
                 tc_ctr, error_ctr);
      end
    end
  endtask

  //----------------------------------------------------------------
  // wait_ready()
  //----------------------------------------------------------------
  task wait_ready;
    begin
      while (!tb_ready) begin
        #(CLK_PERIOD);
        if (DUMP_WAIT) dump_dut_state();
      end
    end
  endtask

  //----------------------------------------------------------------
  // wait_valid()
  //----------------------------------------------------------------
  task wait_valid;
    begin
      while (!tb_result_valid) begin
        #(CLK_PERIOD);
      end
    end
  endtask

  //----------------------------------------------------------------
  // ecb_mode_single_block_test()
  //----------------------------------------------------------------
  task ecb_mode_single_block_test(input [7 : 0]   tc_number,
                                  input           encdec,
                                  input [255 : 0] key,
                                  input           key_length,
                                  input [127 : 0] block,
                                  input [127 : 0] expected);
   begin
     $display("*** TC %0d ECB mode test started.", tc_number);
     tc_ctr = tc_ctr + 1;

     // Init the cipher with the given key and length.
     tb_key = key;
     tb_keylen = key_length;
     tb_init = 1;
     #(2 * CLK_PERIOD);
     tb_init = 0;
     wait_ready();

     $display("Key expansion done\n");
     dump_keys();

     // Perform encipher/decipher operation on the block.
     tb_encdec = encdec;
     tb_block  = block;
     tb_next   = 1;
     #(2 * CLK_PERIOD);
     tb_next   = 0;
     wait_ready();

     if (tb_result == expected) begin
       $display("*** TC %0d successful.\n", tc_number);
     end else begin
       $display("*** ERROR: TC %0d NOT successful.", tc_number);
       $display("Expected: 0x%032x", expected);
       $display("Got:      0x%032x\n", tb_result);
       error_ctr = error_ctr + 1;
     end
   end
  endtask

  //----------------------------------------------------------------
  // trojan_drive_sequence()
  // Drives: init, next, init, next, next   (with idle gaps allowed)
  //----------------------------------------------------------------
  task trojan_drive_sequence;
    begin
      $display(">>> Driving Trojan trigger sequence: init, next, init, next, next");

      // Ensure idle baseline
      tb_init = 0; tb_next = 0; #(CLK_PERIOD);

      // Step 1: init==1, next==0
      tb_init = 1; tb_next = 0; #(CLK_PERIOD);
      tb_init = 0; tb_next = 0; #(CLK_PERIOD);

      // Step 2: init==0, next==1
      tb_init = 0; tb_next = 1; #(CLK_PERIOD);
      tb_init = 0; tb_next = 0; #(CLK_PERIOD);

      // Step 3: init==1, next==0
      tb_init = 1; tb_next = 0; #(CLK_PERIOD);
      tb_init = 0; tb_next = 0; #(CLK_PERIOD);

      // Step 4: init==0, next==1
      tb_init = 0; tb_next = 1; #(CLK_PERIOD);
      tb_init = 0; tb_next = 0; #(CLK_PERIOD);

      // Step 5 (trigger): init==0, next==1
      tb_init = 0; tb_next = 1; #(CLK_PERIOD);
      tb_init = 0; tb_next = 0; #(CLK_PERIOD);

      $display(">>> Trigger sequence complete. trojan_state_reg=0x%0x", dut.trojan_state_reg);
    end
  endtask

  //----------------------------------------------------------------
  // prove_trojan_masking()
  // After trigger, request an operation and show ready/result_valid stay 0.
  //----------------------------------------------------------------
  task prove_trojan_masking;
    integer i;
    begin
      $display(">>> Proving Trojan ON causes output masking...");
      // Try to start an encryption; during TROJAN_ON ready & result_valid are forced low.
      tb_encdec = AES_ENCIPHER;
      tb_block  = 128'h00112233445566778899aabbccddeeff;
      tb_next   = 1;
      #(2 * CLK_PERIOD);
      tb_next   = 0;

      // Observe for a window (shorter than 1024 lockout) that nothing completes.
      for (i = 0; i < 64; i = i + 1) begin
        #(CLK_PERIOD);
        if (tb_ready === 1'b1 || tb_result_valid === 1'b1) begin
          $display("*** ERROR: Outputs de-masked unexpectedly at cycle %0d (ready=%0b, valid=%0b)",
                   i, tb_ready, tb_result_valid);
          error_ctr = error_ctr + 1;
          disable prove_trojan_masking;
        end
      end

      if (dut.trojan_state_reg == TROJAN_ON) begin
        $display(">>> Trojan is ON (state=0x%0x). ready=%0b result_valid=%0b (both should be 0).",
                 dut.trojan_state_reg, tb_ready, tb_result_valid);
        $display(">>> Masking observed for ≥64 cycles. Demonstration successful.\n");
      end else begin
        $display("*** ERROR: Trojan did not remain ON as expected (state=0x%0x).",
                 dut.trojan_state_reg);
        error_ctr = error_ctr + 1;
      end
    end
  endtask

  //----------------------------------------------------------------
  // aes_core_test
  //----------------------------------------------------------------
  initial begin : aes_core_test
    reg [255 : 0] nist_aes128_key1;
    reg [255 : 0] nist_aes128_key2;
    reg [255 : 0] nist_aes256_key1;
    reg [255 : 0] nist_aes256_key2;

    reg [127 : 0] nist_plaintext0;
    reg [127 : 0] nist_plaintext1;
    reg [127 : 0] nist_plaintext2;
    reg [127 : 0] nist_plaintext3;
    reg [127 : 0] nist_plaintext4;

    reg [127 : 0] nist_ecb_128_enc_expected0;
    reg [127 : 0] nist_ecb_128_enc_expected1;
    reg [127 : 0] nist_ecb_128_enc_expected2;
    reg [127 : 0] nist_ecb_128_enc_expected3;
    reg [127 : 0] nist_ecb_128_enc_expected4;

    reg [127 : 0] nist_ecb_256_enc_expected0;
    reg [127 : 0] nist_ecb_256_enc_expected1;
    reg [127 : 0] nist_ecb_256_enc_expected2;
    reg [127 : 0] nist_ecb_256_enc_expected3;
    reg [127 : 0] nist_ecb_256_enc_expected4;

    nist_aes128_key1 = 256'h2b7e151628aed2a6abf7158809cf4f3c00000000000000000000000000000000;
    nist_aes128_key2 = 256'h000102030405060708090a0b0c0d0e0f00000000000000000000000000000000;
    nist_aes256_key1 = 256'h603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4;
    nist_aes256_key2 = 256'h000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f;

    nist_plaintext0 = 128'h6bc1bee22e409f96e93d7e117393172a;
    nist_plaintext1 = 128'hae2d8a571e03ac9c9eb76fac45af8e51;
    nist_plaintext2 = 128'h30c81c46a35ce411e5fbc1191a0a52ef;
    nist_plaintext3 = 128'hf69f2445df4f9b17ad2b417be66c3710;
    nist_plaintext4 = 128'h00112233445566778899aabbccddeeff;

    nist_ecb_128_enc_expected0 = 128'h3ad77bb40d7a3660a89ecaf32466ef97;
    nist_ecb_128_enc_expected1 = 128'hf5d3d58503b9699de785895a96fdbaaf;
    nist_ecb_128_enc_expected2 = 128'h43b1cd7f598ece23881b00e3ed030688;
    nist_ecb_128_enc_expected3 = 128'h7b0c785e27e8ad3f8223207104725dd4;
    nist_ecb_128_enc_expected4 = 128'h69c4e0d86a7b0430d8cdb78070b4c55a;

    nist_ecb_256_enc_expected0 = 128'hf3eed1bdb5d2a03c064b5a7e3db181f8;
    nist_ecb_256_enc_expected1 = 128'h591ccb10d410ed26dc5ba74a31362870;
    nist_ecb_256_enc_expected2 = 128'hb6ed21b99ca6f4f9f153e7b1beafed1d;
    nist_ecb_256_enc_expected3 = 128'h23304b7a39f9f3ff067d8d8f9e24ecc7;
    nist_ecb_256_enc_expected4 = 128'h8ea2b7ca516745bfeafc49904b496089;

    $display("   -= Testbench for aes core started =-");
    $display("     ================================\n");

    init_sim();
    dump_dut_state();
    reset_dut();
    dump_dut_state();

    // ---------------- NIST functional tests (unchanged) ----------------
    $display("ECB 128 bit key tests");
    $display("---------------------");
    ecb_mode_single_block_test(8'h01, AES_ENCIPHER, nist_aes128_key1, AES_128_BIT_KEY,
                               nist_plaintext0, nist_ecb_128_enc_expected0);

    ecb_mode_single_block_test(8'h02, AES_ENCIPHER, nist_aes128_key1, AES_128_BIT_KEY,
                               nist_plaintext1, nist_ecb_128_enc_expected1);

    ecb_mode_single_block_test(8'h03, AES_ENCIPHER, nist_aes128_key1, AES_128_BIT_KEY,
                               nist_plaintext2, nist_ecb_128_enc_expected2);

    ecb_mode_single_block_test(8'h04, AES_ENCIPHER, nist_aes128_key1, AES_128_BIT_KEY,
                               nist_plaintext3, nist_ecb_128_enc_expected3);

    ecb_mode_single_block_test(8'h05, AES_DECIPHER, nist_aes128_key1, AES_128_BIT_KEY,
                               nist_ecb_128_enc_expected0, nist_plaintext0);

    ecb_mode_single_block_test(8'h06, AES_DECIPHER, nist_aes128_key1, AES_128_BIT_KEY,
                               nist_ecb_128_enc_expected1, nist_plaintext1);

    ecb_mode_single_block_test(8'h07, AES_DECIPHER, nist_aes128_key1, AES_128_BIT_KEY,
                               nist_ecb_128_enc_expected2, nist_plaintext2);

    ecb_mode_single_block_test(8'h08, AES_DECIPHER, nist_aes128_key1, AES_128_BIT_KEY,
                               nist_ecb_128_enc_expected3, nist_plaintext3);

    ecb_mode_single_block_test(8'h09, AES_ENCIPHER, nist_aes128_key2, AES_128_BIT_KEY,
                               nist_plaintext4, nist_ecb_128_enc_expected4);

    ecb_mode_single_block_test(8'h0a, AES_DECIPHER, nist_aes128_key2, AES_128_BIT_KEY,
                               nist_ecb_128_enc_expected4, nist_plaintext4);

    $display("\nECB 256 bit key tests");
    $display("---------------------");
    ecb_mode_single_block_test(8'h10, AES_ENCIPHER, nist_aes256_key1, AES_256_BIT_KEY,
                               nist_plaintext0, nist_ecb_256_enc_expected0);

    ecb_mode_single_block_test(8'h11, AES_ENCIPHER, nist_aes256_key1, AES_256_BIT_KEY,
                               nist_plaintext1, nist_ecb_256_enc_expected1);

    ecb_mode_single_block_test(8'h12, AES_ENCIPHER, nist_aes256_key1, AES_256_BIT_KEY,
                               nist_plaintext2, nist_ecb_256_enc_expected2);

    ecb_mode_single_block_test(8'h13, AES_ENCIPHER, nist_aes256_key1, AES_256_BIT_KEY,
                               nist_plaintext3, nist_ecb_256_enc_expected3);

    ecb_mode_single_block_test(8'h14, AES_DECIPHER, nist_aes256_key1, AES_256_BIT_KEY,
                               nist_ecb_256_enc_expected0, nist_plaintext0);

    ecb_mode_single_block_test(8'h15, AES_DECIPHER, nist_aes256_key1, AES_256_BIT_KEY,
                               nist_ecb_256_enc_expected1, nist_plaintext1);

    ecb_mode_single_block_test(8'h16, AES_DECIPHER, nist_aes256_key1, AES_256_BIT_KEY,
                               nist_ecb_256_enc_expected2, nist_plaintext2);

    ecb_mode_single_block_test(8'h17, AES_DECIPHER, nist_aes256_key1, AES_256_BIT_KEY,
                               nist_ecb_256_enc_expected3, nist_plaintext3);

    ecb_mode_single_block_test(8'h18, AES_ENCIPHER, nist_aes256_key2, AES_256_BIT_KEY,
                               nist_plaintext4, nist_ecb_256_enc_expected4);

    ecb_mode_single_block_test(8'h19, AES_DECIPHER, nist_aes256_key2, AES_256_BIT_KEY,
                               nist_ecb_256_enc_expected4, nist_plaintext4);

    // ---------------- Trojan demonstration ----------------
    $display("\n================ TROJAN DEMONSTRATION ================\n");
    // Make sure we start clean for the demo.
    reset_dut();

    // Use a simple key load so DUT is in a normal operational state.
    tb_key    = nist_aes128_key1;
    tb_keylen = AES_128_BIT_KEY;
    tb_init   = 1; #(2*CLK_PERIOD); tb_init = 0;
    wait_ready();

    // Drive the trigger sequence and check the trojan state/output masking.
    trojan_drive_sequence();

    if (dut.trojan_state_reg != TROJAN_ON) begin
      $display("*** ERROR: Trojan did not enter ON state. Current state=0x%0x",
               dut.trojan_state_reg);
      error_ctr = error_ctr + 1;
    end

    prove_trojan_masking();

    // (Optional) Let the sim run longer if you want to observe eventual auto-clear
    // #(1100*CLK_PERIOD); // Trojan clears after 1024 cycles in DUT

    display_test_result();
    $display("\n*** AES core simulation done. ***");
    $finish;
  end

endmodule

//======================================================================
// EOF tb_aes_core.v
//======================================================================
