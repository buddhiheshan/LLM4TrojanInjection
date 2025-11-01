`timescale 1ns/1ps

module tb_wbuart_trojan;

  // clock & reset
  reg  clk   = 0;
  reg  rst   = 1;

  // wishbone
  reg        wb_cyc  = 0;
  reg        wb_stb  = 0;
  reg        wb_we   = 0;
  reg  [1:0] wb_addr = 2'b00;
  reg  [31:0] wb_data = 32'h0;
  reg  [3:0] wb_sel  = 4'hF;
  wire       wb_stall;
  wire       wb_ack;
  wire [31:0] wb_rdata;

  // uart pins (we won’t really use these for the trojan trigger)
  reg  uart_rx = 1'b1;
  wire uart_tx;
  reg  cts_n   = 1'b0;
  wire rts_n;
  wire rx_int, tx_int, rxf_int, txf_int;

  // DUT
  wbuart dut (
    .i_clk(clk),
    .i_reset(rst),
    .i_wb_cyc(wb_cyc),
    .i_wb_stb(wb_stb),
    .i_wb_we(wb_we),
    .i_wb_addr(wb_addr),
    .i_wb_data(wb_data),
    .i_wb_sel(wb_sel),
    .o_wb_stall(wb_stall),
    .o_wb_ack(wb_ack),
    .o_wb_data(wb_rdata),
    .i_uart_rx(uart_rx),
    .o_uart_tx(uart_tx),
    .i_cts_n(cts_n),
    .o_rts_n(rts_n),
    .o_uart_rx_int(rx_int),
    .o_uart_tx_int(tx_int),
    .o_uart_rxfifo_int(rxf_int),
    .o_uart_txfifo_int(txf_int)
  );

  // clock
  always #5 clk = ~clk;   // 100 MHz => 10ns period

  // simple WB read (2-cycle UART core)
  task wb_read(input [1:0] addr);
  begin
    @(posedge clk);
    wb_addr <= addr;
    wb_we   <= 1'b0;
    wb_cyc  <= 1'b1;
    wb_stb  <= 1'b1;

    // wait for ack to go high (the DUT acks after 2 cycles normally)
    wait (wb_ack === 1'b1);
    $display("[%0t] WB READ addr=%0d  ACK=%b  DATA=0x%08x",
              $time, addr, wb_ack, wb_rdata);

    @(posedge clk);
    wb_cyc  <= 1'b0;
    wb_stb  <= 1'b0;
  end
  endtask

  // send a "UART RX" byte by forcing internal wires
  task send_rx_byte(input [7:0] b);
  begin
    // 1st cycle: assert stb + data
    @(posedge clk);
    force dut.rx_stb       = 1'b1;
    force dut.rx_uart_data = b;

    // 2nd cycle: deassert
    @(posedge clk);
    release dut.rx_stb;
    release dut.rx_uart_data;
  end
  endtask

  initial begin
    // reset
    repeat (5) @(posedge clk);
    rst <= 0;
    $display("[%0t] --- RESET DEASSERTED ---", $time);

    // 1) normal read -> should ACK (trojan not armed)
    wb_read(2'b00);   // UART_SETUP

    // 2) trigger Trojan: 10, A4, 98, BD
    $display("[%0t] --- SENDING TROJAN TRIGGER SEQUENCE ---", $time);
    send_rx_byte(8'h10);
    send_rx_byte(8'ha4);
    send_rx_byte(8'h98);
    send_rx_byte(8'hbd);

    // give the trojan FSM one cycle to latch
    @(posedge clk);

    // 3) read again -> ACK should be 0 because trojan_disable_bus_ack=1
    $display("[%0t] --- READING WITH TROJAN ARMED (ACK SHOULD BE 0) ---", $time);
    @(posedge clk);
    wb_addr <= 2'b00;
    wb_we   <= 1'b0;
    wb_cyc  <= 1'b1;
    wb_stb  <= 1'b1;

    // wait a couple of cycles and print ack
    @(posedge clk);
    $display("[%0t] TROJAN ARMED READ: ACK=%b  DATA=0x%08x",
              $time, wb_ack, wb_rdata);
    @(posedge clk);
    wb_cyc  <= 1'b0;
    wb_stb  <= 1'b0;

    // 4) unlock with 4x FE
    $display("[%0t] --- SENDING UNLOCK SEQUENCE (4x FE) ---", $time);
    send_rx_byte(8'hfe);
    send_rx_byte(8'hfe);
    send_rx_byte(8'hfe);
    send_rx_byte(8'hfe);

    @(posedge clk);

    // 5) read again -> ACK should be 1 again
    $display("[%0t] --- READING AFTER UNLOCK (ACK SHOULD BE 1) ---", $time);
    wb_read(2'b00);

    $display("[%0t] --- TEST DONE ---", $time);
    #50;
    $finish;
  end

endmodule
