#include <stdio.h>
#include <rte_hash_crc.h>

#include "core.h"
#include "debug.h"
#include "firmware.h"

void ath10k_debug_print_hwfw_info(struct ath10k *ar)
{
	const struct firmware *firmware;
	char fw_features[128] = {};
	uint32_t crc = 0;

	ath10k_core_get_fw_features_str(ar, fw_features, sizeof(fw_features));

	ath10k_info(ar, "%s target 0x%08x chip_id 0x%08x sub %04x:%04x\n",
		    ar->hw_params.name,
		    ar->target_version,
		    ar->chip_id,
		    ar->id.subsystem_vendor, ar->id.subsystem_device);

	firmware = ar->normal_mode_fw.fw_file.firmware;
	if (firmware) {
		crc =  rte_hash_crc(firmware->data, firmware->size, 0);
	}

	ath10k_info(ar, "├──> firmware-ver %s\n", ar->normal_mode_fw.fw_file.fw_version);
	ath10k_info(ar, "├──> api          %d\n", ar->fw_api);
	ath10k_info(ar, "├──> features     %s\n", fw_features);
	ath10k_info(ar, "└──> crc32        %08x\n", crc);
}

void ath10k_debug_print_board_info(struct ath10k *ar)
{
	char boardinfo[100];

	if (ar->id.bmi_ids_valid)
		scnprintf(boardinfo, sizeof(boardinfo), "%d:%d",
			  ar->id.bmi_chip_id, ar->id.bmi_board_id);
	else
		scnprintf(boardinfo, sizeof(boardinfo), "N/A");

	ath10k_info(ar, "board_file api %d bmi_id %s crc32 %08x\n",
		    ar->bd_api,
		    boardinfo,
		    rte_hash_crc(ar->normal_mode_fw.board->data, 
			ar->normal_mode_fw.board->size, 0));
}

void ath10k_debug_print_boot_info(struct ath10k *ar)
{
	ath10k_info(ar, "htt-ver %d.%d wmi-op %d htt-op %d cal %s max-sta %d raw %d hwcrypto %d\n",
		    ar->htt.target_version_major,
		    ar->htt.target_version_minor,
		    ar->normal_mode_fw.fw_file.wmi_op_version,
		    ar->normal_mode_fw.fw_file.htt_op_version,
		    ath10k_cal_mode_str(ar->cal_mode),
		    ar->max_num_stations,
		    test_bit(ATH10K_FLAG_RAW_MODE, &ar->dev_flags),
		    !test_bit(ATH10K_FLAG_HW_CRYPTO_DISABLED, &ar->dev_flags));
}

void ath10k_print_driver_info(struct ath10k *ar)
{
	ath10k_debug_print_hwfw_info(ar);
	ath10k_debug_print_board_info(ar);
	ath10k_debug_print_boot_info(ar);
}

void ath10k_dbg_dump(struct ath10k *ar,
		     enum ath10k_debug_mask mask,
		     const char *msg, const char *prefix,
		     const void *buf, size_t len)
{
	if(rte_log_get_global_level() & mask){
		int msgSize = 0;
		bool both = msg != NULL && prefix != NULL;
		char* msgConc = NULL;
		if(both) {
			int len = strlen(prefix) + 1 + strlen(msg) + 1;
			msgConc = malloc(len);
			snprintf(msgConc, len, "%s %s\0", prefix, msg);
		} else {
			if(prefix) {
				int len = strlen(prefix) + 1;
				msgConc = malloc(len);
				snprintf(msgConc, len, "%s\0", prefix);
			}
			if(msg) {
				int len = strlen(msg) + 1;
				msgConc = malloc(len);
				snprintf(msgConc, len, "%s\0", msg);
			}
		}

		rte_hexdump(stdout, msgConc, buf, len);

		free(msgConc);
	}
}
