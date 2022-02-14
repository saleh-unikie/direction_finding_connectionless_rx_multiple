/*
 * Copyright (c) 2021 Nordic Semiconductor ASA
 *
 *  SPDX-License-Identifier: Apache-2.0
 */

#include <stddef.h>
#include <errno.h>
#include <zephyr.h>

#include <sys/printk.h>
#include <sys/byteorder.h>
#include <sys/util.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/gap.h>
#include <bluetooth/direction.h>

#include <bluetooth/hci.h>
#include <host/hci_core.h>

#define DEVICE_NAME     CONFIG_BT_DEVICE_NAME
#define DEVICE_NAME_LEN (sizeof(DEVICE_NAME) - 1)
#define NAME_LEN        30
#define TIMEOUT_SYNC_CREATE_MS 40000

static bool scan_enabled;

struct synch_addr_t {
    bt_addr_le_t addr;
    uint8_t sid;
};

struct synch_info_t {
    struct bt_le_per_adv_sync *synch_ptr;
    int64_t timestamp;
};

enum {no_sync=0, candid_sync, ongoing_sync, terminated_sync, done_sync};
atomic_t sync_flag = ATOMIC_INIT(no_sync);
struct synch_addr_t synch_addr;
struct synch_info_t synch_info;

static K_SEM_DEFINE(sem_per_adv, 0, 1);
static K_SEM_DEFINE(sem_per_sync, 0, 1);
static K_SEM_DEFINE(sem_per_sync_lost, 0, 1);

#if defined(CONFIG_BT_CTLR_DF_ANT_SWITCH_RX)
const static uint8_t ant_patterns[] = { 0x1, 0x2, 0x3, 0x4, 0x5,
					0x6, 0x7, 0x8, 0x9, 0xA };
#endif /* CONFIG_BT_CTLR_DF_ANT_SWITCH_RX */

static bool data_cb(struct bt_data *data, void *user_data);
static int create_sync(bt_addr_le_t *address, uint8_t sid,
						struct bt_le_per_adv_sync **synch);
static void scan_recv(const struct bt_le_scan_recv_info *info,
		      struct net_buf_simple *buf);

static void sync_cb(struct bt_le_per_adv_sync *sync,
		    struct bt_le_per_adv_sync_synced_info *info);
static void term_cb(struct bt_le_per_adv_sync *sync,
		    const struct bt_le_per_adv_sync_term_info *info);
static void recv_cb(struct bt_le_per_adv_sync *sync,
		    const struct bt_le_per_adv_sync_recv_info *info,
		    struct net_buf_simple *buf);
static void scan_recv(const struct bt_le_scan_recv_info *info,
		      struct net_buf_simple *buf);
static void scan_disable(void);
static void cte_recv_cb(struct bt_le_per_adv_sync *sync,
			struct bt_df_per_adv_sync_iq_samples_report const *report);

static struct bt_le_per_adv_sync_cb sync_callbacks = {
	.synced = sync_cb,
	.term = term_cb,
	.recv = recv_cb,
	.cte_report_cb = cte_recv_cb,
};

static struct bt_le_scan_cb scan_callbacks = {
	.recv = scan_recv,
};

static const char *phy2str(uint8_t phy)
{
	switch (phy) {
	case 0: return "No packets";
	case BT_GAP_LE_PHY_1M: return "LE 1M";
	case BT_GAP_LE_PHY_2M: return "LE 2M";
	case BT_GAP_LE_PHY_CODED: return "LE Coded";
	default: return "Unknown";
	}
}

static const char *cte_type2str(uint8_t type)
{
	switch (type) {
	case BT_DF_CTE_TYPE_AOA: return "AOA";
	case BT_DF_CTE_TYPE_AOD_1US: return "AOD 1 [us]";
	case BT_DF_CTE_TYPE_AOD_2US: return "AOD 2 [us]";
	case BT_DF_CTE_TYPE_NONE: return "";
	default: return "Unknown";
	}
}

static const char *pocket_status2str(uint8_t status)
{
	switch (status) {
	case BT_DF_CTE_CRC_OK: return "CRC OK";
	case BT_DF_CTE_CRC_ERR_CTE_BASED_TIME: return "CRC not OK, CTE Info OK";
	case BT_DF_CTE_CRC_ERR_CTE_BASED_OTHER: return "CRC not OK, Sampled other way";
	case BT_DF_CTE_INSUFFICIENT_RESOURCES: return "No resources";
	default: return "Unknown";
	}
}

static bool data_cb(struct bt_data *data, void *user_data)
{
	char *name = user_data;
	uint8_t len;

	switch (data->type) {
	case BT_DATA_NAME_SHORTENED:
	case BT_DATA_NAME_COMPLETE:
		len = MIN(data->data_len, NAME_LEN - 1);
		memcpy(name, data->data, len);
		name[len] = '\0';
		return false;
	default:
		return true;
	}
}

static void sync_cb(struct bt_le_per_adv_sync *sync,
		    struct bt_le_per_adv_sync_synced_info *info)
{
	char le_addr[BT_ADDR_LE_STR_LEN];

	bt_addr_le_to_str(info->addr, le_addr, sizeof(le_addr));

	printk("S\tPER_ADV_SYNC[%u]: [DEVICE]: %s synced, "
	       "Interval 0x%04x (%u ms), PHY %s\n",
	       bt_le_per_adv_sync_get_index(sync), le_addr,
	       info->interval, info->interval * 5 / 4, phy2str(info->phy));

	k_sem_give(&sem_per_sync);
}

static void term_cb(struct bt_le_per_adv_sync *sync,
		    const struct bt_le_per_adv_sync_term_info *info)
{
	char le_addr[BT_ADDR_LE_STR_LEN];

	bt_addr_le_to_str(info->addr, le_addr, sizeof(le_addr));

	printk("T\tPER_ADV_SYNC[%u]: [DEVICE]: %s sync terminated\n",
	       bt_le_per_adv_sync_get_index(sync), le_addr);

	if (synch_info.synch_ptr == sync) {
		if (atomic_cas(&sync_flag, ongoing_sync, terminated_sync)) {
			k_sem_give(&sem_per_sync);
		}
	}
}

static void recv_cb(struct bt_le_per_adv_sync *sync,
		    const struct bt_le_per_adv_sync_recv_info *info,
		    struct net_buf_simple *buf)
{
	char le_addr[BT_ADDR_LE_STR_LEN];
	char data_str[129];

	bt_addr_le_to_str(info->addr, le_addr, sizeof(le_addr));
	bin2hex(buf->data, buf->len, data_str, sizeof(data_str));
/*
	printk("PER_ADV_SYNC[%u]: [DEVICE]: %s, tx_power %i, "
	       "RSSI %i, CTE %s, data length %u, data: %s\n",
	       bt_le_per_adv_sync_get_index(sync), le_addr, info->tx_power,
	       info->rssi, cte_type2str(info->cte_type), buf->len, data_str);
*/
}

static void cte_recv_cb(struct bt_le_per_adv_sync *sync,
			struct bt_df_per_adv_sync_iq_samples_report const *report)
{
/*
	char le_addr[BT_ADDR_LE_STR_LEN];

	bt_addr_le_to_str(&(sync->addr), le_addr, sizeof(le_addr));

	printk("CTE[%u]: [DEVICE]: %s, samples count %d, cte type %s, "
	       "slot durations: %u [us], packet status %s, RSSI %i\n",
	       bt_le_per_adv_sync_get_index(sync), le_addr, report->sample_count,
	       cte_type2str(report->cte_type), report->slot_durations,
	       pocket_status2str(report->packet_status), report->rssi);
*/
}

static void scan_recv(const struct bt_le_scan_recv_info *info,
		      struct net_buf_simple *buf)
{
	char le_addr[BT_ADDR_LE_STR_LEN];
	char name[NAME_LEN];

	(void)memset(name, 0, sizeof(name));

	bt_data_parse(buf, data_cb, name);

	bt_addr_le_to_str(info->addr, le_addr, sizeof(le_addr));
/*
	printk("[DEVICE]: %s, AD evt type %u, Tx Pwr: %i, RSSI %i %s C:%u S:%u "
	       "D:%u SR:%u E:%u Prim: %s, Secn: %s, Interval: 0x%04x (%u ms), "
	       "SID: %u\n",
	       le_addr, info->adv_type, info->tx_power, info->rssi, name,
	       (info->adv_props & BT_GAP_ADV_PROP_CONNECTABLE) != 0,
	       (info->adv_props & BT_GAP_ADV_PROP_SCANNABLE) != 0,
	       (info->adv_props & BT_GAP_ADV_PROP_DIRECTED) != 0,
	       (info->adv_props & BT_GAP_ADV_PROP_SCAN_RESPONSE) != 0,
	       (info->adv_props & BT_GAP_ADV_PROP_EXT_ADV) != 0,
	       phy2str(info->primary_phy), phy2str(info->secondary_phy),
	       info->interval, info->interval * 5 / 4, info->sid);
*/
	if (info->interval != 0) {
		if (bt_le_per_adv_sync_lookup_addr(info->addr, info->sid) == NULL) {
			if (atomic_cas(&sync_flag, no_sync, candid_sync)) {
				bt_addr_le_copy(&(synch_addr.addr), info->addr);
				synch_addr.sid = info->sid;

				k_sem_give(&sem_per_adv);
			}
		}
	}
}

static int create_sync(bt_addr_le_t *address, uint8_t sid,
						struct bt_le_per_adv_sync **synch)
{
	int err;
	struct bt_le_per_adv_sync_param sync_create_param;
	char le_addr[BT_ADDR_LE_STR_LEN];

	bt_addr_le_to_str(address, le_addr, sizeof(le_addr));

	printk("C\tCreating Sync:[DEVICE]: %s ...", le_addr);
	bt_addr_le_copy(&sync_create_param.addr, address);

	sync_create_param.options = BT_LE_PER_ADV_SYNC_OPT_SYNC_ONLY_CONST_TONE_EXT|
                                BT_LE_PER_ADV_SYNC_OPT_DONT_SYNC_AOD_1US |
                                BT_LE_PER_ADV_SYNC_OPT_DONT_SYNC_AOD_1US;
	sync_create_param.sid = sid;
	sync_create_param.skip = 0;
	sync_create_param.timeout = 2000;
	err = bt_le_per_adv_sync_create(&sync_create_param, synch);
	if (err != 0) {
		printk("failed (err %d)\n", err);
	} else {
		printk("success.\n");
	}

	return err;
}

static int delete_sync(struct bt_le_per_adv_sync *synch)
{
	int err;
	char le_addr[BT_ADDR_LE_STR_LEN];

	bt_addr_le_to_str(&(synch->addr), le_addr, sizeof(le_addr));

	printk("D\tDeleting Sync of [DEVICE]: %s\n", le_addr);
	err = bt_le_per_adv_sync_delete(synch);
	if (err != 0) {
		printk("failed (err %d)\n", err);
		return err;
	}

	return 0;
}

static int enable_cte_rx(struct bt_le_per_adv_sync *synch)
{
	int err;
	char le_addr[BT_ADDR_LE_STR_LEN];

	const struct bt_df_per_adv_sync_cte_rx_param cte_rx_params = {
		.max_cte_count = 5,
#if defined(CONFIG_BT_CTLR_DF_ANT_SWITCH_RX)
		.cte_types = BT_DF_CTE_TYPE_AOA,
		.slot_durations = 0x1,
		.num_ant_ids = ARRAY_SIZE(ant_patterns),
		.ant_ids = ant_patterns,
#else
		.cte_type = BT_DF_CTE_TYPE_AOD_1US | BT_DF_CTE_TYPE_AOD_2US,
#endif /* CONFIG_BT_CTLR_DF_ANT_SWITCH_RX */
	};

	bt_addr_le_to_str(&(synch->addr), le_addr, sizeof(le_addr));
	printk("E\t[DEVICE]: %s enabling CTE ... ", le_addr);
	/* printk("Enable receiving of CTE..."); */
	err = bt_df_per_adv_sync_cte_rx_enable(synch, &cte_rx_params);
	if (err != 0) {
		/* printk("failed (err %d)\n", err); */
	} else {
		printk("success.\n");
	}

	return err;
}

static int scan_init(void)
{
	/* printk("Scan callbacks register..."); */
	bt_le_scan_cb_register(&scan_callbacks);
	/* printk("success.\n"); */

	/* printk("Periodic Advertising callbacks register..."); */
	bt_le_per_adv_sync_cb_register(&sync_callbacks);
	/* printk("success.\n"); */

	return 0;
}

static int scan_enable(void)
{
	struct bt_le_scan_param param = {
			.type       = BT_LE_SCAN_TYPE_ACTIVE,
			.options    = BT_LE_SCAN_OPT_FILTER_DUPLICATE,
			.interval   = BT_GAP_SCAN_FAST_INTERVAL,
			.window     = BT_GAP_SCAN_FAST_WINDOW,
			.timeout    = 0U, };
	int err;

	if (!scan_enabled) {
		/* printk("Start scanning..."); */
		err = bt_le_scan_start(&param, NULL);
		if (err != 0) {
			/* printk("failed (err %d)\n", err); */
			return err;
		}
		/* printk("success\n"); */
		scan_enabled = true;
	}

	return 0;
}

static void scan_disable(void)
{
	int err;

	/* printk("Scan disable..."); */
	err = bt_le_scan_stop();
	if (err != 0) {
		/* printk("___failed (err %d)\n", err); */
		return;
	}
	/* printk("Success.\n"); */

	scan_enabled = false;
}

void main(void)
{
	int err;
	int last_time_scan_refresh = k_uptime_get();
	int timeout_cnt = 0;
	char le_addr[BT_ADDR_LE_STR_LEN];

	printk("Starting Connectionless Locator Demo\n");

	printk("Bluetooth initialization...");
	err = bt_enable(NULL);
	if (err != 0) {
		printk("failed (err %d)\n", err);
	}
	printk("success\n");

	scan_init();

	scan_enabled = false;

	do {
		/* enable scan */
		scan_enable();

		/* if there is any candidate to be synced, create the sync */
		atomic_set(&sync_flag, no_sync);
		/* wait until when a new candidate is ready to be synced */
		err = k_sem_take(&sem_per_adv, K_MSEC(15000));
		switch (err) {
			/* error */
			case -EBUSY:
				printk("k_sem_take failed (err %d). App terminated#\n", err);
				return;
				break;

			/* time out */
			case -EAGAIN:
				printk(".");
				++timeout_cnt;
				if (timeout_cnt == 20) {
					printk("\n");
					timeout_cnt = 0;
				}
				/* give a fresh scan */
				scan_disable();
				/* start from begining of the loop again */
				continue;
				break;

			default:
				timeout_cnt = 0;
		}

		if (atomic_cas(&sync_flag, candid_sync, ongoing_sync)) {
			err = create_sync(&(synch_addr.addr), synch_addr.sid,
					&(synch_info.synch_ptr));
			if (err != 0) {
				bt_addr_le_to_str(&(synch_addr.addr), le_addr, sizeof(le_addr));
				printk("XC\tCreating sync [DEVICE]: %s failed (err %d)\n", le_addr, err);
				/* give a fresh scan */
				scan_disable();
				/* start from begining of the loop again */
				continue;
			} else {
				/* set timestamp and create the synch obj */
				synch_info.timestamp = k_uptime_get();
			}
		} else {
			/* give a fresh scan */
			scan_disable();
			/* start from begining of the loop again */
			continue;
		}

		/* check the sync process and make it go forward until when CTE is enabled */
		err = k_sem_take(&sem_per_sync, K_MSEC(TIMEOUT_SYNC_CREATE_MS));
		if (err != 0 || atomic_cas(&sync_flag, terminated_sync, terminated_sync)) {
			bt_addr_le_to_str(&(synch_info.synch_ptr->addr), le_addr, sizeof(le_addr));
			if (err != 0) {
				printk("XO\tCreating sync [DEVICE]: %s  timed out\n", le_addr);
			} else {
				printk("XT\tCreating sync [DEVICE]: %s  terminated\n", le_addr);
			}
			
			err = delete_sync(synch_info.synch_ptr);
			if (err != 0) {
				printk("delete_sync failed (err %d). App terminated#\n", err);
				return;
			}

			/* give a fresh scan */
			scan_disable();
			/* start from begining of the loop again */
			continue;
		}

		err = enable_cte_rx(synch_info.synch_ptr);
		if (err != 0) {
			printk("XE\tenable_cte_rx failed\n");
			delete_sync(synch_info.synch_ptr);
			scan_disable();
			continue;
		}

		k_busy_wait(50000);		

		/* give a fresh scan */
		scan_disable();

	} while (true);
}
