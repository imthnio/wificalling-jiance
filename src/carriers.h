/* ePDG 候选清单。默认域名按 3GPP TS 23.003 由 MCC/MNC 生成：
 *   epdg.epc.mnc<MNC>.mcc<MCC>.pub.3gppnetwork.org
 * extra 是运营商实际使用的非标准域名（来自 Android carrier config），会和标准域名一起检测。
 * 新增运营商只需在这里加一行。 */

enum { ASIA, EUROPE, AMERICAS, CONTINENT_COUNT };
static const char *const continent_names[] = {"亚洲", "欧洲", "美洲"};

/* pinyin 仅用于菜单排序，避免依赖系统 locale。 */
static const struct country {
    const char *name, *pinyin;
    int continent;
} countries[] = {
    {"菲律宾", "feilvbin", ASIA},
    {"爱尔兰", "aierlan", EUROPE},
    {"奥地利", "aodili", EUROPE},
    {"比利时", "bilishi", EUROPE},
    {"波兰", "bolan", EUROPE},
    {"德国", "deguo", EUROPE},
    {"法国", "faguo", EUROPE},
    {"荷兰", "helan", EUROPE},
    {"葡萄牙", "putaoya", EUROPE},
    {"瑞典", "ruidian", EUROPE},
    {"瑞士", "ruishi", EUROPE},
    {"西班牙", "xibanya", EUROPE},
    {"意大利", "yidali", EUROPE},
    {"英国", "yingguo", EUROPE},
    {"加拿大", "jianada", AMERICAS},
    {"美国", "meiguo", AMERICAS},
};

static const struct carrier {
    const char *country, *name, *mcc, *mnc, *extra;
} carriers[] = {
    {"德国", "Telekom", "262", "001", NULL},
    {"德国", "Vodafone", "262", "002", NULL},
    {"德国", "O2", "262", "003", NULL},
    {"法国", "Orange", "208", "001", NULL},
    {"法国", "SFR", "208", "010", NULL},
    {"法国", "Bouygues", "208", "020", NULL},
    {"法国", "Free", "208", "015", NULL},
    {"意大利", "TIM", "222", "001", NULL},
    {"意大利", "Vodafone", "222", "010", NULL},
    {"意大利", "WindTre", "222", "088", NULL},
    {"西班牙", "Movistar", "214", "007", NULL},
    {"西班牙", "Orange", "214", "003", NULL},
    {"西班牙", "Vodafone", "214", "001", NULL},
    {"英国", "EE", "234", "030", NULL},
    {"英国", "O2", "234", "010", NULL},
    {"英国", "Vodafone", "234", "015", NULL},
    {"英国", "Three", "234", "020", NULL},
    {"荷兰", "KPN", "204", "008", NULL},
    {"荷兰", "Vodafone", "204", "004", NULL},
    {"比利时", "Proximus", "206", "001", NULL},
    {"比利时", "Orange", "206", "010", NULL},
    {"瑞士", "Swisscom", "228", "001", NULL},
    {"瑞士", "Sunrise", "228", "002", NULL},
    {"奥地利", "A1", "232", "001", NULL},
    {"奥地利", "Magenta", "232", "003", NULL},
    {"波兰", "Orange", "260", "003", NULL},
    {"波兰", "Play", "260", "006", NULL},
    {"瑞典", "Telia", "240", "001", NULL},
    {"瑞典", "Telenor", "240", "008", NULL},
    {"爱尔兰", "Vodafone", "272", "001", NULL},
    {"爱尔兰", "Three", "272", "005", NULL},
    {"葡萄牙", "Vodafone", "268", "001", NULL},
    {"葡萄牙", "MEO", "268", "006", NULL},
    {"美国", "T-Mobile", "310", "260", "ss.epdg.epc.mnc260.mcc310.pub.3gppnetwork.org"},
    {"美国", "AT&T", "310", "410", "epdg.epc.att.net"},
    {"美国", "Verizon", "311", "480", "wo.vzwwo.com"},
    {"加拿大", "Rogers", "302", "720", NULL},
    {"加拿大", "Bell", "302", "610", NULL},
    {"加拿大", "TELUS", "302", "220", NULL},
    {"菲律宾", "Globe", "515", "002", NULL},
    {"菲律宾", "Smart", "515", "003", NULL},
    {"菲律宾", "DITO", "515", "066", NULL},
};
