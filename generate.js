#!/usr/bin/env node

require("dotenv").config();
const { default: IP_CIDR } = require("ip-cidr");
const { expandIPv6Number: expand_ipv6 } = require("ip-num");
const {
    readFileSync: read_file_sync,
    writeFileSync: write_file_sync,
} = require("fs");
const { join: join_path } = require("path");
const { execSync: run_bash } = require('child_process');

const NETBOX = process.env.NETBOX_API_URI;

const fetch_netbox = async (uri, { headers, ...init }) => {
    console.debug(`preflighting request to ${uri}`);

    if (process.env.IGNORE_TLS_VERIFICATION?.toLowerCase() === "true") {
        console.debug("disabling TLS certificate verification, requested by .env");

        process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
    }

    return await fetch(uri, {
        headers: {
            authorization: `Token ${process.env.NETBOX_API_KEY}`,
            accept: "application/json",
            ...headers,
        },
        ...init,
    });
};

const main = async () => {
    const datagrid = {};

    let prefixes_req;
    try {
        prefixes_req = await fetch_netbox(`${NETBOX}/ipam/prefixes/`, {
            method: "GET",
        });
    } catch (error) {
        console.error(error);

        return process.exit(1);
    }

    let prefixes_json;
    try {
        prefixes_json = await prefixes_req.json();
    } catch (error) {
        console.error(error);

        return process.exit(2);
    }

    for (const prefix of prefixes_json.results) {
        if (
            !prefix?.custom_fields?.ptr_prefix ||
            !prefix?.custom_fields?.ptr_subdomain
        ) {
            continue;
        }

        const prefix_cidr = new IP_CIDR(prefix.prefix);
        const is_ip_legacy = prefix_cidr.address.v4;
        if (!is_ip_legacy && !prefix?.custom_fields?.ip6_arpa_zone) {
            continue;
        }

        let zone;
        if (!is_ip_legacy) {
            zone = prefix.custom_fields.ip6_arpa_zone;
        } else {
            zone = `${prefix.prefix
                .split("/")[0]
                .split(".")
                .toReversed()
                .slice(1)
                .join(".")}.in-addr.arpa`;
        }

        const ptr_prefix = prefix.custom_fields.ptr_prefix;
        const subdomain = prefix.custom_fields.ptr_subdomain;

        if (!datagrid[zone]) {
            datagrid[zone] = {
                AF_VERSION: is_ip_legacy ? 4 : 6,
            };
        }

        for (const address of prefix_cidr.toArray()) {
            if (!is_ip_legacy) {
                const split_addr = address.split(":").toReversed();
                if (split_addr[0] === "0000") {
                    continue;
                }

                let result_arr = [];
                for (const chunk of split_addr) {
                    let trimmed = "";
                    for (let i = 0; i < chunk.length; i++) {
                        if (chunk[i] === "0" && trimmed === "") {
                            continue;
                        }

                        trimmed += chunk[i];
                    }

                    if (trimmed.length > 0) {
                        result_arr.push(trimmed);
                    } else if (result_arr[result_arr.length - 1] !== "") {
                        // what the fuck is this?
                        // pushing an empty character means our join here below will create the `--`, that we want replacing the `::`, for us.
                        result_arr.push("");
                    }
                }

                datagrid[zone][address] = `${ptr_prefix}-${result_arr.join(
                    "-"
                )}.${subdomain}.${process.env.PTR_DOMAIN}`;
            } else {
                const [oct0, oct1, oct2, oct3] = address.split(".");
                if (oct3 === "0") {
                    continue;
                }

                datagrid[zone][
                    address
                ] = `${ptr_prefix}-${oct3}-${oct2}-${oct1}-${oct0}.${subdomain}.${process.env.PTR_DOMAIN}`;
            }
        }

        let addresses_req;
        try {
            addresses_req = await fetch_netbox(
                `${NETBOX}/ipam/ip-addresses/?parent=${prefix.prefix}`,
                {
                    method: "GET",
                }
            );
        } catch (error) {
            console.error(error);

            return process.exit(3);
        }

        let addresses_json;
        try {
            addresses_json = await addresses_req.json();
        } catch (error) {
            console.error(error);

            return process.exit(4);
        }

        for (const address of addresses_json.results) {
            // do not let empty dns names replace autoPTRs
            if (!address.dns_name || address.dns_name.replace(/ /g, '') === "") {
                continue;
            }

            const ip_cidr = new IP_CIDR(address.address);

            // prevent IPv4 'network' addresses from obtaining an auto-ptr.
            // also prevent 'ugly' IPv6 addresses from doing the same.
            const parsed_groups = ip_cidr.address.parsedAddress;
            if (parsed_groups[parsed_groups.length - 1] === "0") {
                continue;
            }

            let ip_address = ip_cidr.address.addressMinusSuffix;
            if (!is_ip_legacy) {
                ip_address = expand_ipv6(ip_address);
            }

            datagrid[zone][ip_address] = address.dns_name;
        }
    }

    const default_template = read_file_sync(
        join_path(__dirname, "zone-template.tpl"),
        { encoding: "utf8" }
    );

    for (const [zone, { AF_VERSION, ...records }] of Object.entries(datagrid)) {
        let ptr_records = ``;

        if (AF_VERSION === 6) {
            for (const [address, ptr] of Object.entries(records)) {
                const record_host = `${address
                    .replaceAll(":", "")
                    .split("")
                    .toReversed()
                    .join(".")}.ip6.arpa.`;

                let ptr_value;
                if (ptr.endsWith(".")) {
                    ptr_value = ptr;
                } else {
                    ptr_value = `${ptr}.`;
                }

                ptr_records += `${record_host} IN  PTR ${ptr_value}\n`;
            }
        }

        if (AF_VERSION === 4) {
            for (const [address, ptr] of Object.entries(records)) {
                const [oct0, oct1, oct2, oct3] = address.split(".");

                let ptr_value;
                if (ptr.endsWith(".")) {
                    ptr_value = ptr;
                } else {
                    ptr_value = `${ptr}.`;
                }

                const record_host = `${oct3}.${oct2}.${oct1}.${oct0}.in-addr.arpa.`;

                ptr_records += `${record_host} IN PTR ${ptr_value}\n`;
            }
        }

        let template;
        try {
            template = read_file_sync(join_path(__dirname, `${zone}.tpl`), { encoding: 'utf8' })
        } catch {
            // do nothing, template is undefined
        }

        if (!template) {
            template = default_template;
        }

        const now = new Date();
        const yyyy = now.getUTCFullYear();
        const mm = now.getUTCMonth().toString().padStart(2, '0');
        const dd = now.getUTCDate().toString().padStart(2, '0');
        const serial_yyyymmddxx = `${yyyy}${mm}${dd}01`;

        const result_db = template
            .replaceAll("{{ PTR_RECORDS }}", ptr_records)
            .replaceAll("{{ ZONE }}", zone)
            .replaceAll("{{ SERIAL }}", serial_yyyymmddxx);

        write_file_sync(join_path(process.env.OUT_DIRECTORY, `db.${zone}`), result_db);
    }

    if (process.env.RELOAD_DNS_SERVER_CMD) {
        try {
            run_bash(process.env.RELOAD_DNS_SERVER_CMD);
        } catch (e) {
            console.error('Error while running DNS server reload CMD:', e);

            return process.exit(100);
        }
    }

    return process.exit(0);
};

main();
