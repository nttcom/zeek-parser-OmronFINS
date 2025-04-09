module OMRON_FINS;

@load ./consts

export {
	redef enum Log::ID += { LOG_OMRON_FINS };

	type Info: record {
		ts:	time &log &optional;
		uid: string &log &optional;
		id:	conn_id &log &optional;
		proto: string &log &optional;
		data_type: string &log &optional;
		destination_network_address: string &log &optional;
		destination_node_number: string &log &optional;
		destination_unit_address: string &log &optional;
		source_network_address: string &log &optional;
		source_node_number: string &log &optional;
		source_unit_address: string &log &optional;
		command_type: string &log &optional;
		number: int &log &optional;
		ts_end:	time &log &optional;
	};

	global log_omron_fins: event(rec: Info);

	type AggregationData: record {
		uid: string &log &optional;
		id: conn_id &log &optional;
		proto: string &log &optional;
		data_type: string &log &optional;
		destination_network_address: string &log &optional;
		destination_node_number: string &log &optional;
		destination_unit_address: string &log &optional;
		source_network_address: string &log &optional;
		source_node_number: string &log &optional;
		source_unit_address: string &log &optional;
		command_type: string &log &optional;
	};

	type Ts_num: record {
		ts_s: time &log;
		num: int &log;
		ts_e: time &log &optional;
	};

	function insert_log(res_aggregationData: table[AggregationData] of Ts_num, idx: AggregationData): interval
	{
		local info_insert: Info = [ ];
		info_insert$ts = res_aggregationData[idx]$ts_s;
		info_insert$uid = idx$uid;
		info_insert$id = idx$id;
		info_insert$proto = idx$proto;
		info_insert$data_type = idx$data_type;
		info_insert$destination_network_address = idx$destination_network_address;
		info_insert$destination_node_number = idx$destination_node_number;
		info_insert$destination_unit_address = idx$destination_unit_address;
		info_insert$source_network_address = idx$source_network_address;
		info_insert$source_node_number = idx$source_node_number;
		info_insert$source_unit_address = idx$source_unit_address;
		info_insert$command_type = idx$command_type;
		if ( res_aggregationData[idx]?$ts_e )
		{
			info_insert$ts_end = res_aggregationData[idx]$ts_e;
		}
		if ( res_aggregationData[idx]?$num )
		{
			info_insert$number = res_aggregationData[idx]$num;
		}

		Log::write(LOG_OMRON_FINS, info_insert);

		return 0secs;
	}

	global res_aggregationData: table[AggregationData] of Ts_num &create_expire=60sec &expire_func=insert_log;
}

global expected_data_conns: table[addr, port, addr] of Info;

# Define ports
const finsudp_ports = { 9600/udp };
redef likely_server_ports += { 9600/udp };

redef record connection += {
	OMRON_FINS: Info &optional;
};

event zeek_init() &priority=5 
{
	Log::create_stream(LOG_OMRON_FINS, [ $columns=Info, $ev=log_omron_fins, $path="omron_fins" ]);

	Analyzer::register_for_ports(Analyzer::ANALYZER_OMRON_FINS_UDP, finsudp_ports);
}

function create_aggregationData(info: Info): AggregationData
{
	local aggregationData: AggregationData;
	aggregationData$uid = info$uid;
	aggregationData$id = info$id;
	aggregationData$proto = info$proto;
	aggregationData$data_type = info$data_type;
	aggregationData$destination_network_address = info$destination_network_address;
	aggregationData$destination_node_number = info$destination_node_number;
	aggregationData$destination_unit_address = info$destination_unit_address;
	aggregationData$source_network_address = info$source_network_address;
	aggregationData$source_node_number = info$source_node_number;
	aggregationData$source_unit_address = info$source_unit_address;
	aggregationData$command_type = info$command_type;

	return aggregationData;
}

function insert_res_aggregationData(aggregationData: AggregationData, info: Info): string
{
	if ( aggregationData in res_aggregationData )
	{
		res_aggregationData[aggregationData]$num = res_aggregationData[aggregationData]$num + 1;
		res_aggregationData[aggregationData]$ts_e = info$ts;
	}
	else
	{
		res_aggregationData[aggregationData] = [ $ts_s=info$ts, $num=1, $ts_e=info$ts ];
	}

	return "done";
}

type finsFrame: record {
    dataType: int;
    gatewayCount: int;
    dna: int;
    da1: int;
    da2: int;
    sna: int;
    sa1: int;
    sa2: int;
    commandCode: int;
};

event omron_fins::finsUDP(c: connection, data: finsFrame)
{
	if ( data$gatewayCount == 2 )
	{
		local info: Info;
		local aggregationData: AggregationData;
		info$ts = network_time();
		info$uid = c$uid;
		info$id = c$id;
		info$proto = "udp";
		info$data_type = data_types[data$dataType];
		info$destination_network_address = fmt("0x%02x", data$dna);
		info$destination_node_number = fmt("0x%02x", data$da1);
		info$destination_unit_address = unit_addresses[data$da2];
		info$source_network_address = fmt("0x%02x", data$sna);
		info$source_node_number = fmt("0x%02x", data$sa1);
		info$source_unit_address = unit_addresses[data$sa2];
		info$command_type = command_types[data$commandCode];

		aggregationData = create_aggregationData(info);
		insert_res_aggregationData(aggregationData, info);
	}
}

#local debug
event zeek_done()
{
	for ( i in res_aggregationData )
	{
		local info: Info = [ ];
		info$ts = res_aggregationData[i]$ts_s;
		info$uid = i$uid;
		info$id = i$id;
		info$proto = i$proto;
		info$data_type = i$data_type;
		info$destination_network_address = i$destination_network_address;
		info$destination_node_number = i$destination_node_number;
		info$destination_unit_address = i$destination_unit_address;
		info$source_network_address = i$source_network_address;
		info$source_node_number = i$source_node_number;
		info$source_unit_address = i$source_unit_address;
		info$command_type = i$command_type;

		if ( res_aggregationData[i]?$ts_e )
		{
			info$ts_end = res_aggregationData[i]$ts_e;
		}
		if ( res_aggregationData[i]?$num )
		{
			info$number = res_aggregationData[i]$num;
		}

		Log::write(LOG_OMRON_FINS, info);
	}
}
