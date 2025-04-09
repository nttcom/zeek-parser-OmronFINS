# Zeek-Parser-OmronFINS

English is [here](https://github.com/nttcom-ic/zeek-parser-OmronFINS/blob/main/README_en.md)

## 概要

Zeek-Parser-OmronFINSとはOmron FINS/UDPを解析できるZeekプラグインです。

## インストール

### マニュアルインストール

本プラグインを利用する前に、Zeek, Spicyがインストールされていることを確認します。

```
# Zeekのチェック
~$ zeek -version
zeek version 7.0.0

# Spicyのチェック
~$ spicyz -version
7.0.0
~$ spicyc -version
spicyc v1.11.0 (7ddf6ce4)

# 本マニュアルではZeekのパスが以下であることを前提としています。
~$ which zeek
/usr/local/zeek/bin/zeek
```

本リポジトリをローカル環境に `git clone` します。

```
~$ git clone https://github.com/nttcom-ic/zeek-parser-OmronFINS.git
```

## 使い方

### マニュアルインストールの場合

ソースコードをコンパイルして、オブジェクトファイルを以下のパスにコピーします。

```
~$ cd ~/zeek-parser-OmronFINS/analyzer
~$ spicyz -o omron_fins.hlto omron_fins.spicy omron_fins.evt
# omron_fins.hltoが生成されます
~$ cp omron_fins.hlto /usr/local/zeek/lib/zeek/spicy/
```

同様にZeekファイルを以下のパスにコピーします。

```
~$ cd ~/zeek-parser-OmronFINS/scripts/
~$ cp main.zeek /usr/local/zeek/share/zeek/site/omron_fins.zeek
~$ cp consts.zeek /usr/local/zeek/share/zeek/site/
```

最後にZeekプラグインをインポートします。

```
~$ tail /usr/local/zeek/share/zeek/site/local.zeek
...省略...
@load omron_fins
```

本プラグインを使うことで `omron_fins.log` が生成されます。

```
~$ cd ~/zeek-parser-OmronFINS/testing/Traces
~$ zeek -Cr test.pcap /usr/local/zeek/share/zeek/site/omron_fins.zeek
```

## ログのタイプと説明

本プラグインを使うことで`omron_fins.log`として出力します。

| フィールド | タイプ | 説明 |
| --- | --- | --- |
| ts | time | 最初に通信した時のタイムスタンプ |
| uid | string | ユニークID |
| id.orig_h | addr | 送信元IPアドレス |
| id.orig_p | port | 送信元ポート番号 |
| id.resp_h | addr | 宛先IPアドレス |
| id.resp_p | port | 宛先ポート番号 |
| proto | enum | トランスポート層プロトコル |
| data_type | string | コマンドとレスポンスが定義されている |
| destination_network_address | string | 相手先ネットワークアドレス |
| destination_node_number | string | 相手先ノードアドレス |
| destination_unit_address | string | 相手先号機アドレス |
| source_network_address | string | 発信元ネットワークアドレス |
| source_node_number | string | 発信元ノードアドレス |
| source_unit_address | string | 発信元号機アドレス |
| command_type | string | コマンドのタイプ |
| number | int | パケット出現回数 |
| ts_end | time | 最後に通信した時のタイムスタンプ |

`omron_fins.log` の例は以下のとおりです。

```
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	omron_fins
#open	2025-03-28-16-30-42
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	data_type	destination_network_address	destination_node_number	destination_unit_address	source_network_address	source_node_number	source_unit_address	command_type	number	ts_end
#types	time	string	addr	port	addr	port	string	string	string	string	string	string	string	string	string	int	time
1736159106.716243	CMR1Cj2J87pBDJu7Va	2.2.2.2	55007	1.1.1.1	9600	udp	command	0x00	0x64	CPU Unit	0x00	0x01	CPU Unit	multiple_memory_area_read	10	1736159106.717982
1736159106.716463	CMR1Cj2J87pBDJu7Va	2.2.2.2	55007	1.1.1.1	9600	udp	response	0x00	0x01	CPU Unit	0x00	0x64	CPU Unit multiple_memory_area_read	10	1736159106.718071
#close	2025-03-28-16-30-42
```

## 関連ソフトウェア

本プラグインは[OsecT](https://github.com/nttcom/OsecT)で利用されています。
