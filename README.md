# GopherCap

> Accurate, modular, scalable PCAP manipulation tool written in Go.

GoperCap uses [gopacket](https://github.com/google/gopacket) and [cobra](https://github.com/spf13/cobra) to build a CLI tool for PCAP manipulation. First implemented feature being the ability to concurrently replay offline PCAP files on live network interface. While preserving timestamps between each packet.

It can also calculate metadata for PCAP files and extract files from compressed tarballs (with no intermediate storage requirements).

# Background

Stamus Networks develops  [Scirius Security Platform](https://www.stamus-networks.com/scirius-platform) and open-source [Scirius CE](https://github.com/StamusNetworks/scirius). We specialize in IDS rule management, threat hunting, and data analytics. All centered around [Suricata](https://github.com/OISF/suricata) network IDS. Our development and QA pipeline is therefore *data-driven*, which is just a fancy way of saying *we rely on replaying PCAPs over and over again*.

Normally we would use [tcpreplay](https://tcpreplay.appneta.com/) with predetermined PPS options. But this flattens the packet rate for entire PCAP file, and in process loses important temporal information needed for developing algorithmic threat detection. 

Furthermore, a particular larger-than-average dataset posed an interesting problem where PCAPs were written in parallel using [moloch](https://github.com/aol/moloch). Each worker wrote to a separate file and thus also rotated them independently. Flow processing 101 - all packets in a flow need to pass a single worker and flow balancing is always a best effort. And *elephant flows* happen. That resulted in dataset that could not be replayed sequentially as the actual file periods were all out of sync. And guess what, thread ID was not part of PCAP file naming scheme...

Of course we could just do `-r` and parse PCAPs post-mortem. NSM tools even support reading an entire folder and maintain flows between files. Solves the problem, right? 

Well, not really. This post-mortem read functionality has never really worked well with large out of sync PCAPs. Often the process simply runs for excessive amount of time while using a lot of memory. Maintaining all those flow tables, not sure when to time out, can really take it's toll. And it really struggles when files are not sequential. And to make matters worse, all events are in past with new parse iterations just being thrown into the same elastic pile as the old. Not ideal for continuous QA and dev work. This got us thinking.

We can check when a PCAP file begins and ends by simply parsing the first and last packet. [Gopacket](https://github.com/google/gopacket) is pretty cool. It works well, we have have good experience using it. Even better, golang is actually built from ground up for concurrency, and spinning up IO readers that produce to single IO writer via thread-safe channel is a breeze. So, why not just sleep each reader for a duration calculated between global dataset and PCAP start timestamps. We can easily calculate diffs between each packet with `time.Sub()`, and sleep before pushing to writer. [Gopacket even had an example on that (albeit too basic to outright solve our problem)](https://github.com/google/gopacket/blob/master/examples/pcaplay/main.go). And finally, we could implement this feature as subcommand to bigger binary and build our own swiss army knife for all kinds of funky PCAP operations.

Two working days later, we had a prototype replay tool. And after a month of bugfixes and usage in lab we decided to give it to community.

# Getting started

## Build and basic usage

GoperCap needs on libpcap to write packets into network interface. Development headers are needed for installing and regular library must be installed for execution.

Ubuntu and Debian: 

```
apt-get update && apt-get install -y libpcap-dev libpcap0.8
```

Arch Linux:

```
pacman -Sy libpcap
```

Then proceed as normal for building a go binary. Get project dependencies.

```
go get -u ./
```

And build the binary.

```
go build -o ./gopherCap ./
```

Or install it to `$GOPATH`.

```
go install
which gopherCap
```

Binary can then be executed directly.

```
gopherCap --help
```

## Testing replay

Each subcommand has embedded usage examples. Refer to those for up to date and more extensive information.

```
gopherCap map --help
```
```
gopherCap replay --help
```
```
gopherCap tarExtract --help
```

Replay functionality requires PCAP files to be mapped first. This will collect metadata, such as first and last timestamp, total number of packets, PPS, etc. Most importantly, timestamp information is needed to calculate global dataset start and delay before reading each PCAP.

```
gopherCap map \
	--dir-src /mnt/pcap \
	--file-suffix "pcap" \
	--dump-json /mnt/pcap/meta.json
```

Note that current implementation needs to iterate over entire PCAP file, for all files in dataset. Thus, mapping can take long. But it only needs to be done once. Afterwards, the `replay` subcommand will simply load the JSON metadata. This needs to be considered when moving or remounting PCAP storage.

```
gopherCap replay \
	--out-interface veth0 \
	--dump-json /mnt/pcap/meta.json
```

### Configuring virtual NIC for testing

Virtual ethernet interface pair can be created with following command. Packets replayed to one interface can be read from another.

```
sudo ip link add veth0 type veth peer name veth1
```

After creation, make sure to activate them.

```
sudo ip link set veth0 up
sudo ip link set veth1 up
```

Use tcpdump to validate replay.

```
sudo tcpdump -i veth1 -n
```

Replay command might crash with following error:

```
FATA[0005] send: Message too long
```

This means packet was bigger than interface MTU. Maximum packet size can be found in metadata JSON. But 9000 is usually a safe MTU size, corresponding to common jumbo packet feature in many network switches.

```
sudo ip link set dev veth0 mtu 9000
sudo ip link set dev veth1 mtu 9000
```

## Docker

Alternatively, you can also build and run gophercap as a docker container.

```
docker build -t stamus/gophercap .
```

Subcommands can then be executed through the image.

```
docker run -ti --rm stamus/gophercap --help
```

You will want to mount PCAP directory as volume.

```
docker run -ti --rm -v /mnt/pcap:/pcaps stamus/gophercap map \
  --dir-src /pcaps \
  --dump-json /pcaps/meta.json
```

For replay, you need to use *host network* rather than default docker bridge. Also, make sure that mapped PCAP paths correspond to in-container mount point, rather than host folder.

```
docker run -ti --rm --network host -v /mnt/pcap:/pcaps stamus/gophercap replay \
  --dump-json /pcaps/meta.json \
  --out-interface veth0
```

# Subcommands

GoperCap uses *cobra* and *viper* libraries to implement a single binary with many subcommands. Similar to many other tools built in Go. Here's overview of currently supported features.

## Map

PCAP metadata mapper. Collects timestamp information needed by replay command, along with other useful information. Such as largest packet size, total packet size, packet count, PPS, etc. Can take a lot of time to complete on bigger datasets, as it needs to iterate over all PCAP files. Thus reason for making this a separate subcommand, rather than wasting time before each replay sequence. PCAPs are processed concurrently on workers. So, the time needed depends on system IO throughput and CPU performance.

```
Usage:
  gopherCap map [flags]

Flags:
      --dir-src string       Source folder for recursive pcap search.
      --file-suffix string   Suffix suffix used for file discovery. (default "pcap.gz")
      --file-workers int     Number of concurrent workers for scanning pcap files. Value less than 1 will map all pcap files concurrently. (default 4)
  -h, --help                 help for map

Global Flags:
      --config string        config file (default is $HOME/.go-replay.yaml)
      --dump-json string     Full or relative path for storing pcap metadata in JSON format. (default "db/mapped-files.json")
      --file-regexp string   Regex pattern to filter files.
```

## Replay

Replay PCAP files to network interface while preserving time difference between packets. Requires files to be mapped beforehand, as the command relies entirely on metadata dump and no file discovery or mapping is performed.

PCAP replay can be sped up or slowed down using timescaling parameters. BPF filter can be applied to written packets.

```
Usage:
  gopherCap replay [flags]

Flags:
  -h, --help                           help for replay
      --loop-count int                 Number of iterations over pcap set. Will run infinitely if 0 or negative value is given. (default 1)
      --loop-infinite                  Loop over pcap files infinitely. Will override --loop-count
      --out-bpf string                 BPF filter to exclude some packets.
      --out-interface string           Network interface to replay to. (default "eth0")
      --time-from string               Start replay from this time.
      --time-modifier float            Modifier for speeding up or slowing down the replay by a factor of X. (default 1)
      --time-scale-duration duration   Duration for time scaling. (default 1h0m0s)
      --time-scale-enabled             Enable time scaling. When enabled, will automatically calculate time.modifier value to replay pcap in specified time window. Overrides time.modifier value. Actual replay is not guaranteed to complete in defined time, As overhead from sleep calculations causes a natural drift.
      --time-to string                 End replay from this time.

Global Flags:
      --config string        config file (default is $HOME/.go-replay.yaml)
      --dump-json string     Full or relative path for storing pcap metadata in JSON format. (default "db/mapped-files.json")
      --file-regexp string   Regex pattern to filter files.
```

## Tar extract

While attempting to use gopherCap in offline dev environment, we ran into a little problem. PCAPs were in 1 terabyte gzipped tarball that took 4 terabytes fully uncompressed. More than what was available on hand at the time. And only 1 terabyte subset (300GB compressed) was actually relevant for replay.

This subcommand was written to extract selection of files from tarballs, optionally directly to gzipped file handles. No temporary storage or advanced filesystem level compression needed.

```
Usage:
  gopherCap tarExtract [flags]

Flags:
      --dryrun              Only list files in tarball for regex validation, do not extract.
  -h, --help                help for tarExtract
      --in-tarball string   Input gzipped tarball.
      --out-dir string      Output directory for pcap files.
      --out-gzip            Compress extracted files with gzip.

Global Flags:
      --config string        config file (default is $HOME/.go-replay.yaml)
      --dump-json string     Full or relative path for storing pcap metadata in JSON format. (default "db/mapped-files.json")
      --file-regexp string   Regex pattern to filter files.
```

# Contributing

For all contributions please use a Pull Request on Github or open an issue.
