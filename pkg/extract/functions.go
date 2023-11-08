/*
Copyright © 2021 Stamus Networks oss@stamus-networks.com

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/
package extract

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/StamusNetworks/gophercap/pkg/filter"
	"github.com/StamusNetworks/gophercap/pkg/models"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/sirupsen/logrus"
)

// IPAddr is for decoding IP values directly to IP objects during JSON decode. net.IP is a wrapper
// around byte array, not integer, so it also handles IPv6 addresses.
type IPAddr struct{ net.IP }

// UnmarshalJSON implements json.Unmarshaler
func (t *IPAddr) UnmarshalJSON(b []byte) error {
	str, err := strconv.Unquote(string(b))
	if err != nil {
		return err
	}
	ip := net.ParseIP(str)
	if ip == nil {
		return fmt.Errorf("Invalid IP: %s", string(b))
	}
	t.IP = ip
	return nil
}

type Tunnel struct {
	SrcIP    IPAddr `json:"src_ip"`
	DestIP   IPAddr `json:"dest_ip"`
	SrcPort  uint16 `json:"src_port"`
	DestPort uint16 `json:"dest_port"`
	Proto    string `json:"proto"`
	Depth    uint8  `json:"depth"`
}

type Event struct {
	Timestamp   string `json:"timestamp"`
	CaptureFile string `json:"capture_file"`
	SrcIP       IPAddr `json:"src_ip"`
	DestIP      IPAddr `json:"dest_ip"`
	SrcPort     uint16 `json:"src_port"`
	DestPort    uint16 `json:"dest_port"`
	AppProto    string `json:"app_proto"`
	Proto       string `json:"proto"`
	Tunnel      Tunnel `json:"tunnel"`

	Flow struct {
		Start models.TimeStamp `json:"start"`
	} `json:"flow"`
}

type ExtractPcapConfig struct {
	OutputName string
	EventPath  string
	FileFormat string
	SkipBpf    bool
	Decap      bool
}

/*
Extract a pcap file for a given flow
*/
func ExtractPcapFile(config ExtractPcapConfig) error {
	/* open event file */
	eventFile, err := os.Open(config.EventPath)
	if err != nil {
		return err
	}
	defer eventFile.Close()

	eventPathstring, err := ioutil.ReadAll(eventFile)
	if err != nil {
		return err
	}

	var event Event
	if err = json.Unmarshal(eventPathstring, &event); err != nil {
		return err
	}
	pcapDir := filepath.Dir(event.CaptureFile)

	if len(event.CaptureFile) > 0 {
		_, err := os.Stat(event.CaptureFile)
		if os.IsNotExist(err) {
			return err
		}
		logrus.Debugf("Starting from file %s", event.CaptureFile)
	}

	if event.Tunnel.Depth != 0 {
		logrus.Debugf("Tunnel: %s <-%s-> %s\n", event.Tunnel.SrcIP, event.Tunnel.Proto, event.Tunnel.DestIP)
	}
	logrus.Debugf("Flow: %s <-%s:%s-> %s\n", event.SrcIP, event.Proto, event.AppProto, event.DestIP)

	m, err := filter.NewTupleMatcher(
		event.SrcIP.IP,
		event.SrcPort,
		event.DestIP.IP,
		event.DestPort,
		event.Proto,
	)
	if err != nil {
		return err
	}

	pcapFileList := NewPcapFileList(pcapDir, event, config.FileFormat)
	if pcapFileList == nil {
		return errors.New("Problem when building pcap file list")
	}

	// Open up a second pcap handle for packet writes.
	outfile, err := os.Create(config.OutputName)
	if err != nil {
		logrus.Error("Can't open pcap output file: ", err)
		return err
	}
	defer outfile.Close()

	handleWrite := pcapgo.NewWriter(outfile)
	err = handleWrite.WriteFileHeader(65536, layers.LinkTypeEthernet) // new file, must do this.
	if err != nil {
		logrus.Error("Can't write to output file: ", err)
		return err
	}

	start := time.Now()
	var pktCount int
	/*
		Loop over pcap file starting with the one specified in the event
		If timestamp of first packet > lastTimestamp of flow + flow_timeout then
		we can consider we are at the last pcap
	*/

	// build a list of candidate pcap files
	files, err := newPcapFiles(pcapFileList.Files, event, 600*time.Second)
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return errors.New("no files match the timeframe")
	}

	logrus.
		WithField("start", event.Flow.Start).
		Infof("building candidate fileset beginning from")

	for _, pf := range files {
		logrus.Debugf("Reading packets from %s", pf.Path)
		count, err := processFile(pf, config, m, handleWrite)
		if err != nil {
			return err
		}
		pktCount += count
	}
	logrus.Infof("Finished in %s\n", time.Since(start))
	logrus.Infof("Written %d packet(s)\n", pktCount)

	return nil
}

func processFile(
	pf pcapFile,
	config ExtractPcapConfig,
	m filter.Matcher,
	handleWrite *pcapgo.Writer,
) (int, error) {
	f, err := os.Open(pf.Path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	reader, err := pcapgo.NewReader(f)
	if err != nil {
		return 0, err
	}

	tick := time.NewTicker(1 * time.Second)
	defer tick.Stop()
	var count, matched int
	start := time.Now()

	// Loop over packets and write them
loop:
	for {
		select {
		case <-tick.C:
			logrus.WithFields(logrus.Fields{
				"count":   count,
				"matched": matched,
				"eps":     fmt.Sprintf("%.2f", float64(count)/time.Since(start).Seconds()),
				"file":    pf.Path,
			}).Debug("processing")
		default:
			count++
			data, ci, err := reader.ReadPacketData()
			if err != nil && err == io.EOF {
				return matched, nil
			} else if err != nil {
				return matched, err
			}
			pkt := gopacket.NewPacket(data, reader.LinkType(), gopacket.Lazy)
			if config.Decap {
				if config.Decap {
					decapped, err := filter.DecapGREandERSPAN(pkt, 10)
					if err != nil {
						return matched, err
					}
					pkt = decapped
				}
			}
			if !m.Match(pkt) {
				continue loop
			}
			matched++
			data = pkt.Data()

			ci.CaptureLength = len(data)
			if err := handleWrite.WritePacket(ci, data); err != nil {
				return matched, err
			}
		}
	}
}
