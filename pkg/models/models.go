/*
Copyright © 2020 Stamus Networks oss@stamus-networks.com

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
package models

import (
	"net"
	"strconv"
	"time"
)

type Period struct {
	Beginning time.Time `json:"beginning"`
	End       time.Time `json:"end"`
}

func (p Period) Duration() time.Duration {
	return p.End.Sub(p.Beginning)
}

func (p Period) Delay(target time.Time) time.Duration {
	return p.Beginning.Sub(target)
}

type Counters struct {
	Packets       int `json:"packets"`
	Size          int `json:"size"`
	MaxPacketSize int `json:"max_packet_size"`
	OutOfOrder    int `json:"out_of_order"`
}

func (c Counters) PPS(interval time.Duration) float64 {
	return float64(c.Packets) / interval.Seconds()
}

type Rates struct {
	PPS           float64       `json:"pps"`
	Duration      time.Duration `json:"duration"`
	DurationHuman string        `json:"duration_human"`
}

type EVE struct {
	SrcIP     net.IP `json:"src_ip,omitempty"`
	DestIP    net.IP `json:"dest_ip,omitempty"`
	SrcPort   int    `json:"src_port,omitempty"`
	DestPort  int    `json:"dest_port,omitempty"`
	EventType string `json:"event_type,omitempty"`
	FlowID    int    `json:"flow_id,omitempty"`
}

type Alert struct {
	Signature   string `json:"signature,omitempty"`
	SignatureID int    `json:"signature_id,omitempty"`
	Category    string `json:"category,omitempty"`
}

// TimeStamp is a wrapper around time.Time object to unmarshal RFC3339 timestamp the way
// Suricata creates it. Go time package defines RFC3339, but expects a plus or colon in timezone
// Thus, defining Timestamp as naive time.Time fails with parse error, as template is wrong
type TimeStamp struct{ time.Time }

// UnmarshalJSON implements json.Unmarshaler
func (t *TimeStamp) UnmarshalJSON(b []byte) error {
	raw, err := strconv.Unquote(string(b))
	if err != nil {
		return err
	}
	ts, err := time.Parse("2006-01-02T15:04:05.999999Z0700", raw)
	if err != nil {
		return err
	}
	t.Time = ts
	return nil
}

// MarshalJSON ensures that timestamps are re-encoded the way Suricata made them
func (t *TimeStamp) MarshalJSON() ([]byte, error) {
	return []byte(`"` + t.Time.Format("2006-01-02T15:04:05.000000-0700") + `"`), nil
}
