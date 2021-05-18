package kdata

import (
	"testing"
)

const (
	line1 = "Apr 26 17:10:01 vm kernel: [  634.241210] 4444 IN=lo OUT= MAC=00:00:00:00:00:00:00:00:00:00:00:00:86:dd SRC=0000:0000:0000:0000:0000:0000:0000:0001 DST=0000:0000:0000:0000:0000:0000:0000:0001 LEN=80 TC=0 HOPLIMIT=64 FLOWLBL=330717 PROTO=TCP SPT=34044 DPT=4444 WINDOW=65476 RES=0x00 SYN URGP=0"
	line2 = "Apr 26 17:21:49 vm kernel: [ 1342.554451] 4444 IN=lo OUT= MAC=00:00:00:00:00:00:00:00:00:00:00:00:86:dd SRC=0000:0000:0000:0000:0000:0000:0000:0001 DST=0000:0000:0000:0000:0000:0000:0000:0001 LEN=80 TC=0 HOPLIMIT=64 FLOWLBL=229361 PROTO=TCP SPT=34202 DPT=4444 SEQ=151652885 ACK=0 WINDOW=65476 RES=0x00 SYN URGP=0 OPT (0204FFC40402080A82855A2A0000000001030307)"
	line3 = "Apr 29 22:54:36 vm kernel: [  459.009537] REJECT IN=lo OUT= MAC=00:00:00:00:00:00:00:00:00:00:00:00:08:00 SRC=127.0.0.1 DST=127.0.0.1 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=22210 DF PROTO=TCP SPT=41712 DPT=4444 SEQ=1241461970 ACK=0 WINDOW=65495 RES=0x00 SYN URGP=0 OPT (0204FFD70402080AF27775780000000001030307)"
	line4 = "Apr 29 22:56:19 vm kernel: [  561.607828] 4444 IN=lo OUT= MAC=00:00:00:00:00:00:00:00:00:00:00:00:08:00 SRC=10.116.0.1 DST=10.116.0.2 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=23332 DF PROTO=TCP SPT=41716 DPT=1234 SEQ=2393725385 ACK=0 WINDOW=65495 RES=0x00 SYN URGP=0 OPT (0204FFD70402080AF27906410000000001030307)"
	line5 = "Apr 29 22:58:29 vm kernel: [  692.312037] 4444 IN=lo OUT= MAC=00:00:00:00:00:00:00:00:00:00:00:00:08:00 SRC=192.168.56.1 DST=192.168.56.2 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=57150 DF PROTO=TCP SPT=41724 DPT=56789 SEQ=3910063279 ACK=0 WINDOW=65495 RES=0x00 SYN URGP=0 OPT (0204FFD70402080AF27B04D40000000001030307)"
	line6 = "May 10 08:17:12 vm kernel: [ 3281.482604] 4444 IN=lo OUT= MAC=00:00:00:00:00:00:00:00:00:00:00:00:86:dd SRC=0000:0000:0000:0000:0000:0000:0000:0001 DST=0000:0000:0000:0000:0000:0000:0000:0001 LEN=80 TC=0 HOPLIMIT=64 FLOWLBL=526237 PROTO=TCP SPT=33766 DPT=4444 SEQ=3789814926 ACK=0 WINDOW=65476 RES=0x00 SYN URGP=0 OPT (0204FFC40402080A5DB2BEF20000000001030307"
)

type dataTestCase struct {
	Text string
	Kde  *KnockDataEntry
}

var (
	logEntryTestCases []*dataTestCase = []*dataTestCase{{
		line1, &KnockDataEntry{
			Spt:    34044,
			Dpt:    4444,
			Seq:    0,
			Ack:    0,
			Window: 65476,
			Src:    "0000:0000:0000:0000:0000:0000:0000:0001",
			Nonce:  (330717 & 0xff00) | (330717 & 0xff),
		},
	}, {
		line2, &KnockDataEntry{
			Spt:    34202,
			Dpt:    4444,
			Seq:    151652885,
			Ack:    0,
			Window: 65476,
			Src:    "0000:0000:0000:0000:0000:0000:0000:0001",
			Nonce:  (229361 & 0xff00) | (229361 & 0xff),
		},
	}, {
		line3, &KnockDataEntry{
			Spt:    41712,
			Dpt:    4444,
			Seq:    1241461970,
			Ack:    0,
			Window: 65495,
			Src:    "127.0.0.1",
			Nonce:  22210,
		},
	}, {
		line4, &KnockDataEntry{
			Spt:    41716,
			Dpt:    1234,
			Seq:    2393725385,
			Ack:    0,
			Window: 65495,
			Src:    "10.116.0.1",
			Nonce:  23332,
		},
	}, {
		line5, &KnockDataEntry{
			Spt:    41724,
			Dpt:    56789,
			Seq:    3910063279,
			Ack:    0,
			Window: 65495,
			Src:    "192.168.56.1",
			Nonce:  57150,
		},
	}, {
		line6, &KnockDataEntry{
			Spt:    33766,
			Dpt:    4444,
			Seq:    3789814926,
			Ack:    0,
			Window: 65476,
			Src:    "0000:0000:0000:0000:0000:0000:0000:0001",
			Nonce:  (526237 & 0xff00) | (526237 & 0xff),
		},
	}}
	ciphertextTestCases []*dataTestCase = []*dataTestCase{{
		string([]byte{0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17}),
		&KnockDataEntry{
			Nonce:  0x1a1b,
			Seq:    0x1c1d1e1f,
			Ack:    0x10111213,
			Window: 0x1415,
			Spt:    0x1617,
		}}, {
		string([]byte{0x0a, 0x0b, 0x0d, 0x0a}),
		&KnockDataEntry{
			Nonce:  0x0a0b,
			Seq:    0,
			Ack:    0,
			Window: 0,
			Spt:    0,
		}}, {
		string([]byte{0x0a, 0x0b, 0x0d, 0x0a, 0x00, 0x00}),
		&KnockDataEntry{
			Nonce:  0x0a0b,
			Seq:    0x0d0a0000,
			Ack:    0,
			Window: 0,
			Spt:    0,
		}}, {
		string([]byte{0x11, 0x30, 0x02, 0x0a, 0x0b, 0x56, 0x87, 0x99}),
		&KnockDataEntry{
			Nonce:  0x1130,
			Seq:    0x020a0b56,
			Ack:    0,
			Window: 0,
			Spt:    0,
		}}, {
		string([]byte{0x11, 0x30, 0x02, 0x0a, 0x0b, 0x56, 0x87, 0x99, 0xaa, 0xba}),
		&KnockDataEntry{
			Nonce:  0x1130,
			Seq:    0x020a0b56,
			Ack:    0x8799aaba,
			Window: 0,
			Spt:    0,
		}},
	}
)

func TestFromLogEntry(t *testing.T) {
	for i, lr := range logEntryTestCases {
		k := FromLogEntry(lr.Text)
		if !equals(k, lr.Kde) {
			t.Fatalf("parsed knock data is not the same as expected data %d %v != %v", i+1, k, lr.Kde)
		}
	}
}

func TestFromCiphertext(t *testing.T) {
	for _, ct := range ciphertextTestCases {
		k := FromCipherText([]byte(ct.Text))
		if !equals(ct.Kde, k) {
			t.Fatalf("parsed knock data is not the same as expected data %v != %v", k, ct.Kde)
		}
	}
}

func equals(k1, k2 *KnockDataEntry) bool {
	return Verify(k1, k2) &&
		k1.Src == k2.Src &&
		k1.Dpt == k2.Dpt
}
