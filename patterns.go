package mafmt

import (
	"strings"

	ma "github.com/jbenet/go-multiaddr"
)

var IP = Or(Base(ma.P_IP4), Base(ma.P_IP6))
var TCP = And(IP, Base(ma.P_TCP))
var UDP = And(IP, Base(ma.P_UDP))
var UTP = And(UDP, Base(ma.P_UTP))
var Reliable = Or(TCP, UTP)
var IPFS = And(Reliable, Base(ma.P_IPFS))

const (
	or  = iota
	and = iota
)

func And(ps ...Pattern) Pattern {
	return &pattern{
		Op:   and,
		Args: ps,
	}
}

func Or(ps ...Pattern) Pattern {
	return &pattern{
		Op:   or,
		Args: ps,
	}
}

type Pattern interface {
	Matches(ma.Multiaddr) bool
	partialMatch([]ma.Protocol) (bool, []ma.Protocol)
	String() string
}

type pattern struct {
	Args []Pattern
	Op   int
}

func (ptrn *pattern) Matches(a ma.Multiaddr) bool {
	ok, rem := ptrn.partialMatch(a.Protocols())
	return ok && len(rem) == 0
}

func (ptrn *pattern) partialMatch(pcs []ma.Protocol) (bool, []ma.Protocol) {
	switch ptrn.Op {
	case or:
		for _, a := range ptrn.Args {
			ok, rem := a.partialMatch(pcs)
			if ok {
				return true, rem
			}
		}
		return false, nil
	case and:
		if len(pcs) < len(ptrn.Args) {
			return false, nil
		}

		for i := 0; i < len(ptrn.Args); i++ {
			ok, rem := ptrn.Args[i].partialMatch(pcs)
			if !ok {
				return false, nil
			}

			pcs = rem
		}

		return true, pcs
	default:
		panic("unrecognized pattern operand")
	}
}

func (ptrn *pattern) String() string {
	var sub []string
	for _, a := range ptrn.Args {
		sub = append(sub, a.String())
	}

	switch ptrn.Op {
	case and:
		return strings.Join(sub, "/")
	case or:
		return "{" + strings.Join(sub, "|") + "}"
	default:
		panic("unrecognized pattern op!")
	}
}

type Base int

func (p Base) Matches(a ma.Multiaddr) bool {
	pcs := a.Protocols()
	return pcs[0].Code == int(p) && len(pcs) == 1
}

func (p Base) partialMatch(pcs []ma.Protocol) (bool, []ma.Protocol) {
	if len(pcs) == 0 {
		return false, nil
	}
	if pcs[0].Code == int(p) {
		return true, pcs[1:]
	}
	return false, nil
}

func (p Base) String() string {
	return ma.ProtocolWithCode(int(p)).Name
}
