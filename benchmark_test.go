package main

import (
	"testing"

	"github.com/go-piv/piv-go/piv"
)

func setSlots(newSlots []piv.Slot) {
	slots = newSlots
}

var slotBenchmarkCases = []struct {
	name  string
	slots []piv.Slot
}{
	{
		name: "1 slot",
		slots: []piv.Slot{
			piv.SlotAuthentication,
		},
	},

	{
		name: "2 slots both exist",
		slots: []piv.Slot{
			piv.SlotAuthentication,
			piv.SlotKeyManagement,
		},
	},

	// This assumes there are certificates on slots 9A and 9D only.
	{
		name: "2 slots 1 exist",
		slots: []piv.Slot{
			piv.SlotAuthentication,
			piv.SlotCardAuthentication,
		},
	},

	{
		name: "4 slots",
		slots: []piv.Slot{
			piv.SlotAuthentication,
			piv.SlotCardAuthentication,
			piv.SlotKeyManagement,
			piv.SlotSignature,
		},
	},
}

func BenchmarkList(b *testing.B) {
	a := &Agent{}
	b.Cleanup(func() {
		a.Close()
	})

	for _, bc := range slotBenchmarkCases {
		b.Run(bc.name, func(b *testing.B) {
			setSlots(bc.slots)
			for i := 0; i < b.N; i++ {
				_, err := a.List()
				if err != nil {
					b.Error(err)
				}
			}
		})
	}
}

func BenchmarkSigners(b *testing.B) {
	a := &Agent{}
	b.Cleanup(func() {
		a.Close()
	})
	if err := a.ensureYK(); err != nil {
		b.Errorf("could not reach YubiKey: %w", err)
	}

	for _, bc := range slotBenchmarkCases {
		b.Run(bc.name, func(b *testing.B) {
			setSlots(bc.slots)
			for i := 0; i < b.N; i++ {
				_, err := a.signers()
				if err != nil {
					b.Error(err)
				}
			}
		})
	}
}
